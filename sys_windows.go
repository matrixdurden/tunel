package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// On Windows a client owns:
//   C:\Program Files\tunel\tunel.exe   this binary (on the system PATH)
//   C:\ProgramData\tunel\              client.json, tunel.log
//   the "tunel" service                manual start; any signed-in user may start/stop it
//   the "tunel" Wintun adapter         exists only while the tunnel is on
//   the Wintun driver                  only if tunel was the one that installed it

const (
	isLinux = false
	svcName = "tunel"
)

var (
	installDir      = filepath.Join(os.Getenv("ProgramFiles"), "tunel")
	installedBin    = filepath.Join(installDir, "tunel.exe")
	dataDir         = filepath.Join(os.Getenv("ProgramData"), "tunel")
	clientStatePath = filepath.Join(dataDir, "client.json")
	clientLogPath   = filepath.Join(dataDir, "tunel.log")
	clientLogHint   = clientLogPath
	clientModePath  = filepath.Join(dataDir, "mode") // written by the service
	offFlagPath     = filepath.Join(dataDir, "off")  // tunel off was the last word; autostart keeps it off
	wintunMarker    = filepath.Join(dataDir, "wintun-installed-by-tunel")
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	shell32            = windows.NewLazySystemDLL("shell32.dll")
	user32             = windows.NewLazySystemDLL("user32.dll")
	procGetConsolePIDs = kernel32.NewProc("GetConsoleProcessList")
	procShellExecuteEx = shell32.NewProc("ShellExecuteExW")
	procSendMessageTO  = user32.NewProc("SendMessageTimeoutW")
)

func setupConsole() {
	h := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if windows.GetConsoleMode(h, &mode) != nil {
		// Redirected. An elevated child keeps colors: its output is replayed on a console.
		if len(os.Args) < 2 || os.Args[1] != "__admin" {
			noColor()
		}
		return
	}
	// Go writes to a console with WriteConsoleW, so ✓ and ● need no code page change.
	if windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) != nil {
		noColor()
	}
}

// ownConsole reports whether Windows made a console just for us, which is
// what happens when tunel.exe is double-clicked.
func ownConsole() bool {
	var pids [2]uint32
	n, _, _ := procGetConsolePIDs.Call(uintptr(unsafe.Pointer(&pids[0])), 2)
	return n == 1
}

func isAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func userHome() (string, error) {
	return os.UserHomeDir()
}

// ---------- elevation ----------

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hIcon        windows.Handle
	hProcess     windows.Handle
}

// runElevated re-runs this binary through a UAC prompt, streams the child's
// output (written to a temp file, since an elevated process cannot share our
// console) and returns its result.
func runElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	f, err := os.CreateTemp("", "tunel-*.log")
	if err != nil {
		return err
	}
	out := f.Name()
	defer os.Remove(out)

	params := adminChildArgs(out, args)
	for i, p := range params {
		params[i] = windows.EscapeArg(p)
	}
	info := shellExecuteInfo{
		fMask:        0x00000040 | 0x00000100, // SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
		lpVerb:       windows.StringToUTF16Ptr("runas"),
		lpFile:       windows.StringToUTF16Ptr(exe),
		lpParameters: windows.StringToUTF16Ptr(strings.Join(params, " ")),
		nShow:        windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, e := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		f.Close()
		if errors.Is(e, windows.ERROR_CANCELLED) {
			return fmt.Errorf("administrator permission was not given; nothing was changed")
		}
		return fmt.Errorf("could not start as administrator: %v", e)
	}
	defer windows.CloseHandle(info.hProcess)

	for {
		ev, _ := windows.WaitForSingleObject(info.hProcess, 100)
		io.Copy(os.Stdout, f)
		if ev != uint32(windows.WAIT_TIMEOUT) {
			break
		}
	}
	io.Copy(os.Stdout, f)
	f.Close()
	var code uint32
	windows.GetExitCodeProcess(info.hProcess, &code)
	if code != 0 {
		return errReported
	}
	return nil
}

// ---------- install / uninstall ----------

// installSelf copies the running binary to dst.
func installSelf(dst string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return installFile(exe, dst)
}

// installFile copies src to dst. A running old copy cannot be overwritten on
// Windows but can be renamed, so it is moved aside and deleted once it exits.
func installFile(src, dst string) error {
	if a, errA := os.Stat(src); errA == nil {
		if b, errB := os.Stat(dst); errB == nil && os.SameFile(a, b) {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	old := dst + ".old"
	os.Remove(old)
	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, old); err != nil {
			return err
		}
	}
	if err := copyFile(src, dst); err != nil {
		os.Rename(old, dst)
		return err
	}
	if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
		deleteLater(old) // still running, very likely as this very process
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func installClient() error {
	if err := installSelf(installedBin); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil { // DPI-only has no client.json to create it
		return err
	}
	if _, err := os.Stat(wintunMarker); err != nil && !serviceExists() && len(wintunDrivers()) == 0 {
		// The driver is not there yet, so the first `tunel on` installs it and
		// `tunel remove` may take it away again.
		os.WriteFile(wintunMarker, nil, 0o644)
	}

	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	binPath := windows.EscapeArg(installedBin) + " service"
	s, err := m.OpenService(svcName)
	if err == nil {
		cfg, err := s.Config()
		if err == nil {
			cfg.BinaryPathName = binPath // the start type stays: it is tunel autostart's
			err = s.UpdateConfig(cfg)
		}
		if err != nil {
			s.Close()
			return err
		}
	} else {
		s, err = m.CreateService(svcName, installedBin, mgr.Config{
			DisplayName:  "tunel",
			Description:  "Sends this computer's traffic through your tunel server. Use: tunel on / tunel off",
			StartType:    mgr.StartManual,
			ErrorControl: mgr.ErrorNormal,
		}, "service")
		if err != nil {
			return err
		}
	}
	defer s.Close()

	// Restart after a crash; after three quick crashes, stay off.
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 3 * time.Second}
	s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, {Type: mgr.NoAction}}, 600)

	// Let signed-in users start and stop the service, so on/off needs no UAC prompt.
	// They cannot reconfigure it.
	sd, err := windows.SecurityDescriptorFromString(
		"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLOCRRC;;;AU)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return err
	}

	if added, err := editSystemPath(true); err != nil {
		bad("PATH: %v", err)
	} else if added {
		ok("added %s to PATH (new terminals can run tunel from anywhere)", installDir)
	}
	return nil
}

func uninstallClient() error {
	svcStop()
	if m, err := mgr.Connect(); err == nil {
		if s, err := m.OpenService(svcName); err == nil {
			s.Delete()
			s.Close()
		}
		m.Disconnect()
	}
	for i := 0; i < 50 && serviceExists(); i++ {
		time.Sleep(200 * time.Millisecond)
	}
	if serviceExists() {
		return fmt.Errorf("the tunel service could not be deleted; restart Windows and run tunel remove again")
	}

	removeAdapter()
	if _, err := os.Stat(wintunMarker); err == nil {
		for _, inf := range wintunDrivers() {
			// Without /force pnputil refuses if another program's adapter still uses it.
			exec.Command("pnputil", "/delete-driver", inf).Run()
		}
	}
	if _, err := editSystemPath(false); err != nil {
		bad("PATH: %v", err)
	}
	return os.RemoveAll(dataDir)
}

// removeAdapter deletes the tunel adapter if a crash left it behind.
// Normally it disappears together with the tunnel.
func removeAdapter() {
	ps := `$a = Get-NetAdapter -Name 'tunel' -IncludeHidden -ErrorAction SilentlyContinue; ` +
		`if ($a) { pnputil /remove-device $a.PnPDeviceID | Out-Null }`
	exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Run()
}

var oemInfRe = regexp.MustCompile(`(?i)\boem\d+\.inf\b`)

// wintunDrivers lists the published names (oemNN.inf) of Wintun in the driver
// store. pnputil's labels are localized; the file names are not.
func wintunDrivers() []string {
	out, err := exec.Command("pnputil", "/enum-drivers").Output()
	if err != nil {
		return nil
	}
	var found []string
	last := ""
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if m := oemInfRe.FindString(line); m != "" {
			last = m
		} else if strings.Contains(strings.ToLower(line), "wintun.inf") && last != "" {
			found = append(found, last)
		}
	}
	return found
}

func removeInstalledBin() error {
	exe, _ := os.Executable()
	if !strings.HasPrefix(strings.ToLower(exe), strings.ToLower(installDir)+`\`) {
		return os.RemoveAll(installDir)
	}
	// A running .exe cannot delete itself; a detached cmd does it once this
	// process and the unelevated one that started it have exited.
	return deleteLater(installDir)
}

// deleteLater removes a file or folder that a running process still holds:
// a detached cmd retries every second for half a minute.
func deleteLater(p string) error {
	del := fmt.Sprintf(`del /f /q "%s"`, p)
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		del = fmt.Sprintf(`rd /s /q "%s"`, p)
	}
	cmd := exec.Command("cmd.exe")
	// cmd.exe does not understand Go's \" escaping, so pass the line verbatim.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: fmt.Sprintf(`cmd.exe /d /c for /l %%i in (1,1,30) do (ping -n 2 127.0.0.1 >nul & %s 2>nul & if not exist "%s" exit)`,
			del, p),
		CreationFlags: windows.CREATE_NO_WINDOW | windows.DETACHED_PROCESS,
	}
	return cmd.Start()
}

const envKey = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

// editSystemPath adds or removes installDir in the machine PATH and reports
// whether it changed anything.
func editSystemPath(add bool) (bool, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, envKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false, err
	}
	defer k.Close()
	cur, _, err := k.GetStringValue("Path")
	if err != nil {
		return false, err
	}
	var parts []string
	has := false
	for _, p := range strings.Split(cur, ";") {
		if strings.EqualFold(strings.TrimRight(p, `\`), installDir) {
			has = true
			continue
		}
		if p != "" {
			parts = append(parts, p)
		}
	}
	if has == add {
		return false, nil
	}
	if add {
		parts = append(parts, installDir)
	}
	if err := k.SetExpandStringValue("Path", strings.Join(parts, ";")); err != nil {
		return false, err
	}
	env, _ := windows.UTF16PtrFromString("Environment")
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x001A, 0x0002
	var result uintptr
	procSendMessageTO.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)),
		smtoAbortIfHung, 3000, uintptr(unsafe.Pointer(&result)))
	return true, nil
}

// ---------- service control (no admin needed) ----------

func openService(access uint32) (*mgr.Service, func(), error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, err
	}
	h, err := windows.OpenService(scm, windows.StringToUTF16Ptr(svcName), access)
	if err != nil {
		windows.CloseServiceHandle(scm)
		return nil, nil, err
	}
	s := &mgr.Service{Name: svcName, Handle: h}
	return s, func() { s.Close(); windows.CloseServiceHandle(scm) }, nil
}

func serviceExists() bool {
	_, done, err := openService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	done()
	return true
}

func svcState() svc.State {
	s, done, err := openService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return svc.Stopped
	}
	defer done()
	st, err := s.Query()
	if err != nil {
		return svc.Stopped
	}
	return st.State
}

// svcRunning reports whether the tunnel is up: the service reports Running
// only once it is.
func svcRunning() bool {
	return svcState() == svc.Running
}

// svcStarting reports a service still waiting to bring the tunnel up.
func svcStarting() bool {
	return svcState() == svc.StartPending
}

func svcControl(op string) error {
	switch op {
	case "on":
		return svcStart(modeServer)
	case "dpi":
		return svcStart(modeDPI)
	}
	return svcStop()
}

// svcStart starts the service in mode, switching if it runs in the other one.
// The mode travels as a start argument, which signed-in users may pass.
func svcStart(mode string) error {
	if svcRunning() && currentMode() == mode {
		return nil
	}
	// Running in the other mode, or still waiting at boot: start over.
	if svcRunning() || svcStarting() {
		if err := svcStop(); err != nil {
			return err
		}
	}
	s, done, err := openService(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return fmt.Errorf("the tunel service is missing; run: tunel client")
	}
	defer done()
	if err := s.Start(mode); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	for i := 0; i < 300; i++ { // server mode first checks the server
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running:
			return nil
		case svc.Stopped:
			return startFailure(logTail(clientLogPath))
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("the tunnel is taking too long to start; see %s", clientLogPath)
}

func svcStop() error {
	s, done, err := openService(windows.SERVICE_STOP | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil // not installed: nothing to stop
	}
	defer done()
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	for i := 0; i < 150; i++ {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("the tunnel did not stop in time")
}

func logTail(path string) string {
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return "  " + strings.Join(lines, "\n  ")
}

// ---------- autostart ----------

func autostartEnabled() bool {
	s, done, err := openService(windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return false
	}
	defer done()
	cfg, err := s.Config()
	return err == nil && cfg.StartType == mgr.StartAutomatic
}

func setAutostart(on bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		return fmt.Errorf("the tunel service is missing; run: tunel client")
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	cfg.StartType = mgr.StartManual
	if on {
		cfg.StartType = mgr.StartAutomatic
	}
	return s.UpdateConfig(cfg)
}

// ---------- programs that break the tunnel ----------

// DPI bypass tools rewrite outgoing packets with WinDivert: they split them
// and add fakes that are meant to die on the way. The tunnel adapter has no
// "way", so the fakes reach the tunnel and corrupt connections (TLS 1.2 fails).
var packetRewriters = map[string]string{
	"goodbyedpi.exe": "GoodbyeDPI",
	"winws.exe":      "zapret",
}

func conflictingPrograms() []string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	seen := map[string]bool{}
	var found []string
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if name, ok := packetRewriters[strings.ToLower(windows.UTF16ToString(e.ExeFile[:]))]; ok && !seen[name] {
			seen[name] = true
			found = append(found, name)
		}
	}
	return found
}

// ---------- the service itself ----------

func runClientService() error {
	if is, _ := svc.IsWindowsService(); !is {
		return fmt.Errorf("this is started by the tunel service; use: tunel on")
	}
	return svc.Run(svcName, winService{})
}

type winService struct{}

func (winService) Execute(args []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending, WaitHint: 10000}
	// args[0] is the service name. tunel on/dpi add the mode; a start at boot
	// (autostart) or after a crash brings none: then the last mode is used,
	// unless the user turned the tunnel off.
	mode := currentMode()
	explicit := len(args) > 1 && (args[1] == modeServer || args[1] == modeDPI)
	if explicit {
		mode = args[1]
		os.Remove(offFlagPath)
	} else if _, err := os.Stat(offFlagPath); err == nil {
		os.WriteFile(clientLogPath, []byte("tunel: turned off before; staying off\n"), 0o644)
		return false, 0
	}
	os.WriteFile(clientModePath, []byte(mode+"\n"), 0o644)

	// Bring the tunnel up in the background, so tunel off (a Stop) can end a
	// start that is still waiting for the network or the server.
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	var check uint32
	tick := func() {
		check++
		st <- svc.Status{State: svc.StartPending, Accepts: accepts, CheckPoint: check, WaitHint: 10000}
	}
	st <- svc.Status{State: svc.StartPending, Accepts: accepts, WaitHint: 10000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type started struct {
		b   io.Closer
		err error
	}
	done := make(chan started, 1)
	go func() {
		b, err := startTunnel(ctx, mode, clientLogPath, !explicit, tick)
		done <- started{b, err}
	}()
	var b io.Closer
	for b == nil {
		select {
		case r := <-done:
			switch {
			case errors.Is(r.err, errServerDown), errors.Is(r.err, context.Canceled):
				return false, 0 // stopped on purpose, not a failure to recover from
			case r.err != nil:
				appendLog(clientLogPath, "tunel: "+r.err.Error())
				return true, 1
			}
			b = r.b
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				if c.Cmd == svc.Stop {
					os.WriteFile(offFlagPath, nil, 0o644)
				}
				st <- svc.Status{State: svc.StopPending}
				cancel()
				if r := <-done; r.b != nil {
					r.b.Close()
				}
				return false, 0
			}
		}
	}
	st <- svc.Status{State: svc.Running, Accepts: accepts}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			if c.Cmd == svc.Stop {
				// tunel off (or a pause that turns it back on right after). A
				// shutdown is not a choice to turn it off, so it leaves no mark.
				os.WriteFile(offFlagPath, nil, 0o644)
			}
			st <- svc.Status{State: svc.StopPending}
			b.Close()
			return false, 0
		}
	}
	return false, 0
}
