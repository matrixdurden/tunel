package main

import (
	"bufio"
	"bytes"
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

// installSelf copies the running binary to dst. A running old copy cannot be
// overwritten on Windows but can be renamed, so it is moved aside first.
func installSelf(dst string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if a, errA := os.Stat(exe); errA == nil {
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
	if err := copyFile(exe, dst); err != nil {
		os.Rename(old, dst)
		return err
	}
	os.Remove(old) // fails while the old one still runs; `tunel remove` deletes the folder anyway
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
			cfg.BinaryPathName = binPath
			cfg.StartType = mgr.StartManual
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
	return deleteLater(installDir, 3)
}

func deleteLater(dir string, seconds int) error {
	cmd := exec.Command("cmd.exe")
	// cmd.exe does not understand Go's \" escaping, so pass the line verbatim.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       fmt.Sprintf(`cmd.exe /d /c ping -n %d 127.0.0.1 >nul & rd /s /q "%s"`, seconds+1, dir),
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

func svcRunning() bool {
	s, done, err := openService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer done()
	st, err := s.Query()
	return err == nil && st.State == svc.Running
}

func svcControl(op string) error {
	if op == "on" {
		return svcStart()
	}
	return svcStop()
}

func svcStart() error {
	s, done, err := openService(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return fmt.Errorf("the tunel service is missing; run: tunel client 'vless://…'")
	}
	defer done()
	if st, _ := s.Query(); st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	for i := 0; i < 150; i++ {
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running:
			return nil
		case svc.Stopped:
			return fmt.Errorf("the tunnel did not start:\n%s", logTail(clientLogPath))
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

// ---------- the service itself ----------

func runClientService() error {
	if is, _ := svc.IsWindowsService(); !is {
		return fmt.Errorf("this is started by the tunel service; use: tunel on")
	}
	return svc.Run(svcName, winService{})
}

type winService struct{}

func (winService) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	b, err := startTunnel(clientLogPath)
	if err != nil {
		appendLog(clientLogPath, "tunel: "+err.Error())
		return true, 1
	}
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
			b.Close()
			return false, 0
		}
	}
	return false, 0
}

func appendLog(path, line string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	fmt.Fprintln(f, line)
	f.Close()
}
