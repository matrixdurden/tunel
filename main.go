// tunel routes a whole computer through your own server, disguised as ordinary HTTPS.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

var version = "dev"

const usageText = `tunel %s

server (Linux):
  tunel server [PORT]     set up this machine as the server (default port 443)
  tunel add NAME          add a user and print their link
  tunel del NAME          remove a user; their link stops working
  tunel users             list users
  tunel link NAME         print a user's link again

client (Windows, Linux):
  tunel client [LINK]     set up this computer with a link from the server
  tunel on                send all traffic through the server
  tunel off               back to the normal connection
  tunel                   show status

  tunel remove            remove everything tunel added to this computer
`

func usage() {
	fmt.Printf(usageText, version)
}

func main() {
	setupConsole()
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	var err error
	switch cmd {
	case "":
		if ownConsole() {
			// Double-clicked tunel.exe: set up if needed, then keep the window open.
			if clientInstalled() {
				err = cmdStatus()
				fmt.Println("\n  Run tunel on / tunel off in a terminal, or tunel remove to uninstall.")
			} else {
				err = cmdClient(nil)
			}
			if err != nil && !errors.Is(err, errReported) {
				printErr(err)
			}
			fmt.Print("\nPress Enter to close.")
			fmt.Scanln()
			if err != nil {
				os.Exit(1)
			}
			return
		}
		err = cmdStatus()
	case "server":
		err = asAdmin(append([]string{"server"}, args...)...)
	case "add", "del", "users", "link":
		err = asAdmin(append([]string{cmd}, args...)...)
	case "client":
		err = cmdClient(args)
	case "on":
		err = cmdOn()
	case "off":
		err = cmdOff()
	case "remove", "uninstall":
		err = cmdRemove()
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		usage()
	// Internal entry points.
	case "serve":
		err = runServer()
	case "service":
		err = runClientService()
	case "__admin":
		err = runAdminChild(args)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		if !errors.Is(err, errReported) {
			printErr(err)
		}
		os.Exit(1)
	}
}

// errReported means the message was already shown (e.g. by an elevated child).
var errReported = errors.New("reported")

// asAdmin runs a privileged command: inline when already root/elevated,
// otherwise in a child started through sudo or a UAC prompt.
func asAdmin(args ...string) error {
	if isAdmin() {
		return runAdmin(args)
	}
	return runElevated(args)
}

// adminChildArgs is how runElevated passes its output file and whether the
// parent's terminal shows colors; runAdminChild reads them back.
func adminChildArgs(out string, args []string) []string {
	color := "color"
	if cReset == "" {
		color = "plain"
	}
	return append([]string{"__admin", out, color}, args...)
}

func runAdminChild(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("internal: missing output")
	}
	if args[1] == "plain" {
		noColor()
	}
	if out := args[0]; out != "-" {
		f, err := os.OpenFile(out, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		os.Stdout, os.Stderr = f, f
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintln(f, "panic:", r)
				os.Exit(1)
			}
		}()
	}
	if !isAdmin() {
		return fmt.Errorf("administrator rights are required")
	}
	err := runAdmin(args[2:])
	if err != nil && !errors.Is(err, errReported) {
		printErr(err)
		return errReported
	}
	return err
}

func runAdmin(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("internal: empty command")
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "server":
		return adminServer(args)
	case "add":
		return adminAdd(args)
	case "del":
		return adminDel(args)
	case "users":
		return adminUsers()
	case "link":
		return adminLink(args)
	case "client-install":
		return adminClientInstall(args)
	case "on":
		return svcStart()
	case "off":
		return svcStop()
	case "remove":
		return adminRemove()
	}
	return fmt.Errorf("internal: unknown command %q", cmd)
}

// ---------- output ----------

var (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cRed    = "\033[31m"
)

func noColor() {
	cReset, cBold, cDim, cGreen, cYellow, cRed = "", "", "", "", "", ""
}

func ok(format string, a ...any) {
	fmt.Printf("  %s✓%s %s\n", cGreen, cReset, fmt.Sprintf(format, a...))
}

func bad(format string, a ...any) {
	fmt.Printf("  %s✗%s %s\n", cRed, cReset, fmt.Sprintf(format, a...))
}

func printErr(err error) {
	msg := strings.TrimSpace(err.Error())
	fmt.Fprintf(os.Stderr, "%s%serror:%s %s\n", cBold, cRed, cReset, msg)
}
