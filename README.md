# tunel

`tunel` reaches your own server over SSH and the web from networks that block SSH. It runs [Xray](https://github.com/XTLS/Xray-core) VLESS + Reality, so the connection looks like ordinary HTTPS to a well-known site.

One bash file for Linux and for Windows with Git Bash. No config file, no system proxy, no admin rights on the client.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/tunel | bash
```

This puts `tunel` in `$XDG_BIN_HOME` or `~/.local/bin`; on Windows, in `~/bin` next to a `tunel.cmd` for PowerShell and cmd. Run it once on the server and once on each client.

## Server

```sh
tunel server
```

It asks for `sudo` once, installs Xray on port 443, picks a Reality SNI that works, tests itself, and prints the command for the client:

```text
  ✓ xray 26.3.27 :443
  ✓ sni dl.google.com
  ✓ self-test 203.0.113.7
  ✓ ssh 22

  tunel client 'vless://…'
```

Run `tunel server` again at any time to print the command again. Pass a port to use one other than 443: `tunel server 8443`. Port 443 must reach the server over TCP; UDP is not needed.

## Client

Paste the command the server printed:

```sh
tunel client 'vless://…'
```

Then:

```sh
tunel             # ● on 203.0.113.7  /  ○ off
tunel on          # start the tunnel
tunel off         # stop the tunnel
tunel web         # open the default browser through the tunnel
tunel web brave   # or brave, chrome, edge
ssh NAME          # NAME is the server user, shown by `tunel`
```

While the tunnel is on:

- `ssh NAME` reaches the server's SSH through `127.0.0.1:2222`.
- `127.0.0.1:10808` is a SOCKS5 proxy that exits from the server.
- `tunel web` opens the browser with its own profile in `~/.tunel/web`, so your normal browser window stays off the tunnel. In that window, `127.0.0.1` means the server, so its local-only web apps open too.

Nothing else on the machine goes through the tunnel. Other apps can use the SOCKS5 proxy if they have a proxy setting.

On Linux the tunnel is a systemd user service. On Windows it is a hidden `xray.exe` that `tunel off` stops.

## Windows and WSL

Windows and WSL each need their own client. WSL's localhost forwarding is not reliable enough to share one tunnel, and both can run at the same time. Run `tunel web` on Windows. In WSL, the tunnel stops when WSL shuts down; run `tunel on` again.

## Requirements

- Linux with systemd, `curl`, and `unzip`; the server also needs `python3`.
- Windows with [Git for Windows](https://gitforwindows.org). To run `tunel` from PowerShell or cmd, add `%USERPROFILE%\bin` to `PATH`.
- The client downloads Xray from GitHub once. If GitHub is blocked where you are, run `tunel client` on another network, or through a proxy you already have: `ALL_PROXY=socks5h://HOST:PORT tunel client …`.

## Remove

```sh
tunel remove
```

It stops the tunnel and removes everything tunel added: Xray and its config on a server; the `~/.tunel` folder, the user service, the marked block in `~/.ssh/config`, and the browser profile on a client; then `tunel` itself.
