# tunel

`tunel` gets a whole computer past network blocks, in one of two modes:

- **`tunel on`**: all traffic goes through your own server. To the network in between it looks like ordinary HTTPS to a well-known site (VLESS + Reality), so networks that block VPNs or SSH let it through.
- **`tunel dpi`**: no server. Traffic leaves over your own connection, but DNS is asked over HTTPS and every TLS handshake is split into several records, so a DPI filter can neither poison names nor read which site you open.

A server in a censored country meets the same filter on its way out, so it splits handshakes and asks DNS over HTTPS too.

## 1. Server (only for `tunel on`)

On a Linux machine with systemd that the internet reaches on TCP port 443:

```sh
curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- server
```

It asks for your sudo password, sets everything up, tests itself and prints a link.

## 2. Computers

**Windows**: open PowerShell, run this, and paste the link when asked, or press Enter for `tunel dpi` only:

```powershell
irm https://raw.githubusercontent.com/matrixdurden/tunel/main/install.ps1 | iex
```

**Linux**:

```sh
curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- client 'vless://…'
curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- dpi
```

A link is checked before anything is changed. Windows asks for administrator permission once; you can add a link later with `tunel client`.

## Use

```sh
tunel on        # all traffic goes through the server
tunel dpi       # your own connection, past DPI blocks
tunel off       # back to the normal connection
tunel           # ● on 203.0.113.7  /  ● dpi 198.51.100.4  /  ○ off
```

`tunel on` and `tunel dpi` switch between each other directly. On Windows none of them need administrator permission. WSL uses the Windows tunnel automatically.

Your local network (router, printer, `192.168.x.x`) never goes through the tunnel. With `tunel on`, the server's own IP address reaches the server itself, so SSH to it and web apps that listen only on the server's `127.0.0.1` work without going around through its router, and speed is capped by the server's upload speed.

After a reboot the tunnel is off until you turn it on, unless you run `tunel autostart on` (once; `off` undoes it). Then at boot it comes back as you left it: in `on` mode, in `dpi` mode, or off after `tunel off`. It first waits for the network; in `on` mode it also checks the server, and if the server does not answer within 90 seconds it stays off and the internet works as usual. `tunel on` checks the server too, and leaves everything as it is if the server does not answer. If the tunnel crashes, the computer falls back to its normal connection at once.

On a new network, `tunel doctor` measures what it does (sign-in page, DNS rewriting, DNS over HTTPS, site-name filtering, HTTPS inspection, whether the server is reachable) and says which mode will work. It saves the report to the desktop, for when that network blocks everything else. `tunel dpi` picks, each time it starts, the first DNS over HTTPS server the network lets through, and falls back to plain DNS if none does.

Close GoodbyeDPI or zapret before using tunel: they add fake packets that break connections through the tunnel, and `tunel dpi` does their job. `tunel` warns when they run.

## Users

On the server:

```sh
sudo tunel add ali     # prints a link for ali
sudo tunel del ali     # ali's link stops working
sudo tunel users
sudo tunel link ali    # prints ali's link again
```

The link is a standard `vless://` link, so phone apps such as Hiddify or v2rayNG accept it too.

## Update

```sh
tunel update
```

Installs the latest release if there is a newer one, checks its checksum, and restarts what was running. Keys, users and links stay as they are. Running the install command again does the same.

## Remove

```sh
tunel remove
```

Removes everything tunel added: the service, the network adapter, the settings, the `PATH` entry, and tunel itself (and the `~/.ssh/config` block that versions before v0.1.5 added). On a server it also removes the server and its keys.

## Build

With Go:

```sh
./build.sh      # dist/: Linux and Windows, amd64 and arm64, and checksums.txt
go test -tags with_utls,with_gvisor,badlinkname,tfogo_checklinkname0 -ldflags=-checklinkname=0 .
```

Pushing a `v*` tag builds and publishes a release, which the install scripts download.

The tunnel engine is [sing-box](https://github.com/SagerNet/sing-box), built in. Like sing-box, tunel is licensed under the GPL-3.0.
