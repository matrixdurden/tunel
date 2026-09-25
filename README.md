# tunel

`tunel` sends a whole computer's traffic through your own server. To the network in between it looks like ordinary HTTPS to a well-known site (VLESS + Reality), so networks that block VPNs or SSH let it through.

## 1. Server

On a Linux machine with systemd that the internet reaches on TCP port 443:

```sh
curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- server
```

It asks for your sudo password, sets everything up, tests itself and prints a link.

## 2. Computers

**Windows**: open PowerShell, run this and paste the link when asked:

```powershell
irm https://raw.githubusercontent.com/matrixdurden/tunel/main/install.ps1 | iex
```

**Linux**:

```sh
curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- client 'vless://…'
```

The link is checked before anything is changed. Windows asks for administrator permission once.

## Use

```sh
tunel on        # all traffic goes through the server
tunel off       # back to the normal connection
tunel           # ● on 203.0.113.7  /  ○ off
ssh NAME        # the server's SSH; NAME is shown by `tunel`
```

On Windows `tunel on` and `tunel off` need no administrator permission. WSL uses the Windows tunnel automatically.

While the tunnel is on, browsers, games and DNS all go through the server; your local network (router, printer, `192.168.x.x`) does not. The server's own IP address reaches the server itself, so `ssh NAME` and web apps that listen only on the server's `127.0.0.1` work. Speed is capped by the server's upload speed.

After a reboot the tunnel is off until `tunel on`. If the tunnel crashes, the computer falls back to its normal connection at once.

## Users

On the server:

```sh
sudo tunel add ali     # prints a link for ali
sudo tunel del ali     # ali's link stops working
sudo tunel users
sudo tunel link ali    # prints ali's link again
```

The link is a standard `vless://` link, so phone apps such as Hiddify or v2rayNG accept it too.

## Remove

```sh
tunel remove
```

Removes everything tunel added: the service, the network adapter, the settings, the `PATH` entry, its block in `~/.ssh/config`, and tunel itself. On a server it also removes the server and its keys.

## Build

With Go:

```sh
./build.sh      # dist/: Linux and Windows, amd64 and arm64, and checksums.txt
go test -tags with_utls,with_gvisor,badlinkname,tfogo_checklinkname0 -ldflags=-checklinkname=0 .
```

Pushing a `v*` tag builds and publishes a release, which the install scripts download.

The tunnel engine is [sing-box](https://github.com/SagerNet/sing-box), built in. Like sing-box, tunel is licensed under the GPL-3.0.
