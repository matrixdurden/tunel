#!/bin/sh
# Downloads tunel for this Linux machine, checks it, and runs it:
#
#   curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- server
#   curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- client 'vless://…'
#   curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- update
#
# tunel installs itself to /usr/local/bin; `tunel remove` takes everything away again.
set -eu

base=https://github.com/matrixdurden/tunel/releases/latest/download

say() { printf '%s\n' "$*" >&2; }
die() { say "tunel: $*"; exit 1; }

if [ $# -eq 0 ]; then
  say "usage:"
  say "  curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- server"
  say "  curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- client 'vless://…'"
  say "  curl -fsSL https://raw.githubusercontent.com/matrixdurden/tunel/main/install.sh | sh -s -- update"
  exit 2
fi

[ "$(uname -s)" = Linux ] || die "this script is for Linux; on Windows run: irm https://raw.githubusercontent.com/matrixdurden/tunel/main/install.ps1 | iex"
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) die "unsupported CPU: $(uname -m)" ;;
esac
command -v curl >/dev/null || die "curl is required"
command -v sha256sum >/dev/null || die "sha256sum is required"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM
file=tunel-linux-$arch

curl -fsSL "$base/$file" -o "$tmp/$file" || die "download failed: $base/$file"
curl -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || die "download failed: $base/checksums.txt"
(cd "$tmp" && grep " $file\$" checksums.txt | sha256sum -c --quiet -) || die "checksum mismatch; nothing was installed"
chmod 755 "$tmp/$file"

# The link and sudo's password prompt read from the terminal, not from this pipe.
if { true </dev/tty; } 2>/dev/null; then
  "$tmp/$file" "$@" </dev/tty
else
  "$tmp/$file" "$@"
fi
