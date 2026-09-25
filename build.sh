#!/bin/sh
# Builds tunel for every supported platform into dist/, with checksums.txt.
set -eu
cd "$(dirname "$0")"

TAGS=with_utls,with_gvisor,badlinkname,tfogo_checklinkname0
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
LDFLAGS="-s -w -buildid= -checklinkname=0 -X main.version=$VERSION -X runtime.godebugDefault=multipathtcp=0,tlssha1=1"

rm -rf dist
mkdir -p dist
for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}
  arch=${target#*/}
  out=tunel-$os-$arch
  [ "$os" = windows ] && out=$out.exe
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -tags "$TAGS" -ldflags "$LDFLAGS" -o "dist/$out" .
  echo "dist/$out"
done
(cd dist && sha256sum tunel-* > checksums.txt)
echo "dist/checksums.txt ($VERSION)"
