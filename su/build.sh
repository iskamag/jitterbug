#!/bin/bash
# Build the su subsystem as static aarch64 binaries (musl: nothing to link
# against on the device).  sud is the daemon, su the client, sumgr the manager.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
CC="$(dirname "$DIR")/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc"
CFLAGS="-O2 -static -no-pie -Wall -Wextra -Wno-unused-parameter"

for p in sud su sumgr; do
    "$CC" $CFLAGS -o "$DIR/$p" "$DIR/$p.c" "$DIR/client.c"
    echo "[+] $DIR/$p"
done
ls -l "$DIR/sud" "$DIR/su" "$DIR/sumgr" | awk '{print $5, $9}'
