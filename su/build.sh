#!/bin/bash
# Build the su subsystem as static aarch64 binaries (musl: there is nothing
# to link against on the device).  sud is the daemon, su the client, sumgr the
# manager CLI.
#
#   CC=<cross-gcc> ./build.sh     # default: ../tools/aarch64-linux-musl-cross
#   ./build.sh test               # host tests for policy + framing instead
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-$(dirname "$DIR")/../tools/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc}"
CFLAGS="-O2 -static -no-pie -Wall -Wextra -Wno-unused-parameter"

if [ "${1:-}" = test ]; then
    exec "$DIR/tests/run.sh"
fi

common="client.c config.c framing.c policy.c"

for p in sud su sumgr; do
    # shellcheck disable=SC2086
    "$CC" $CFLAGS -o "$DIR/$p" "$DIR/$p.c" $DIR/$common
    echo "[+] $DIR/$p"
done
ls -l "$DIR/sud" "$DIR/su" "$DIR/sumgr" | awk '{print $5, $9}'
