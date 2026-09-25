#!/usr/bin/env bash
# rootcmd.sh - drive the installd-domain root command channel on the MRX-AL09.
#
# The exploit starts (as u:r:installd:s0, uid 0) a loop that watches
# /data/local/tmp/cmd, runs it with /system/bin/sh, and writes stdout/stderr to
# /data/local/tmp/out.  This script is the host-side client:
#
#   ./rootcmd.sh 'id; getenforce'      # one-shot command
#   ./rootcmd.sh                       # interactive prompt (type 'exit' to quit)
#
# It talks to the device only through `adb shell`/`adb push`; no network
# forwarding is used (installd has no tcp permission on this firmware).

set -u
D=/data/local/tmp
TIMEOUT_TICKS=${TIMEOUT_TICKS:-120}   # 120 * 0.5s = 60s

send() {
    local cmd="$1" tmp
    tmp=$(mktemp)
    {
        # the daemon runs as root; its umask can make `out` 0600, so widen it
        echo 'chmod 666 /data/local/tmp/out /data/local/tmp/hits 2>/dev/null'
        printf '%s\n' "$cmd"
    } > "$tmp"
    adb shell "rm -f $D/out" >/dev/null 2>&1
    adb push -q "$tmp" "$D/cmd" >/dev/null 2>&1 || { echo "[rootcmd] push failed"; rm -f "$tmp"; return 1; }
    rm -f "$tmp"
    # the daemon polls at 1 Hz and creates `out` empty before it runs the
    # command, so `-f out` returns a partial read; wait for its terminator.
    local i
    for i in $(seq 1 "$TIMEOUT_TICKS"); do
        if adb shell "grep -q '^\[exit ' $D/out" >/dev/null 2>&1; then break; fi
        sleep 0.5
    done
    adb shell "cat $D/out" 2>&1
    # no host-side chmod here: `out` is root-owned, so a shell chmod gets
    # EPERM and poisons this function's exit status.  The daemon widens the
    # mode itself (first line of every command), which is enough.
}

if [ "$#" -gt 0 ]; then
    send "$*"
    exit $?
fi

echo "[rootcmd] interactive root channel (installd domain). Ctrl-D or 'exit' to quit."
while true; do
    printf 'root@MRX-AL09:/ # '
    if ! IFS= read -r line; then echo; break; fi
    [ -z "$line" ] && continue
    [ "$line" = "exit" ] && break
    send "$line"
done
