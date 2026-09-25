#!/bin/bash
# channel.sh -- drive the persistent root command channel that runs as
# uid 0 / u:r:installd:s0 (spawned by the cold libbase GetBoolProperty hook).
#
# usage:  ./channel.sh '<shell commands>'      # run and print output
#         ./channel.sh -s '<shell commands>'   # just submit, don't wait
#
# Protocol: write a script to /data/local/tmp/cmd; the in-installd loop
# executes it with output in /data/local/tmp/out (root, chmod 666 by the
# wrapper's first line).
set -u
DEV="${CHANNEL_DEV:-U4G6R20811000860}"
WAIT=1
[ "${1:-}" = "-s" ] && { WAIT=0; shift; }
CMD="${1:?usage: channel.sh [-s] '<commands>'}"

TMP=$(mktemp)
{
  echo 'chmod 666 /data/local/tmp/out /data/local/tmp/hits 2>/dev/null'
  printf '%s\n' "$CMD"
} > "$TMP"

adb -s "$DEV" shell 'rm -f /data/local/tmp/out' >/dev/null 2>&1
adb -s "$DEV" push "$TMP" /data/local/tmp/cmd >/dev/null || { echo "push failed"; exit 1; }
rm -f "$TMP"

if [ "$WAIT" = 1 ]; then
  for i in $(seq 1 120); do
    sleep 1
    OUT=$(adb -s "$DEV" shell 'cat /data/local/tmp/out 2>/dev/null' 2>/dev/null)
    case "$OUT" in
      *"[exit "*) printf '%s\n' "$OUT"; exit 0 ;;
    esac
  done
  echo "TIMEOUT waiting for channel output" >&2
  printf '%s\n' "${OUT:-}" >&2
  exit 1
fi
