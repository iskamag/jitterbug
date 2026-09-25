#!/bin/bash
# devlock.sh -- serialize on-device runs between cooperating agents.
#   tools/devlock.sh <max_seconds> <tag> -- <command...>
set -u
MAX=${1:?usage: devlock.sh <max_seconds> <tag> -- <cmd...>}
TAG=${2:?tag required}
shift 2
[ "${1:-}" = "--" ] && shift
[ $# -gt 0 ] || { echo "devlock: no command" >&2; exit 2; }

SER=${SER:-U4G6R20811000860}
A="adb -s $SER"
LOCK=/tmp/matepad_device.lock
STAMP=/tmp/matepad_device.last
COOLDOWN=${COOLDOWN:-20}
WAIT_LOCK=${WAIT_LOCK:-900}
LOG=/tmp/matepad_device.log

exec 9>"$LOCK" || exit 3
if ! flock -w "$WAIT_LOCK" 9; then
  echo "[devlock:$TAG] BLOCKED: another agent holds the device" >&2
  exit 4
fi
echo "[devlock:$TAG] lock acquired $(date '+%H:%M:%S')" | tee -a "$LOG"

if [ -f "$STAMP" ]; then
  last=$(cat "$STAMP" 2>/dev/null || echo 0); now=$(date +%s); gap=$(( now - last ))
  if [ "$gap" -lt "$COOLDOWN" ]; then
    echo "[devlock:$TAG] cool-down $(( COOLDOWN - gap ))s" | tee -a "$LOG"
    sleep $(( COOLDOWN - gap ))
  fi
fi

for i in $(seq 1 30); do
  [ "$( $A shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
  echo "[devlock:$TAG] waiting for device/boot ($i)" | tee -a "$LOG"
  $A wait-for-device >/dev/null 2>&1
  sleep 5
done
if [ "$( $A shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]; then
  echo "[devlock:$TAG] REFUSING: device not booted" | tee -a "$LOG"; exit 5
fi

echo "[devlock:$TAG] RUN (cap ${MAX}s): $*" | tee -a "$LOG"
t0=$(date +%s)
timeout -s KILL "$MAX" "$@"
rc=$?
date +%s > "$STAMP"
echo "[devlock:$TAG] rc=$rc after $(( $(date +%s) - t0 ))s" | tee -a "$LOG"
if ! $A shell getprop sys.boot_completed >/dev/null 2>&1; then
  echo "[devlock:$TAG] *** DEVICE DOWN/PANICKING -- wait for boot ***" | tee -a "$LOG"
else
  echo "[devlock:$TAG] device still up" | tee -a "$LOG"
fi
exit $rc