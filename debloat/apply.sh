#!/usr/bin/env bash
# apply.sh -- push the target list and run the on-device debloat, with logs.
#
#   debloat/apply.sh                 # disable the targets (default)
#   debloat/apply.sh --reap          # only kill leftover processes of the targets
#   debloat/apply.sh --restore       # re-enable exactly what this script disabled
#   debloat/apply.sh --restore-all   # re-enable every package in targets.txt
#
# TARGETS=<file> stages the rollout (e.g. groups A+B first, then A+B+C).
# The device work goes through the root channel (su -> sud, brought up by
# channel/rootshell.sh); wrap the call in tools/devlock.sh.
set -u
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SER=${SER:?set SER to the device serial}
A="adb -s $SER"
D=/data/local/tmp
SU=$D/su
HERE=$REPO/debloat
LOGS=$HERE/logs
STATE=$HERE/state
mkdir -p "$LOGS" "$STATE"

MODE=apply
RESTORE_LIST=""
case "${1:-}" in
  ""|--apply) MODE=apply ;;
  --reap)     MODE=reap ;;
  --restore)
    MODE=restore
    # every state file, not just the newest: a staged rollout writes one per run
    RESTORE_LIST=$(ls -1t "$STATE"/disabled-*.txt 2>/dev/null)
    [ -n "$RESTORE_LIST" ] || { echo "[apply] no state/disabled-*.txt to restore from"; exit 2; }
    ;;
  --restore-all) MODE=restore ;;
  *) echo "usage: apply.sh [--reap|--restore|--restore-all]"; exit 2 ;;
esac

TS=$(date -u +%Y%m%dT%H%M%SZ)
LOG=$LOGS/$MODE-$TS.log

say() { printf '[apply] %s\n' "$*" | tee -a "$LOG"; }

# restore list -> a target file with just those packages (group "R").
# TARGETS=<file> in restore mode restores just that subset instead.
if [ "$MODE" = restore ] && [ -z "${TARGETS:-}" ]; then
  # shellcheck disable=SC2086
  cat $RESTORE_LIST | awk '{print "R", $3}' | sort -u > "$HERE/targets-restore.txt"
  say "restoring $(grep -c '^R ' "$HERE/targets-restore.txt") entries from $(echo $RESTORE_LIST | wc -w) state file(s)"
fi

push_and_run() {
  local list=$1
  $A push -q "$HERE/device-debloat.sh" $D/debloat.sh
  $A push -q "$list" $D/debloat-targets.txt
  $A shell "$SU -c 'sh $D/debloat.sh $MODE $D/debloat-targets.txt'"
}

# --- pre-state
{ echo "### pre: huawei processes with a live process"
  $A shell "$SU -c 'ps -A -o PID,NAME | grep -i huawei'"
} >> "$LOG" 2>&1

case "$MODE" in
  restore) LIST=${TARGETS:-$HERE/targets-restore.txt} ;;
  *)       LIST=${TARGETS:-$HERE/targets.txt} ;;
esac
push_and_run "$LIST" > "$LOGS/tmp-run.txt" 2>&1
tee -a "$LOG" < "$LOGS/tmp-run.txt"

case "$MODE" in
  apply)
    # device-debloat.sh prints "OK apply <pkg> <user>"
    grep '^OK ' "$LOGS/tmp-run.txt" > "$STATE/disabled-$TS.txt" || true
    say "disabled $(wc -l < "$STATE/disabled-$TS.txt") package/user pairs -> $STATE/disabled-$TS.txt"
    ;;
  restore)
    say "re-enabled $(grep -c '^OK ' "$LOGS/tmp-run.txt") package/user pairs"
    ;;
  reap)
    say "reaped $(grep -c '^KILL ' "$LOGS/tmp-run.txt") processes"
    ;;
esac
say "FAIL/SKIP summary: $(grep -c '^FAIL' "$LOGS/tmp-run.txt") fail, $(grep -c '^SKIP' "$LOGS/tmp-run.txt") skip"

# --- post-state / health
{ echo "### post: pm list packages -d"
  $A shell "$SU -c 'pm list packages -d'"
  echo "### post: huawei processes with a live process"
  $A shell "$SU -c 'ps -A -o PID,NAME | grep -i huawei'"
  echo "### post: systemui / launcher / sumgr alive"
  $A shell "pidof com.android.systemui; pidof com.huawei.android.launcher; pidof com.matepad.sumgr"
  echo "### post: crash buffer (root)"
  $A shell "$SU -c 'logcat -d -b crash -t 40 | tail -25'"
} >> "$LOG" 2>&1
rm -f "$LOGS/tmp-run.txt"
say "log: $LOG"
