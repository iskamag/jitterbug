#!/usr/bin/env bash
# pocrun.sh -- run one PoC on the device, collect everything, never reboot.
#
#   tools/pocrun.sh -b <local-binary> [-n <device-name>] [-a "<args>"]
#                   [-t <timeout_s>] [-T <tag>] [-w <boot-wait_s>]
#                   [-u <min_uptime_s, default 600>] [-i (idle gate)]
#
# What it does, in order:
#   1. preflight: device present, sys.boot_completed=1, record boot_id/uptime
#   2. upload: push -> sync -> md5 verify ON DEVICE (a panic once ate a binary)
#   3. run:    nohup <dev> <args> > /data/local/tmp/<name>_<ts>.log 2>&1
#              and echo $? > .../<name>_<ts>.rc
#   4. collect: poll the rc file (bounded); if the device stops answering,
#              wait (bounded) for it to come back and harvest the dropbox
#              panic record (dumpsys dropbox --print is shell-readable here)
#   5. persist: everything into <repo>/exploits/CVE-2022-38181/runs/<ts>-<tag>/
#              host.log  dev.log  rc  meta.txt  dropbox.txt  panic.txt
#
# It NEVER reboots, never loops, and never probes an address the caller did
# not ask for.  One invocation = one device run.
set -u

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SER=${SER:-U4G6R20811000860}
DEVNAME=mali_boot
TIMEOUT=600
BOOTWAIT=300
TAG=run
ARGS=""
IDLE_WAIT=0
MIN_UPTIME=${MIN_UPTIME:-60}    # just enough for adb/services after a reboot.
				# The old 600s settle bought nothing: mb124
				# panicked at 5038s uptime (jit_free race loss
				# fires at any boot age); iteration speed is
				# worth more than the defunct heuristic.
RUNS=${RUNS:-$REPO/exploits/CVE-2022-38181/runs}

usage() { sed -n '2,25p' "$0"; exit 2; }

while getopts "b:n:a:t:T:w:u:ih" o; do
  case $o in
    b) BIN=$OPTARG ;;
    n) DEVNAME=$OPTARG ;;
    a) ARGS=$OPTARG ;;
    t) TIMEOUT=$OPTARG ;;
    T) TAG=$OPTARG ;;
    w) BOOTWAIT=$OPTARG ;;
    u) MIN_UPTIME=$OPTARG ;;
    i) IDLE_WAIT=1 ;;
    *) usage ;;
  esac
done
[ -n "${BIN:-}" ] || usage
[ -f "$BIN" ] || { echo "pocrun: no such binary: $BIN" >&2; exit 4; }

A="adb -s $SER"
TS=$(date -u +%Y%m%dT%H%M%SZ)
RUN=$RUNS/$TS-$TAG
mkdir -p "$RUN"
HOSTLOG=$RUN/host.log
META=$RUN/meta.txt
MD5=$(md5sum "$BIN" | awk '{print $1}')
MD5_AT_START=$MD5
DEVLOG=/data/local/tmp/${DEVNAME}_${TS}.log
DEVRCP=/data/local/tmp/${DEVNAME}_${TS}.rc

say() { echo "$@" | tee -a "$HOSTLOG"; }
adbsh() { timeout 20 $A shell "$@" 2>&1; }
verdict() { echo "$1" > "$RUN/verdict"; say "VERDICT: $1"; }

# --- 1. preflight -----------------------------------------------------------
BOOTID0=$(adbsh cat /proc/sys/kernel/random/boot_id | tr -d '\r')
UP0=$(adbsh cat /proc/uptime | awk '{print $1}')
BC=$(adbsh getprop sys.boot_completed | tr -d '\r')
say "== pocrun $TS tag=$TAG bin=$BIN md5=$MD5"
say "== device $SER boot_completed=$BC boot_id=$BOOTID0 uptime=$UP0"
if [ "$BC" != "1" ]; then verdict "PREFLIGHT-FAIL(not booted)"; exit 4; fi

# Minimum uptime: the race's documented "pre-jit_free" panic has only ever hit
# freshly booted devices (2-5 min); every historical win came from settled
# load.  While the uptime is short, no PoC is started.
say "== uptime ${UP0}s (minimum ${MIN_UPTIME}s)"
waited=0
while : ; do
  up=$(adbsh cat /proc/uptime | awk '{print int($1)}')
  case "${up:-x}" in ''|*[!0-9]*) up=0 ;; esac
  if [ "$up" -ge "$MIN_UPTIME" ]; then break; fi
  if [ "$waited" -ge 1800 ]; then
    say "== gave up waiting for uptime >= ${MIN_UPTIME}s (at ${up}s)"
    verdict "PREFLIGHT-FAIL(young-boot)"; exit 4
  fi
  sleep 30
  waited=$((waited + 30))
done
UP0=$up
say "== uptime gate satisfied (${up}s)"

if [ "$IDLE_WAIT" = 1 ]; then
  for _ in $(seq 1 30); do
    a=$(adbsh "head -1 /proc/stat"); sleep 3; b=$(adbsh "head -1 /proc/stat")
    idle=$(echo "$a $b" | awk '{for(i=2;i<=11;i++)d1+=$i; for(i=13;i<=22;i++)d2+=$i;
      dd=d2-d1; di=$16-$5; if(dd>0) printf "%d",(100*di)/dd}')
    if [ -n "$idle" ] && [ "$idle" -ge 92 ]; then say "== settled (idle ${idle}%)"; break; fi
    say "== waiting for settled load (idle=${idle:-?}%)"
  done
fi

# --- 2. upload --------------------------------------------------------------
$A push "$BIN" "/data/local/tmp/$DEVNAME" >/dev/null 2>&1 || { verdict "PREFLIGHT-FAIL(push)"; exit 4; }
adbsh sync
GOT=$(adbsh "md5sum /data/local/tmp/$DEVNAME" | awk '{print $1}')
if [ "$GOT" != "$MD5" ]; then verdict "PREFLIGHT-FAIL(md5 $GOT != $MD5)"; exit 4; fi
MD5_NOW=$(md5sum "$BIN" | awk '{print $1}')
if [ "$MD5_NOW" != "$MD5_AT_START" ]; then
  say "== WARNING: the local binary changed while this run was starting"
  verdict "PREFLIGHT-FAIL(binary rebuilt mid-flight)"; exit 4
fi
adbsh "chmod 755 /data/local/tmp/$DEVNAME"
say "== uploaded /data/local/tmp/$DEVNAME md5 verified"

# --- 3. run -----------------------------------------------------------------
adbsh "rm -f $DEVLOG $DEVRCP"
$A shell "nohup sh -c 'cd /data/local/tmp; ./$DEVNAME $ARGS > $DEVLOG 2>&1; echo \$? > $DEVRCP' >/dev/null 2>&1 &" >/dev/null 2>&1
say "== launched: ./$DEVNAME $ARGS  (timeout ${TIMEOUT}s)"
STATE=TIMEOUT
elapsed=0
for _ in $(seq 1 $((TIMEOUT / 5))); do
  sleep 5
  elapsed=$((elapsed + 5))
  # the rc file exists only when the on-device shell wrapper has finished
  if timeout 20 $A shell "[ -f $DEVRCP ]" >/dev/null 2>&1; then
    RC=$(timeout 20 $A shell "cat $DEVRCP" 2>/dev/null | tr -d '[:space:]')
    STATE=DONE; break
  fi
  if ! $A shell true >/dev/null 2>&1; then STATE=DOWN; break; fi
  if [ $((elapsed % 30)) = 0 ]; then
    say "== ...${elapsed}s (still running)"
  fi
done
if [ "$STATE" = TIMEOUT ]; then
  pid=$(adbsh "ps -A | grep $DEVNAME | grep -v grep" | awk '{print $2}' | head -1)
  [ -n "${pid:-}" ] && { say "== timeout: killing on-device pid $pid"; adbsh "kill -9 $pid"; }
fi
say "== run state: $STATE${RC:+ rc=$RC}"

# --- 4. panic / reboot recovery ---------------------------------------------
DROPBOX=""
if [ "$STATE" = DOWN ]; then
  say "== device stopped answering -- waiting up to ${BOOTWAIT}s for it to come back"
  for _ in $(seq 1 $((BOOTWAIT / 5))); do
    sleep 5
    bc=$(adbsh getprop sys.boot_completed | tr -d '\r')
    [ "$bc" = "1" ] && break
  done
  BOOTID1=$(adbsh cat /proc/sys/kernel/random/boot_id | tr -d '\r')
  UP1=$(adbsh cat /proc/uptime | awk '{print $1}')
  say "== came back: boot_id=$BOOTID1 uptime=$UP1 (was $BOOTID0 / $UP0)"
  DROPBOX=$(timeout 120 $A shell dumpsys dropbox --print 2>/dev/null)
  printf '%s\n' "$DROPBOX" > "$RUN/dropbox.txt"
  # only THIS boot's record: the last SYSTEM_LAST_KMSG section in the dump
  printf '%s\n' "$DROPBOX" | awk '
    /SYSTEM_LAST_KMSG/ { start = NR }
    { buf[NR] = $0 }
    END { for (i = start; i <= NR; i++) print buf[i] }' > "$RUN/lastkmsg.txt"
  grep -nE "Kernel panic|panic\+0x|Unable to handle|Internal error|SError|Comm:|PC is at|Call trace|do_mem_abort|el1_da|BUG|watchdog|FAR|ESR|kbase|Mali" \
      "$RUN/lastkmsg.txt" > "$RUN/panic.txt"
  # ATTRIBUTION: the crash belongs to the task named in the panic record, which
  # is often NOT this run -- a wedged earlier attempt trips hung_task/RCU much
  # later and the crash surfaces inside whichever run is active.  Never claim
  # "this run panicked" without checking Comm:/pid: here.
  FATAL=$(grep -m1 -oE "Comm:[A-Za-z0-9_.-]+,CPU:[0-9]+" "$RUN/lastkmsg.txt" 2>/dev/null | head -1)
  FATALPID=$(grep -m1 -oE "pid:[0-9]+,cpu[0-9]+,(khungtaskd|mb[0-9]+|[a-z_]+)\](\[<[0-9a-f]+>\] )?panic\+0x" "$RUN/lastkmsg.txt" 2>/dev/null | head -1)
  echo "fatal_task=$FATAL" >> "$META"
  echo "fatal_frame=$FATALPID" >> "$META"
  FATALNAME=$(echo "$FATAL" | sed -E "s/Comm:([A-Za-z0-9_.-]+),.*/\1/")
  if [ -n "$FATALNAME" ] && [ "$FATALNAME" != "$DEVNAME" ]; then
    say "== NOTE: the crash belongs to task '$FATALNAME', NOT to this run ($DEVNAME)"
    say "==       (a wedged earlier attempt tripping hung_task/RCU surfaces here)"
  fi
  say "== dropbox: $(wc -l < "$RUN/dropbox.txt" 2>/dev/null) lines; this boot's last-kmsg $(wc -l < "$RUN/lastkmsg.txt" 2>/dev/null); extract $(wc -l < "$RUN/panic.txt" 2>/dev/null); fatal task ${FATALNAME:-unknown}"
fi

# --- 5. persist -------------------------------------------------------------
timeout 60 $A shell "cat $DEVLOG" > "$RUN/dev.log" 2>/dev/null
: > "$META"
{
  echo "ts=$TS tag=$TAG"
  echo "binary=$BIN md5=$MD5"
  echo "serial=$SER devname=$DEVNAME args=$ARGS"
  echo "boot_id_before=$BOOTID0 uptime_before=$UP0"
  echo "boot_id_after=${BOOTID1:-} uptime_after=${UP1:-}"
  echo "state=$STATE rc=${RC:-} timeout=$TIMEOUT elapsed=${elapsed:-}"
  echo "devlog=$DEVLOG devrc=$DEVRCP"
} >> "$META"
tail -n 40 "$RUN/dev.log" | sed 's/^/    | /' | tee -a "$HOSTLOG"

if [ "$STATE" = DOWN ]; then
  if [ -n "${FATALNAME:-}" ] && [ "$FATALNAME" != "$DEVNAME" ]; then
    verdict "DEVICE-DOWN (crash belongs to '$FATALNAME', not this run; see $RUN/panic.txt)"
  else
    verdict "PANIC/REBOOT (this run's task faulted; see $RUN/panic.txt)"
  fi
elif [ "$STATE" = TIMEOUT ]; then verdict "HANG (killed by abandon)"
elif grep -q "BOOTSTRAP COMPLETE\|WINDOW OK\|DIAG END" "$RUN/dev.log" 2>/dev/null; then verdict "COMPLETE rc=$RC"
else verdict "RAN rc=$RC"
fi
say "== artifacts: $RUN"
[ "$STATE" = DONE ] && exit 0
[ "$STATE" = TIMEOUT ] && exit 2
exit 3
