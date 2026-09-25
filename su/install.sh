#!/usr/bin/env bash
# install.sh -- deploy su / sud / sumgr, start the daemon, prove the shell is
# running as uid 0 with the full capability set.
#
#   su/install.sh                    per boot (needs the rshell channel up)
#   SETUID=1 su/install.sh           also remount /data suid and 4755 su
#
# The daemon has to be started through the rshell channel: that is the only
# process on this device running as uid 0 with a full capability set, and sud
# inherits it and hands it to every shell it forks.  (A setuid binary cannot:
# SECURE_NOROOT is locked and adbd's bounding set is 0xc0.)
set -euo pipefail

# The device serial has no safe default; set SER (or use adb's only device).
if [ -z "${SER:-}" ]; then
    SER=$(adb devices | awk 'NR>1 && $2=="device" {print $1; exit}')
    [ -n "$SER" ] || { echo "install.sh: set SER=<serial> (adb devices)"; exit 2; }
fi
DIR=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$DIR/.." && pwd)
# honour SU_DIR so the daemon's paths and this script's agree
D=${SU_DIR:-/data/local/tmp}
MANAGER=${SU_MANAGER_PKG:-com.matepad.sumgr}
TERMUX_BIN=/data/data/com.termux/files/usr/bin
A=(adb -s "$SER")

# the channel scripts live in ../channel in this layout
root() { "$REPO/channel/rootcmd.sh" "$*"; }
say()  { printf '[su] %s\n' "$*"; }

"$DIR/build.sh" >/dev/null

say "pushing su (client), sud (daemon), sumgr (manager)"
for f in su sud sumgr; do
    "${A[@]}" push -q "$DIR/$f" "$D/$f"
done
"${A[@]}" shell "chmod 755 $D/su $D/sud $D/sumgr"

say "root channel probe"
if ! root 'id' | grep -q 'uid=0'; then
    say "no root channel -- run channel/rootshell.sh first"
    exit 1
fi

# One channel and one daemon.  Duplicate r.sh loops all poll the same cmd file,
# so a command would run once per loop; stale suds hold an unlinked socket and
# just leak.  $PPID is the r.sh we are talking through, so it is left alone.
say "deduplicating channels and daemons"
root 'me=$PPID
for p in /proc/[0-9]*; do
  c=$(cat $p/cmdline 2>/dev/null | tr "\0" " ")
  pid=${p#/proc/}
  case "$c" in
    "sh $D/r.sh"*) [ "$pid" = "$me" ] || { kill -9 "$pid"; echo "killed extra channel $pid"; } ;;
    "$D/sud"*)      kill -9 "$pid"; echo "killed stale sud $pid" ;;
  esac
done
sleep 0.3' 2>&1 | sed 's/^/[su] /'

say "starting sud"
root "rm -f $D/su.sock
$D/sud
sleep 1
echo \"pid=\$(cat $D/sud.pid 2>/dev/null)\"
tail -1 $D/sud.log" 2>&1 | sed 's/^/[su] /'

# Termux is where this operation is driven from, and its $PATH does not have
# $D in it, so give it real commands.  Checked as root: the app's
# home is not stat-able by the shell uid.
say "linking su/sumgr into Termux's bin (if installed)"
root "if [ -d $TERMUX_BIN ]; then
  ln -sf $D/su $TERMUX_BIN/su
  ln -sf $D/sumgr $TERMUX_BIN/sumgr
  ls -l $TERMUX_BIN/su $TERMUX_BIN/sumgr
else
  echo 'no Termux at $TERMUX_BIN'
fi" 2>&1 | sed 's/^/[su] /'

say "verifying from an unprivileged shell (uid 2000, CapEff 0)"
"${A[@]}" shell "$D/su -c 'id; grep -E \"^CapEff\" /proc/self/status'" | sed 's/^/[su] /'

say "policies:"
"${A[@]}" shell "$D/sumgr list" | sed 's/^/[su] /'

if [ "${SETUID:-0}" = 1 ]; then
    say "SETUID=1: remounting /data suid + installing the setuid fallback"
    root "mount -o remount,suid /data
chown 0:0 $D/su
chmod 4755 $D/su
ls -l $D/su" | sed 's/^/[su] /'
fi

cat <<EOF

[su] ready:
       adb shell $D/su                 # interactive root shell
       adb shell $D/su -c 'id'
       adb shell $D/sumgr list         # allow|deny|ask <uid> [minutes] | pending | log
     Termux:  su / sumgr               # symlinked into \$PREFIX/bin
     adb:     export PATH=$D:\$PATH    # then just: su
     The manager app ($MANAGER) prompts for uids with no policy.
EOF
