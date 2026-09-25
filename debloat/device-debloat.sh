#!/system/bin/sh
# device-debloat.sh -- enable/disable the packages in a target list, per user.
# Runs on device as root (via /data/local/tmp/su -c 'sh ...').  No reboot.
#
#   sh device-debloat.sh apply   [targets]   # disable-user, then reap
#   sh device-debloat.sh restore [targets]   # enable
#   sh device-debloat.sh reap    [targets]   # only kill leftover processes
#
# Output: one line per (package,user).  The host parses "OK <op> <pkg> <user>"
# to build the restore list.  Written for /system/bin/sh (no bash arrays).
#
# DO NOT reintroduce a `for p in /proc/[0-9]*; do ... < $p/cmdline` loop here.
# Measured on this device (2026-09-17): if a pid dies between the glob and the
# read, the reader never gets EOF and spins at 100% CPU for ever.  Two orphaned
# channel scripts from an earlier session did exactly that and pegged two cores
# for hours (load average ~50).  The reap below uses one `ps` pass instead.
set -u
MODE=${1:-apply}
LIST=${2:-/data/local/tmp/debloat-targets.txt}
[ -r "$LIST" ] || { echo "FATAL no target list $LIST"; exit 2; }

USERS=$(pm list users 2>/dev/null | sed -n 's/.*UserInfo{\([0-9][0-9]*\).*/\1/p')
[ -n "$USERS" ] || USERS=0
echo "# op=$MODE users=$USERS list=$LIST"

# A disabled package keeps its already-running process: `am force-stop` is a
# no-op for a package sharing uid 1000, and SystemServer only tears the process
# down when the *whole* uid's app state changes.  Kill the processes whose
# command line starts with the package name (with a ":service" or ".Child"
# suffix for its sub-processes) so the disable bites now, not at the next boot.
#
# Matching is done in awk against a set read from a file: a single regex with
# 71 alternatives silently matched nothing (measured 2026-09-17).
reap_all() {
  awk '!/^#/ && NF>=2 {print $2}' "$LIST" | sort -u > /data/local/tmp/debloat-pkgs.txt
  ps -A -o PID,ARGS 2>/dev/null > /data/local/tmp/debloat-ps.txt
  awk '
    NR==FNR { pk[$1]=1; next }
    {
      if ($1 !~ /^[0-9]+$/) next
      n=$2; hit=0
      for (k=0; k<6; k++) {
        if (n in pk) { hit=1; break }
        if (index(n, ":") > 0) { n=substr(n, 1, index(n, ":")-1); continue }
        j=match(n, /\.[A-Za-z0-9_]+$/)
        if (j == 0) break
        n=substr(n, 1, j-1)
      }
      if (hit) print $1, n
    }' /data/local/tmp/debloat-pkgs.txt /data/local/tmp/debloat-ps.txt \
      > /data/local/tmp/debloat-reap.txt
  _cand=$(wc -l < /data/local/tmp/debloat-reap.txt)
  _n=0
  while read -r _pid _name; do
    if kill -9 "$_pid" 2>/dev/null; then
      echo "KILL $_pid $_name"
      _n=$(( _n + 1 ))
    fi
  done < /data/local/tmp/debloat-reap.txt
  echo "# reap: $_cand candidates, $_n killed"
}

if [ "$MODE" = reap ]; then
  reap_all
  echo "# done"
  exit 0
fi

while read -r grp pkg rest; do
  case "$grp" in ''|\#*) continue ;; esac
  [ -n "$pkg" ] || continue
  for u in $USERS; do
    case "$MODE" in
      apply)
        out=$(pm disable-user --user "$u" "$pkg" 2>&1)
        rc=$?
        ;;
      restore)
        out=$(pm enable --user "$u" "$pkg" 2>&1)
        rc=$?
        ;;
      *) echo "FATAL bad mode $MODE"; exit 2 ;;
    esac
    if [ $rc -eq 0 ]; then
      echo "OK $MODE $pkg $u"
    else
      # "not installed for user" is expected for preload apps on user 10
      case "$out" in
        *"not installed for"*) echo "SKIP $pkg $u: not installed for this user" ;;
        *) echo "FAIL $pkg $u: $(printf '%s' "$out" | tr '\n' ' ')" ;;
      esac
    fi
  done
done < "$LIST"

[ "$MODE" = apply ] && reap_all
echo "# done"
