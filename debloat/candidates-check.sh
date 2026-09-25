#!/system/bin/sh
# candidates-check.sh -- which uid-1000 candidates can actually reach the network?
#
# For each package: INTERNET permission, plus whether it is disabled (a disabled
# package cannot run, so it cannot be the sender however loud the firewall log is).
LIST=${1:-/data/local/tmp/candidates.txt}
printf '%-42s %-9s %s\n' PACKAGE INTERNET STATE
while read -r p; do
  case "$p" in ''|\#*) continue ;; esac
  n=$(dumpsys package "$p" 2>/dev/null | grep -c "android.permission.INTERNET")
  [ "$n" -gt 0 ] && net=INTERNET || net=-
  d=$(dumpsys package "$p" 2>/dev/null | grep -m1 "^    User 0:" | grep -o "enabled=[0-9]")
  case "$d" in
    enabled=3) st=disabled ;;
    enabled=1) st=enabled ;;
    enabled=0) st=enabled-default ;;
    *) st="?" ;;
  esac
  printf '%-42s %-9s %s\n' "$p" "$net" "$st"
done < "$LIST"
