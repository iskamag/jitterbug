#!/system/bin/sh
# drop-services.sh -- clear the ActivityManager service records of disabled packages.
#
# Why killing processes is not enough: a disabled package's services stay
# registered in ActivityManager, and AMS restarts them on death (and
# `am force-stop` is a no-op for a package sharing uid 1000).  Those restarted
# processes keep running their network clients -- measured 2026-09-17:
# com.huawei.nearby kept a live TLS session to 80.158.20.104:443 (Open Telekom
# Cloud, DE) for minutes after the package was disabled, on the *direct* wlan
# path, i.e. bypassing the user's VPN-based firewall.
#
# `am stop-service` removes the record instead of racing it, so the process dies
# and nothing restarts it (the package is disabled, so no component can start).
#
#   sh drop-services.sh [targets-file]
SU=${SU:-/data/local/tmp/su}
LIST=${1:-/data/local/tmp/debloat-targets.txt}
DUMP=/data/local/tmp/svc-dump.txt
dumpsys activity services > "$DUMP" 2>/dev/null

for pkg in $(awk '!/^#/ && NF>=2 {print $2}' "$LIST"); do
  comps=$(grep -o "$pkg/[A-Za-z0-9_.\$]*" "$DUMP" 2>/dev/null | sort -u)
  [ -n "$comps" ] || continue
  for comp in $comps; do
    if am stop-service --user 0 -n "$comp" >/dev/null 2>&1; then
      echo "STOP $comp"
    else
      echo "FAIL $comp"
    fi
  done
done
echo "# done"
