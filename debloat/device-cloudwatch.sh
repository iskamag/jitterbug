#!/system/bin/sh
# device-cloudwatch.sh <seconds> [outdir] -- catch and attribute bursty traffic.
#
# A 1-second sample misses short-lived sockets (the firewall log shows a burst
# every ~2 s that a 30 s sample did not see at all).  So sample the socket tables
# ~4x/s, logging every non-LISTEN socket with its uid and inode, and snapshot the
# uid-1000 (system) fd->inode map every 5th iteration so an inode can be resolved
# to a process afterwards.
#
# SAFETY: no /proc/<pid>/cmdline reads (README do-not).
SECS=${1:-600}
OUT=${2:-/data/local/tmp/cloudwatch}
mkdir -p "$OUT" || exit 2
: > "$OUT/conns.txt"; : > "$OUT/map.txt"; : > "$OUT/ps.txt"
end=$(( $(date +%s) + SECS ))
i=0
while [ "$(date +%s)" -lt "$end" ]; do
  i=$(( i + 1 ))
  ts=$(date +%H:%M:%S)
  for t in tcp tcp6; do
    awk -v ts="$ts" -v t="$t" '$1 != "sl" && $4 != "0A" \
      {print ts, t, $2, $3, $4, $8, $10}' "/proc/net/$t" >> "$OUT/conns.txt"
  done
  if [ $(( i % 5 )) -eq 1 ]; then
    ps -A -o PID,USER,NAME > "$OUT/ps.txt"
    for pid in $(awk '$2 == "system" {print $1}' "$OUT/ps.txt"); do
      for f in /proc/$pid/fd/*; do
        x=$(readlink "$f" 2>/dev/null) || continue
        case "$x" in
          "socket:["*"]") ino=${x#socket:[}; echo "$ts $pid ${ino%]}" >> "$OUT/map.txt" ;;
        esac
      done
    done
  fi
  sleep 0.2
done
chmod -R a+rX "$OUT"
echo "cloudwatch: $i samples, $(wc -l < "$OUT/conns.txt") conn lines, $(wc -l < "$OUT/map.txt") map lines"
