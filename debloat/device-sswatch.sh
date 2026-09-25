#!/system/bin/sh
# device-sswatch.sh <seconds> [outdir] -- attribute outbound traffic to a process.
#
# `ss -tnp` on this device (as root) prints the owning process *and* pid for every
# TCP socket, so a bursty connection can be attributed without the inode dance.
# Samples every 0.5 s; LISTEN sockets are skipped.
SECS=${1:-600}
OUT=${2:-/data/local/tmp/sswatch}
mkdir -p "$OUT" || exit 2
: > "$OUT/ss.txt"
end=$(( $(date +%s) + SECS ))
n=0
while [ "$(date +%s)" -lt "$end" ]; do
  n=$(( n + 1 ))
  ts=$(date +%H:%M:%S)
  ss -tnp 2>/dev/null | awk -v ts="$ts" '/LISTEN/ {next} NR > 1 {print ts, $0}' >> "$OUT/ss.txt"
  sleep 0.5
done
chmod -R a+rX "$OUT"
echo "sswatch: $n samples, $(wc -l < "$OUT/ss.txt") lines"
