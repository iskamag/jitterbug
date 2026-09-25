#!/usr/bin/env bash
# host-sswatch.sh [seconds] -- attribute connections to processes, sampled from here.
#
# Why the host and not the device: `ss -tnp` drops the `users:(("name",pid=N))`
# column when its stdout is not a tty (112-char truncation, COLUMNS is ignored),
# and `lsof -i` is not supported by toybox lsof on this build.  `adb shell`
# allocates a pty, so running ss that way keeps the process attribution.
#
# Samples in a tight loop (~3/s: one adb round trip each) and appends timestamped
# lines to debloat/logs/sswatch-<utc>.txt.  Analyze with
# debloat/analyze-sswatch.py <file> --all
set -u
SECS=${1:-600}
SER=${SER:-U4G6R20811000860}
SU=${SU:-/data/local/tmp/su}
OUT=${OUT:-debloat/logs/sswatch-$(date -u +%Y%m%dT%H%M%SZ).txt}
echo "# host-sswatch $SECS s -> $OUT" | tee "$OUT"
end=$(( $(date +%s) + SECS ))
n=0
while [ "$(date +%s)" -lt "$end" ]; do
  n=$(( n + 1 ))
  ts=$(date +%H:%M:%S)
  adb -s "$SER" shell "$SU -c 'ss -tnp'" 2>/dev/null \
    | awk -v ts="$ts" 'NR > 1 && !/LISTEN/ {print ts, $0}' >> "$OUT"
done
echo "# host-sswatch done: $n samples, $(wc -l < "$OUT") lines" | tee -a "$OUT"
