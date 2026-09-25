#!/system/bin/sh
# device-sockets.sh -- attribute network connections to processes on this device.
#
# A firewall only sees the uid, and the interesting traffic here runs as uid 1000
# (android.uid.system), shared by dozens of packages.  So: join the socket tables
# to the per-process socket fds on the inode, and (for a heartbeat) watch the
# tables of the uid-1000 processes over a few seconds.
#
# SAFETY: never reads /proc/<pid>/cmdline (see README do-not: a pid dying
# mid-read makes the reader spin at 100% CPU for ever).  fd symlinks are safe.
#
#   sh device-sockets.sh full  <outdir>
#   sh device-sockets.sh watch <outdir> [seconds]
MODE=${1:-full}
OUT=${2:-/data/local/tmp/sockdump}
mkdir -p "$OUT" || exit 2

case "$MODE" in
  full)
    for t in tcp tcp6 udp udp6; do cp "/proc/net/$t" "$OUT/$t" 2>/dev/null; done
    ps -A -o PID,NAME > "$OUT/ps.txt" 2>/dev/null
    : > "$OUT/fds"
    for p in /proc/[0-9]*; do
      for f in $p/fd/*; do
        t=$(readlink "$f" 2>/dev/null) || continue
        case "$t" in
          "socket:["*"]") i=${t#socket:[}; echo "${p#/proc/} ${i%]}" ;;
        esac
      done
    done >> "$OUT/fds"
    echo "full: $(wc -l < "$OUT/fds") fds, $(wc -l < "$OUT/tcp6") tcp6 lines"
    ;;
  watch)
    SECS=${3:-30}
    : > "$OUT/watch.txt"; : > "$OUT/watch-map.txt"
    end=$(( $(date +%s) + SECS ))
    while [ "$(date +%s)" -lt "$end" ]; do
      ts=$(date +%H:%M:%S)
      for t in tcp tcp6; do
        awk -v ts="$ts" -v t="$t" '$1 != "sl" {print ts, t, $2, $3, $4, $10}' \
            "/proc/net/$t" >> "$OUT/watch.txt"
      done
      # uid 1000 is "system"; scan only those processes' fds (cheap per sample)
      for pid in $(ps -A -o PID,USER | awk '$2 == "system" {print $1}'); do
        for f in /proc/$pid/fd/*; do
          t=$(readlink "$f" 2>/dev/null) || continue
          case "$t" in
            "socket:["*"]") i=${t#socket:[}; echo "$ts $pid ${i%]}" >> "$OUT/watch-map.txt" ;;
          esac
        done
      done
      sleep 1
    done
    echo "watch: $(wc -l < "$OUT/watch.txt") table lines, $(wc -l < "$OUT/watch-map.txt") system-uid socket fds"
    ;;
  *) echo "usage: $0 full|watch <outdir> [seconds]"; exit 2 ;;
esac
chmod -R a+rX "$OUT"
