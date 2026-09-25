#!/system/bin/sh
# chan-trim.sh -- keep exactly one r.sh command-channel loop.
# The libbase hook fires on every cold call, so loops accumulate over a session
# (22 were running on 2026-09-17); every extra loop runs each command once more.
# This mirrors what tools/su/install.sh and tools/rootshell.sh already do.
ps -A -o PID,ARGS | awk '$2=="sh" && $3=="/data/local/tmp/r.sh" {print $1}' > /data/local/tmp/loops.txt
echo "loops before: $(wc -l < /data/local/tmp/loops.txt)"
keep=$(head -1 /data/local/tmp/loops.txt)
echo "keeping $keep"
tail -n +2 /data/local/tmp/loops.txt | while read -r p; do
  kill -9 "$p" 2>/dev/null && echo "killed $p"
done
sleep 1
echo "loops after: $(ps -A -o PID,ARGS | awk '$2=="sh" && $3=="/data/local/tmp/r.sh"' | wc -l)"
