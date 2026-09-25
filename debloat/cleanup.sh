#!/system/bin/sh
# cleanup.sh -- kill runaway helpers, keep the r.sh command channel / sud.
#
# Two classes of leftover, both from earlier sessions or aborted runs:
#   * `sh /data/local/tmp/debloat.sh ...` reap loops (spawn one `tr` per /proc entry)
#   * `tr '\0' ' ' < /proc/<dead-pid>/cmdline` -- never gets EOF on this kernel,
#     spins at 100% CPU for ever.  Every tr on the device is a runaway.
# The r.sh loops are `sleep 1` pollers and are deliberately left alone.
echo "=== before ==="
ps -A -o PID,PPID,NAME | grep -cE ' tr$'
echo "=== killing reap loops + tr ==="
# bracket trick so this script's own command line cannot match
pkill -9 -f 'debloat[.]sh' 2>/dev/null
pkill -9 -x tr 2>/dev/null
sleep 1
echo "=== after: tr count / reap loops / channel loops ==="
ps -A -o PID,NAME | grep -cE ' tr$'
ps -A -o PID,ARGS 2>/dev/null | grep -c 'debloat[.]sh'
ps -A -o PID,ARGS 2>/dev/null | awk '$2=="sh" && $3=="/data/local/tmp/r.sh"' | wc -l
echo "=== cpu ==="
top -n 1 -b 2>/dev/null | sed -n '4p'
echo "=== root still ok? ==="
id -u
