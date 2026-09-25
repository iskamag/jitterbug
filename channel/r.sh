D=/data/local/tmp/dump
/system/bin/mkdir -p "$D"
m=$(/system/bin/cat /data/local/tmp/mode 2>/dev/null)
c=$(/system/bin/cat /proc/self/attr/current 2>/dev/null)
echo "fired mode=$m pid=$$ ctx=$c" >> "$D/hits"
if [ "$m" = "copy" ]; then
  while read p; do
    [ -z "$p" ] && continue
    /system/bin/mkdir -p "$D/$p"
    /system/bin/cp -r /data/data/$p/. "$D/$p/" 2>>"$D/err.$p"
    /system/bin/cp -r /data/user/0/$p/. "$D/$p/" 2>>"$D/err.$p"
  done < /data/local/tmp/pkgs
  echo done > "$D/DONE"
fi
