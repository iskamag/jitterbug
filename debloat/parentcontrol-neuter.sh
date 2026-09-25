#!/system/bin/sh
# parentcontrol-neuter.sh -- best available "removal" for a firmware-protected app.
#
# com.huawei.parentcontrol cannot be disabled, uninstalled, hidden or suspended:
# all four are refused ("not allowed to disable/uninstall this package" /
# silent no-op for hide+suspend), because it is the app a *child* must not be
# able to remove.  The APK cannot be deleted either: ro.boot.veritymode=green,
# bootloader locked, /system is the root dm-verity device and the product
# partitions are read-only erofs + dm-verity -- a write there breaks verified
# boot with no repair path.
#
# So: deny it background execution (its services/receivers then cannot run at
# all) and stop anything live.  User-initiated launches from Settings still work,
# which is exactly what the firmware is protecting.
#
# Revert:
#   cmd appops set com.huawei.parentcontrol RUN_IN_BACKGROUND allow
#   cmd appops set com.huawei.parentcontrol RUN_ANY_IN_BACKGROUND allow
P=com.huawei.parentcontrol

echo "--- state before:"
cmd appops get "$P" 2>/dev/null | grep -iE "RUN_IN_BACKGROUND|RUN_ANY_IN_BACKGROUND" || echo "(no ops set)"

cmd appops set "$P" RUN_IN_BACKGROUND deny
cmd appops set "$P" RUN_ANY_IN_BACKGROUND deny
am force-stop --user 0 "$P"
am force-stop --user 10 "$P"

echo "--- state after:"
cmd appops get "$P" 2>/dev/null | grep -iE "RUN_IN_BACKGROUND|RUN_ANY_IN_BACKGROUND"
echo "--- package state (unchanged: still enabled -- the firmware will not let go):"
dumpsys package "$P" | grep -m2 -E "User 0:|User 10:" | sed 's/  */ /g'
echo "--- process:"
ps -A -o PID,NAME | grep -i parentcontrol || echo "not running"
