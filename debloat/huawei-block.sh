#!/system/bin/sh
# huawei-block.sh -- packet-level block of Huawei Cloud destinations, THIS BOOT ONLY.
#
#   sh huawei-block.sh apply | flush | status
#
# Rules are inserted at the top of the OUTPUT chains, ahead of EMUI's own
# ip_block_list / uid_trust_list / ip_trust_list / network_reject_list, so a
# destination Huawei trusts by default cannot override them.  Nothing is
# persisted: a reboot clears them (that is the point -- no package state changes,
# no reboot needed to undo).
#
# Endpoints blocked by default: the two that were measured live on 2026-09-18 --
#   com.huawei.android.pushagent -> 159.138.204.113:5223 (Huawei Cloud Moscow,
#     ecs-159-138-204-113.compute.hwclouds-dns.com, AS136907) -- the push port,
#     blocked by /16 so it cannot re-route inside that region;
#   com.huawei.nearby -> 80.158.20.104:443 (open-telekom-cloud.com, AS6878
#     T-Systems Leipzig, where that process ran hwddmp's services);
# plus the v6 range the firewall log showed (2407:c080::/32, Huawei Cloud).
# The wider Huawei Cloud list is in WIDER_V4/WIDER_V6 below -- uncomment when a
# capture shows a client moving outside the default set.
#
# Revert: `sh huawei-block.sh flush` (or reboot).
SU=${SU:-/data/local/tmp/su}
V4="159.138.0.0/16 80.158.20.0/24"
V6="2407:c080::/32"
# WIDER_V4="119.3.0.0/16 114.115.0.0/16 49.4.0.0/16 121.36.0.0/16 122.112.0.0/16 139.9.0.0/16 119.8.0.0/16 124.70.0.0/16 116.205.0.0/16 1.94.0.0/16 159.138.0.0/16 80.158.20.0/24"
# WIDER_V6="2407:c080::/32 2407:8000::/24 2a0b::/24"

apply() {
  for c in $V4; do
    iptables -C OUTPUT -d "$c" -j REJECT 2>/dev/null || iptables -I OUTPUT 1 -d "$c" -j REJECT || echo "FAIL out v4 $c"
    # inbound too: an accepted push is an accepted command channel
    iptables -C INPUT -s "$c" -j DROP 2>/dev/null || iptables -I INPUT 1 -s "$c" -j DROP || echo "FAIL in v4 $c"
  done
  for c in $V6; do
    ip6tables -C OUTPUT -d "$c" -j REJECT 2>/dev/null || ip6tables -I OUTPUT 1 -d "$c" -j REJECT || echo "FAIL out v6 $c"
    ip6tables -C INPUT -s "$c" -j DROP 2>/dev/null || ip6tables -I INPUT 1 -s "$c" -j DROP || echo "FAIL in v6 $c"
  done
  echo "# applied"
}

flush() {
  for c in $V4 $WIDER_V4; do
    while iptables -D OUTPUT -d "$c" -j REJECT 2>/dev/null; do :; done
    while iptables -D INPUT -s "$c" -j DROP 2>/dev/null; do :; done
  done
  for c in $V6 $WIDER_V6; do
    while ip6tables -D OUTPUT -d "$c" -j REJECT 2>/dev/null; do :; done
    while ip6tables -D INPUT -s "$c" -j DROP 2>/dev/null; do :; done
  done
  echo "# flushed"
}

status() {
  echo "== v4 OUTPUT (top)"; iptables -L OUTPUT -n --line-numbers | sed -n '1,8p'
  echo "== v6 OUTPUT (top)"; ip6tables -L OUTPUT -n --line-numbers | sed -n '1,8p'
  echo "== EMUI lists that matter (Huawei's own trust/block) =="
  for ch in ip_trust_list ip_block_list; do
    echo "-- $ch"; iptables -L "$ch" -n 2>/dev/null | sed -n '1,6p'
  done
}

probe() {
  # No nc/curl/wget/openssl on this device; ping is the only reachability tool.
  echo "== negative control (must fail): blocked Huawei push endpoint"
  timeout 6 ping -c 1 -W 3 159.138.204.113 2>&1 | tail -2
  echo "== positive control (must succeed): unrelated host"
  timeout 6 ping -c 1 -W 3 1.1.1.1 2>&1 | tail -2
  echo "== rule counters (non-zero pkts = the block is matching traffic) =="
  iptables -L OUTPUT -n -v | awk 'NR>2 && /REJECT/ {print "   v4 out:", $1, "pkts ->", $9}'
  ip6tables -L OUTPUT -n -v | awk 'NR>2 && /REJECT/ {print "   v6 out:", $1, "pkts ->", $9}'
  iptables -L INPUT -n -v | awk 'NR>2 && /DROP/ && $9 ~ /^([0-9]+\.){3}/ {print "   v4 in :", $1, "pkts <-", $8}'
  echo "== huawei sockets still up? =="
  ss -tnp 2>/dev/null | grep -iE "huawei|159\.138|80\.158" || echo "   none"
}

case "${1:-status}" in
  apply)  apply; probe ;;
  flush)  flush; probe ;;
  status) status ;;
  *) echo "usage: sh $0 apply|flush|status"; exit 2 ;;
esac
