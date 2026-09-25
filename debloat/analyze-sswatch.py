#!/usr/bin/env python3
"""analyze-sswatch.py -- summarize a device-sswatch.sh capture by process.

    debloat/analyze-sswatch.py <ssw-dir-or-ss.txt> [--all]

The on-device watcher stores raw `ss -tnp` lines prefixed with a timestamp.
This groups them by owning process and prints every peer it was seen talking to,
flagging Huawei address space -- so a firewall's anonymous "uid 1000" entries
become package names.
"""
import ipaddress
import re
import sys
from collections import defaultdict
from pathlib import Path

HUAWEI = [ipaddress.ip_network(x) for x in
          ("2407:c080::/32", "2407:8000::/24", "119.3.0.0/16", "114.115.0.0/16",
           "49.4.0.0/16", "121.36.0.0/16", "122.112.0.0/16", "139.9.0.0/16",
           "119.8.0.0/16", "124.70.0.0/16", "159.138.0.0/16", "116.205.0.0/16",
           "1.94.0.0/16")]
LINE = re.compile(r"^(\S+)\s+(\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+users:\(\("
                  r"\"?([^\"]+?)\"?,\s*pid=(\d+)")


def ip_of(s):
    s = s.strip()
    if s.startswith("["):
        s = s[1:s.index("]")]
    if ":" in s:
        if s.startswith("::ffff:"):
            s = s[len("::ffff:"):]
        else:
            return ipaddress.IPv6Address(s)
    return ipaddress.IPv4Address(s)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    p = Path(sys.argv[1])
    f = p / "ss.txt" if p.is_dir() else p
    show_all = "--all" in sys.argv
    per = defaultdict(lambda: defaultdict(int))
    span = {}
    for line in f.read_text(errors="replace").splitlines():
        m = LINE.match(line)
        if not m:
            continue
        ts, state, local, peer, name, pid = m.groups()
        if state == "LISTEN":
            continue
        per[(name, pid)][(peer, state)] += 1
        e = span.setdefault((name, pid), [ts, ts])
        e[1] = ts
    print(f"# {f}: {len(per)} processes held outbound sockets")
    for (name, pid), peers in sorted(per.items(), key=lambda kv: -sum(kv[1].values())):
        hw = []
        for (peer, state), n in peers.items():
            try:
                a = ip_of(peer.rsplit(":", 1)[0])
            except Exception:
                continue
            if any(a in net for net in HUAWEI):
                hw.append((peer, state, n))
        if not hw and not show_all:
            continue
        s = span[(name, pid)]
        print(f"\n{name} (pid {pid})  {s[0]}..{s[1]}"
              + (f"   *** {sum(n for _, _, n in hw)} samples TO HUAWEI ***" if hw else ""))
        for peer, state, n in sorted(hw or [], key=lambda x: -x[2]):
            print(f"    {n:5d}x {peer} {state}   <== HUAWEI")
        if show_all:
            for (peer, state), n in sorted(peers.items(), key=lambda kv: -kv[1])[:6]:
                print(f"    {n:5d}x {peer} {state}")


if __name__ == "__main__":
    main()
