#!/usr/bin/env python3
"""analyze-sockets.py -- join a device socket dump to the owning processes.

    debloat/analyze-sockets.py <sockdump-dir> [--all]

Reads tcp/tcp6/udp/udp6 + ps.txt + fds (pid inode) written by
device-sockets.sh, decodes the /proc/net address format (four 32-bit
little-endian words for IPv6), joins on the socket inode, and prints the
process behind every non-LISTEN connection -- flagging Huawei ranges.

--all also lists non-Huawei destinations.
"""
import ipaddress
import struct
import sys
from collections import defaultdict
from pathlib import Path

# Huawei Cloud (the AS55990 range the firewall log shows) + common Huawei space.
HUAWEI_V6 = [ipaddress.ip_network("2407:c080::/32")]
HUAWEI_V4 = [
    ipaddress.ip_network(x)
    for x in ("119.3.0.0/16", "114.115.0.0/16", "49.4.0.0/16",
              "121.36.0.0/16", "122.112.0.0/16", "139.9.0.0/16",
              "119.8.0.0/16", "124.70.0.0/16")
]


def is_huawei(addr):
    if addr.version == 6:
        return any(addr in n for n in HUAWEI_V6)
    return any(addr in n for n in HUAWEI_V4)


def decode_addr4(hexword):
    return ipaddress.IPv4Address(struct.pack("<I", int(hexword, 16)))


def decode_addr6(hexstr):
    words = [hexstr[i:i + 8] for i in range(0, 32, 8)]
    raw = b"".join(struct.pack("<I", int(w, 16)) for w in words)
    return ipaddress.IPv6Address(raw)


def read_table(path, v6):
    rows = []
    for line in Path(path).read_text(errors="replace").splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        local, rem, state, inode = f[1], f[2], f[3], f[9]
        try:
            laddr, lport = local.rsplit(":", 1)
            raddr, rport = rem.rsplit(":", 1)
            loc = (decode_addr6(laddr) if v6 else decode_addr4(laddr), int(lport, 16))
            rmt = (decode_addr6(raddr) if v6 else decode_addr4(raddr), int(rport, 16))
        except Exception:
            continue
        rows.append({"state": state, "inode": inode, "local": loc, "remote": rmt})
    return rows


STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
          "06": "TIME_WAIT", "08": "CLOSE_WAIT", "0A": "LISTEN", "07": "CLOSE"}


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    d = Path(sys.argv[1])
    show_all = "--all" in sys.argv
    pid_of_inode = {}
    for line in (d / "fds").read_text(errors="replace").splitlines():
        parts = line.split()
        if len(parts) == 2:
            pid_of_inode.setdefault(parts[1], parts[0])
    names = {}
    for line in (d / "ps.txt").read_text(errors="replace").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            names[parts[0]] = parts[1].strip()

    per_proc = defaultdict(list)
    for fname, v6 in (("tcp", False), ("tcp6", True), ("udp", False), ("udp6", True)):
        f = d / fname
        if not f.exists():
            continue
        for row in read_table(f, v6):
            if row["state"] == "0A":          # LISTEN, not interesting
                continue
            pid = pid_of_inode.get(row["inode"])
            per_proc[(pid, fname)].append(row)

    def fmt(pid, rows, fname):
        name = names.get(pid or "", "?")
        out = [f"pid={pid or '?'} ({name}) {fname}  {len(rows)} conn(s)"]
        for r in sorted(rows, key=lambda r: str(r["remote"][0]))[:6]:
            ip, port = r["remote"]
            out.append(f"    -> [{ip}]:{port}  {STATES.get(r['state'], r['state'])}")
        if len(rows) > 6:
            out.append(f"    ... +{len(rows) - 6} more")
        return "\n".join(out)

    hw = []
    other = 0
    for (pid, fname), rows in per_proc.items():
        hw_rows = [r for r in rows if is_huawei(r["remote"][0])]
        other += len(rows) - len(hw_rows)
        if hw_rows:
            hw.append((len(hw_rows), fmt(pid, hw_rows, fname)))
    print(f"### connections to Huawei ranges ({sum(n for n, _ in hw)}), "
          f"other non-listen connections: {other}")
    for _, text in sorted(hw, reverse=True):
        print(text)
    if show_all:
        print("### everything else")
        for (pid, fname), rows in sorted(per_proc.items(), key=lambda kv: -len(kv[1])):
            nhw = [r for r in rows if not is_huawei(r["remote"][0])]
            if nhw:
                print(fmt(pid, nhw, fname))


if __name__ == "__main__":
    main()
