#!/usr/bin/env python3
"""analyze-capture.py -- attribute a device-cloudwatch.sh capture to processes.

    debloat/analyze-capture.py <capture-dir> [--show-all] [--timeline]

Joins three files the on-device watcher writes:
  conns.txt  <ts> tcp|tcp6 <local> <remote> <st> <uid> <inode>
  map.txt    <ts> <pid> <inode>            (uid-1000 fds, snapshot ~1.2 s)
  ps.txt     <pid> <user> <name>           (last snapshot)

An inode seen in conns.txt and in map.txt is attributed to that pid.  Prints one
block per process with its destinations, marking Huawei address space, so a
firewall's "uid 1000" line becomes a package name.
"""
import ipaddress
import struct
import sys
from collections import defaultdict
from pathlib import Path

HUAWEI_V6 = [ipaddress.ip_network("2407:c080::/32"), ipaddress.ip_network("2407:8000::/24")]
HUAWEI_V4 = [ipaddress.ip_network(x) for x in
             ("119.3.0.0/16", "114.115.0.0/16", "49.4.0.0/16", "121.36.0.0/16",
              "122.112.0.0/16", "139.9.0.0/16", "119.8.0.0/16", "124.70.0.0/16",
              "159.138.0.0/16", "116.205.0.0/16", "1.94.0.0/16")]

STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
          "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
          "09": "LAST_ACK", "0B": "CLOSING"}


def is_huawei(a):
    return any(a in n for n in (HUAWEI_V6 if a.version == 6 else HUAWEI_V4))


def dec(hexstr, v6):
    if v6:
        words = [hexstr[i:i + 8] for i in range(0, 32, 8)]
        return ipaddress.IPv6Address(b"".join(struct.pack("<I", int(w, 16)) for w in words))
    return ipaddress.IPv4Address(struct.pack("<I", int(hexstr, 16)))


def unmapped(a):
    """::ffff:a.b.c.d -> a.b.c.d"""
    if a.version == 6 and a.ipv4_mapped:
        return a.ipv4_mapped
    return a


def main():
    d = Path(sys.argv[1])
    show_all = "--show-all" in sys.argv
    names, users = {}, {}
    for line in (d / "ps.txt").read_text(errors="replace").splitlines():
        f = line.split()
        if len(f) >= 3 and f[0].isdigit():
            names[f[0]] = " ".join(f[2:])
            users[f[0]] = f[1]

    inode_pid = defaultdict(set)
    for line in (d / "map.txt").read_text(errors="replace").splitlines():
        f = line.split()
        if len(f) == 3:
            inode_pid[f[2]].add(f[1])

    per_proc = defaultdict(lambda: {"rows": [], "ts": set(), "unresolved": 0})
    for line in (d / "conns.txt").read_text(errors="replace").splitlines():
        f = line.split()
        if len(f) < 7:
            continue
        ts, proto, local, remote, st, uid, inode = f[:7]
        v6 = proto == "tcp6"
        try:
            l = (unmapped(dec(local.rsplit(":", 1)[0], v6)), int(local.rsplit(":", 1)[1], 16))
            r = (unmapped(dec(remote.rsplit(":", 1)[0], v6)), int(remote.rsplit(":", 1)[1], 16))
        except Exception:
            continue
        pids = inode_pid.get(inode)
        if not pids:
            per_proc[(None, uid)]["unresolved"] += 1
            per_proc[(None, uid)]["rows"].append((ts, proto, l, r, st))
            continue
        for pid in pids:
            e = per_proc[(pid, uid)]
            e["rows"].append((ts, proto, l, r, st))
            e["ts"].add(ts)

    print(f"### capture {d}/conns.txt: {sum(len(e['rows']) for e in per_proc.values())} non-LISTEN entries")
    for (pid, uid), e in sorted(per_proc.items(), key=lambda kv: -len(kv[1]["rows"])):
        rows = e["rows"]
        hw = [x for x in rows if is_huawei(x[3][0])]
        if not rows or (not hw and not show_all):
            continue
        name = names.get(pid, "?") if pid else "?"
        user = users.get(pid, "?") if pid else "?"
        dests = defaultdict(int)
        for _, proto, _, r, st in rows:
            dests[(str(r[0]), r[1], STATES.get(st, st))] += 1
        print(f"\npid={pid} uid={uid} ({name}, user {user})  {len(rows)} entries, {len(e['ts'])} distinct seconds"
              f"{', ' + str(len(hw)) + ' TO HUAWEI' if hw else ''}")
        for (ip, port, st), n in sorted(dests.items(), key=lambda kv: -kv[1])[:8]:
            flag = "  <== HUAWEI" if is_huawei(ipaddress.ip_address(ip)) else ""
            print(f"    {n:5d}x -> [{ip}]:{port} {st}{flag}")
        ts = sorted(e["ts"])
        print(f"    seen {ts[0]}..{ts[-1]}")

    unresolved = {k: v for k, v in per_proc.items() if k[0] is None}
    if unresolved:
        print("\n### entries whose inode was never seen in a uid-1000 fd snapshot")
        for (_, uid), e in unresolved.items():
            dests = defaultdict(int)
            for _, proto, _, r, st in e["rows"]:
                dests[(str(r[0]), r[1], STATES.get(st, st))] += 1
            for (ip, port, st), n in sorted(dests.items(), key=lambda kv: -kv[1])[:6]:
                flag = "  <== HUAWEI" if is_huawei(ipaddress.ip_address(ip)) else ""
                print(f"    uid={uid} {n}x -> [{ip}]:{port} {st}{flag}")


if __name__ == "__main__":
    main()
