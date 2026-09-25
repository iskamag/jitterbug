# mrx-al09-root

Rooting a **Huawei MatePad Pro (MRX-AL09, Kirin 990, EMUI 11.0.0.205,
Android 10, kernel 4.14.116, Mali r18p0)** from an `adb` shell, and the tooling
that came out of it. It started as a way to get game saves off a
locked-bootloader tablet; it ended with a real `su`.

Everything here is device-specific and per-boot: the SELinux switch and the
`su` daemon live in kernel/device state that a reboot clears, so the bring-up
is re-run each boot. The exploit offsets are the ones measured on this
firmware.

> **Warning.** These are working privilege-escalation exploits against a
> specific device. Run them only on hardware you own.

## The layers

| Dir | What it is |
|---|---|
| `su/` | A permission-based `su`: a daemon (`sud`) that holds the privilege, a client you run, a manager CLI, and an Android prompt app. |
| `manager/` | The prompt app (`com.matepad.sumgr`): pending requests, per-app policy, Allow / 10 minutes / Deny. |
| `channel/` | The per-boot bring-up: SELinux permissive switch + a uid-0 command channel (a `libbase.so` page-cache hook). |
| `exploit/` | **CVE-2022-38181** (Mali r18p0 JIT UAF) — the kernel physical read/write. Reliable and repeatable on this firmware. |
| `debloat/` | First use of the root: removing Huawei/HMS telemetry and having the removal stick. |
| `tools/` | Host-side harnesses: a device lock (`devlock.sh`) and the PoC runner (`pocrun.sh`). |

## How it works

Four primitives, brought up in this order each boot; each is documented where
it lives.

1. **A kernel physical R/W window** — **CVE-2022-38181**: a Mali r18p0 JIT UAF
   reclaimed into page tables, giving content-verified physical read/write.
   → `exploit/`, `exploit/MALI-BOOT-REWRITE.md`.
2. **SELinux permissive** — a data-only write to the policy DB's
   `permissive_map`, plus AVC eviction (a cache *hit* copies the old decision).
   Kernel memory only, no policy reload. This is the `switch` mode of
   `mali_boot`; the channel needs it to have full access. → `exploit/`.
3. **A uid-0 channel** — **CVE-2022-22706**: a cold `GetBoolProperty` call in
   `/system/lib64/libbase.so` is redirected into a payload that spawns a shell
   in `u:r:installd:s0`. It is the only process on the device with a full
   capability set (`CapEff 0000007fffffffff`), which is why the `su` daemon has
   to be started from it. → `channel/`, `channel/REPORT-installd-channel.md`.
4. **`su`** — everything after that is ordinary Unix: a socket, `SO_PEERCRED`,
   per-uid policies, and a pts pump so the caller keeps job control.

### Why `su` is a daemon, not a setuid binary

A setuid binary cannot be a real `su` here. Two measured, kernel-level facts
(SELinux is not the obstacle — the switch does not touch either):

* `securebits = 0x2f` with `SECURE_NOROOT` **set and locked**: a setuid-root
  binary comes out `Uid: 2000 0 0 0` with `CapPrm = CapEff = 0`.
* `CapBnd = 0xc0` (inherited from this firmware's non-root `adbd`), and the
  bounding set is a hard ceiling.

So the privilege lives in the channel, and `sud` — started by it — forks each
root shell with the caller's ttys. Full detail in `su/README.md`.

## Build

```
make su        # sud, su, sumgr   (needs NDK=<path> or MUSL=<path>)
make channel   # pcwrite2         (needs NDK=<path>)
make exploit   # mali_boot        (needs NDK=<path>)
make test      # host tests for the su subsystem
```

Binaries are never committed. `su/build.sh` and `manager/build.sh` take the
toolchain from the environment (`CC`, `SDK_DIR`).

## Run

```
export SER=<your-device-serial>          # adb devices
NDK=<android-ndk> channel/stage.sh       # once: push pcwrite2 + r.sh to the device
channel/rootshell.sh                     # 1. permissive + uid-0 channel
su/install.sh                            # 2. build, push, start sud, verify
adb shell /data/local/tmp/su -c 'id'     #    uid=0(root), CapEff full
```

`rootshell.sh` runs `mali_boot switch` (through `tools/pocrun.sh`) first, so a
lost race there is possible; it warns and continues if the switch did not
report `MAC GRANTED`. `su/README.md`, `exploit/MALI-BOOT-REWRITE.md` and
`channel/REPORT-installd-channel.md` carry the detail.

## Layout note

The `su` stack talks to the daemon through `/data/local/tmp/su.sock` by
default; `SU_DIR`, `SU_MANAGER_PKG` and `SU_SHELL_PKG` are environment
overrides (`su/config.h`), so the same binaries work for another install.

## License

MIT — see `LICENSE`. The CVE identifiers belong to their respective advisories.
