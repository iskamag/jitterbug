# JITterbug

Semi-untethered Root and debloat tooling for the Huawei MatePad Pro MRX-AL09 (Kirin 990,
EMUI 11.0.0.205, Android 10, kernel 4.14.116, Mali bifrost r18p0).

The device has a locked bootloader and no root. Root is obtained from an `adb`
shell (uid 2000, `u:r:shell:s0`) using two known CVEs; a `su` is then kept
alive for the rest of the boot.

<img src="assets/logo.svg" alt="JITterbug" width="320">

Obvious disclaimer: This is made for a very specific, extremely outdated Linux/EMUI version, using long-patched exploits.
The program hardcodes specific memory offsets, so good luck reproducing this on any other device or firmware.

## Tree

| Path | |
|---|---|
| `su/` | Permission-based `su`: daemon, client, manager CLI. |
| `manager/` | Android app that answers permission prompts. |
| `channel/` | Bring-up: SELinux switch plus the uid-0 command channel. |
| `exploit/` | CVE-2022-38181: Mali r18p0 JIT UAF, kernel physical read/write. |
| `debloat/` | Huawei/HMS package removal and destination blocking. |
| `tools/` | Host harnesses: `devlock.sh`, `pocrun.sh`. |

## The chain

1. `exploit/mali_boot.c` races a Mali r18p0 JIT UAF and reclaims the freed
   pages as page tables. That gives content-verified physical read/write.
   Everything after this uses it.

2. The same primitive switches SELinux to permissive by clearing
   `policydb.permissive_map` and the AVC cache. This is `mali_boot switch`.
   It writes kernel memory only; there is no policy reload.

3. `channel/` installs CVE-2022-22706: a cold `GetBoolProperty` call in
   `/system/lib64/libbase.so` is redirected to a payload that runs a command
   loop as uid 0 in `u:r:installd:s0`. That is the only process on the device
   with a full capability set.

4. `su/` is a normal su from there: a unix socket, `SO_PEERCRED` for identity,
   per-uid allow/deny/ask policies, and a pty pump so the calling shell keeps
   job control.

### Why su is a daemon

A setuid-root binary gets euid 0 and no capabilities on this device.
`securebits` is `0x2f` with `SECURE_NOROOT` set and locked, so
`cap_bprm_set_creds()` never grants capabilities to a setuid exec, and
`CapBnd` is `0xc0` from the firmware's non-root `adbd`. Both are measured on
the device. The privilege therefore has to stay in the process that already
has it, so `sud` is started from the channel and forks each shell.

See `su/README.md` for the protocol and the permission model.

## Build

A cross toolchain is required for the device binaries, and an Android SDK for
the manager app.

```
NDK=<android-ndk> MUSL=<aarch64-musl> make su
NDK=<android-ndk> make channel
NDK=<android-ndk> make exploit
make test
```

`make test` builds and runs the host tests for the policy parser and the wire
framing. Binaries are not committed.

## Run

```
export SER=<serial>                  # adb devices
NDK=<android-ndk> channel/stage.sh   # once: push pcwrite2 and r.sh
channel/rootshell.sh                 # permissive, then the channel
su/install.sh                        # build, push, start sud, verify
```

`rootshell.sh` runs `mali_boot switch` through `tools/pocrun.sh`. If the run
does not report `MAC GRANTED` it warns and continues.

Paths and packages are runtime configuration, see `su/config.h`. `SU_DIR`
defaults to `/data/local/tmp`, `SU_MANAGER_PKG` to `com.matepad.sumgr`.

## License

MIT, see `LICENSE`.
