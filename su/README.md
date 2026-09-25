# su — permission-based root for the MatePad MRX-AL09

A working `su`: a daemon that holds the privilege, a client you run, a manager
app that prompts, and a CLI to manage the policies.  No setuid bit, no
exploitation at use time — the per-boot bring-up is `channel/rootshell.sh` (MAC
switch + channel) and then `su/install.sh`.

```
su                 # interactive root shell (bash if the device has one)
su -c 'id'         # one command
su -s /path/sh     # pick the shell
sumgr list|pending|log|allow|deny|ask <uid> [minutes]|stop
```

## Why a daemon and not a setuid binary

A setuid binary cannot be a real `su` on this device.  Two measured, kernel
level facts (not SELinux — the permissive switch does not touch either):

1. **`securebits = 0x2f`, with `SECURE_NOROOT` set *and locked*.**  So
   `cap_bprm_set_creds()` skips the root-grants-caps block: a setuid-root
   binary run from `adb shell` comes out `Uid: 2000 0 0 0` with
   `CapPrm = CapEff = 0`.  `setgid(0)` fails with `EPERM`; no
   `CAP_DAC_OVERRIDE`, so `/data/data/<app>` stays unreadable.
2. **`CapBnd = 0xc0` ({SETUID, SETGID}, inherited from this firmware's
   non-root `adbd`), and the bounding set is a hard ceiling** — the kernel
   computes `pP' = (cap_bset | cap_inheritable)` for setid execs and ANDs file
   capabilities with `cap_bset` too.

The only process that has a full capability set (`CapEff 0000007fffffffff`) is
the **installd channel** built by `channel/rootshell.sh`.  So that is where the
privilege lives: `sud` is started by the channel, inherits the full set, and
forks each root shell from there.  (`su` still has a local fallback when it is
invoked with a setuid bit — `SETUID=1 su/install.sh` — but it can only be
a crippled root, and it prints exactly why.)

This is also why Magisk cannot simply be dropped in: its install path *is*
boot-image patching (the bootloader here is locked), `magisk --daemon` refuses
to start unless `/proc/self/exe` lives on Magisk's own tmpfs created by
`magiskinit`, and its su path expects its patched sepolicy (`u:r:magisk:s0`,
`magisk_exec`, `magisk_client`) — none of which can exist here (loading a
policy is MAC-denied from this position).  What is left is the mechanism
below, which is what Magisk's su is anyway: a client, a socket, and a daemon
that forks with the caller's ttys.

## Per boot

Nothing here persists: the MAC switch, the channel, the daemon and the
policies' *reachability* are per boot.

```
channel/rootshell.sh      # 1. MAC switch (~80 s, race lottery) + channel
su/install.sh             # 2. build, push, start sud, verify, link into Termux
```

`install.sh` also kills duplicate channels and stale daemons (a duplicate
`r.sh` runs every command once per loop) and verifies the whole thing from
uid 2000: `uid=0(root)` with `CapEff 0000007fffffffff`.

## The permission model

Per uid, in `SU_POLICIES`: `deny` / `allow` / `ask`, with an optional expiry
(Magisk's numbering, `deny=0 allow=1 ask=2`).  A uid with no policy is `ask`:
the daemon queues the request, starts the manager app's prompt, and waits
(120 s) for a decision; the decision is written back as a policy.  Root never
asks.  All decisions are logged to `SU_LOG` with the deciding uid.

```
/data/local/tmp/su.policies   # "uid policy until" -- human editable, 0660 root:shell
/data/local/tmp/su.pending    # requests waiting for an answer
/data/local/tmp/sud.log       # every decision, with who made it
/data/local/tmp/su.sock       # 0666; authorization is SO_PEERCRED, not the path
/data/local/tmp/sud.pid
```

**Who may manage policies:** uid 0, the shell uid (2000), the manager app
(`com.matepad.sumgr`), and Termux (`com.termux`) — the last two resolved by
package name in `/data/system/packages.list`, so the uid is the real identity
and cannot be spoofed by another app.  The shell uid is included because it
already reaches root through the channel each boot, so this grants it nothing
new.  Everyone else can *ask* for root, never grant it.  Caveat worth stating
plainly: anything running as the shell uid (adb, or a shell in Termux) can
edit the policy file directly.

## The manager app

`com.matepad.sumgr` (`../manager/`, built with `manager/build.sh` against an
Android SDK): pending requests on top, then every installed app with
its current policy; tapping a policy button cycles allow → ask → deny.  The
prompt (`RequestActivity`, started by the daemon with `am start`) offers
Allow / Allow for 10 minutes / Deny.

## Design notes

* **The shell runs on its own pty**, and `sud` pumps the caller's stdio through
  it (`open("/dev/ptmx")` + `TIOCSPTLCK` to unlock the slave — devpts returns
  `EIO` otherwise — then `setsid()` + `TIOCSCTTY`).  The caller's terminal is
  put in raw mode for the duration and restored afterwards.  Stealing the
  caller's controlling terminal would be simpler but leaves the calling shell
  unable to `tcsetpgrp()` once `su` exits; this is Magisk's design
  (`native/src/core/su/pts.rs`).
* **A fast command must not lose its output**: the pump drains the pty after
  reaping the child (`su -c true` exits before its last bytes are read).
* Flags kept for compatibility: `--mount-master` (this build always runs in the
  global mount namespace) and `-Z CONTEXT` (accepted, warns: the policy has no
  other su domain to transition to).

## Building

```
./build.sh                   # sud, su, sumgr (musl static, aarch64)
../manager/build.sh           # the app (aapt2/d8/apksigner, no gradle)
./install.sh                  # deploy + start + verify
./build.sh test               # host tests: policy parser + wire framing
```

Paths and packages are runtime configuration (`config.h`): `SU_DIR`,
`SU_MANAGER_PKG` and `SU_SHELL_PKG` override the compiled defaults, so the
same binaries work for another install.
