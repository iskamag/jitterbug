# Debloat record — Huawei/HMS removal on MRX-AL09 (2026-09-17)

Applied from the per-boot root channel (`tools/su`, daemon started by
`tools/rootshell.sh`). Groups and per-package rationale: **`PLAN.md`**.

## What was done

| | |
|---|---|
| primitive | `pm disable-user --user <u>` (per user 0 = Владелец, 10 = Fair) |
| scope | **68 packages** = 47 telemetry/HMS (A+B) + 21 aggressive plumbing (C) |
| applied | 136 package/user pairs, **0 FAIL, 0 SKIP** |
| **correction** | **3 of the 68 were re-enabled** the same evening (see below) → **65 stay disabled** (86 of 90 pairs, for users 0 and 10); **+1 addendum package** (`com.yandex.zenkitpartnerconfig`) → **66** |
| total disabled on device (measured) | **user 0: 66** = 65 of ours + `com.huawei.securitypluginbase` (disabled before this operation); **user 10: 68** = 65 of ours + `com.android.stk`, `com.huawei.associateassistant`, `com.huawei.kidsmode` (all pre-existing). `com.huawei.powergenie` never sticks for user 0, `com.yandex.zenkitpartnerconfig` is not installed for user 10, `com.huawei.parentcontrol` cannot be disabled at all |
| reboot needed | none; disabled state is in `/data/system/users/*/package-restrictions.xml` and survives reboots |
| data touched | none — no APK, no app data, no uninstall |

### 2026-09-18 00:2x local: destination block for this boot (no reboot)

Applied with `huawei-block.sh apply` — the user asked for a packet-level block
rather than a reboot. What it does:

| | |
|---|---|
| ipv4 | `iptables -I OUTPUT 1 -d <cidr> -j REJECT` + `-I INPUT 1 -s <cidr> -j DROP` for `159.138.0.0/16` (Huawei Cloud Moscow — the push server) and `80.158.20.0/24` (T-Systems Leipzig — the nearby/hwddmp endpoint) |
| ipv6 | same for `2407:c080::/32` (Huawei Cloud — the range in the firewall log) |
| placement | chain position 1, ahead of EMUI's own `ip_block_list` / `uid_trust_list` / `ip_trust_list` / `network_reject_list` / `huawei_firewall`, so a Huawei-trusted destination cannot override. (Those lists were empty here, so nothing was being exempted by default.) |
| lifetime | **this boot only** — nothing persisted; a reboot clears it, and `huawei-block.sh flush` removes it now |
| wider list | `WIDER_V4` / `WIDER_V6` in the script, uncomment when a capture shows a client moving outside the default three |

Evidence (in the run log):

* negative control: `ping 159.138.204.113` → `0 packets transmitted, 0 received, +1 errors`;
  positive control: `ping 1.1.1.1` → `1 received, 0% packet loss, 65 ms` — targeted, not blanket.
* the rule counter proves the block is *matching traffic*, not just sitting there:
  `159.138.0.0/16` went 13 → 15 pkts in 45 s while the restarted push client retried.
* the live session is gone: killed the push client (pid 20488), it came back as
  23763 and could not re-establish; afterwards the device's whole outbound socket
  list was `conversations` (XMPP, ESTAB) plus one orphaned `FIN-WAIT-1` to the
  blocked address, and connectivity was otherwise normal.

Note for future probing: this build has **no `nc`, `curl`, `wget` or `openssl`** —
reachability must be tested with `ping` plus the iptables packet counters.

### 2026-09-18 ~00:15 local: is it still phoning home? Yes — measured, and why

A firewall log showed uid 1000 talking to Huawei Cloud (AS55990) every ~2 s.
uid 1000 is `android.uid.system`, shared by dozens of packages, so the firewall
cannot attribute it. Root can: sample `ss -tnp` (through `adb shell`, because
`ss` drops the `users:((pid))` column when stdout is not a tty) and read the
owner out of the kernel. That is `debloat/host-sswatch.sh` +
`analyze-sswatch.py`; captures in `logs/sswatch-*.txt`.

**What was live** (4 min of continuous sampling, 3 processes holding outbound
sockets in total):

| process | peer | what it is |
|---|---|---|
| `com.huawei.android.pushagent` (`.PushService`, pid 20488, **disabled**) | `159.138.204.113:5223` **ESTAB, continuous 910 samples / 106 s** | `ecs-159-138-204-113.compute.hwclouds-dns.com`, **AS136907 HUAWEI CLOUDS, Moscow**. Port 5223 is Huawei's push port — a standing channel, not a burst. |
| `com.huawei.nearby` (pid 20523, **disabled**) | `80.158.20.104:443` ESTAB 1125 samples, ended 00:13:49 | `open-telekom-cloud.com`, AS6878 T-Systems, Leipzig — that process was running **hwddmp's** services (`DeviceMonitorService`, `TrustEngineService`, `DataBusService`) plus `NearbyService`, i.e. the "Huawei data management services" the firewall listed under uid 1000 |
| `eu.siacs.conversations` | `81.85.74.29:5222` | the user's own XMPP client |

Both Huawei sockets were on the **direct wlan address** (`192.168.1.126`), and at
the time of the second check there was **no `tun0`** — the NetGuard VPN was down
(process alive), so the firewall was neither filtering nor logging. That is the
answer to "why did it stop right before the scan": it did not evade anything; a
2 s-cadence burst cannot hide from a 3-sample/s capture, and what is actually
there is a *standing* session that outlives the burst.

**Why the debloat did not stop them:** disabling a package does not kill its
process. ActivityManager keeps the service records and restarts them (measured
<5 s, three times). `am force-stop` is a no-op for a package sharing uid 1000,
and `am stop-service` is **refused** for a disabled package's services
(`drop-services.sh`: FAIL for every component, including
`com.huawei.nearby/.NearbyService`). So the options that actually end it:

1. **Reboot** — PMS then does not register the components and they never start.
   Costs the per-boot root stack (`tools/rootshell.sh` to bring it back).
2. **`pm uninstall --user 0 <pkg>`** for `com.huawei.android.pushagent`,
   `com.huawei.nearby`, `com.huawei.hiview`, `com.huawei.iaware` — the process
   cannot restart at all, the socket dies immediately, no reboot. Reversible:
   `pm install-existing --user 0 <pkg>` (then `pm disable-user --user 0` again to
   get back to the disabled state). Works from a plain `adb shell`, no root.
3. **Block the destinations** (`iptables -I OUTPUT -d 159.138.0.0/16 -j REJECT`,
   Huawei Cloud ranges) — no package change, but it is lost on reboot and needs
   root per boot.

Note also: only **9** of the uid-1000 packages are both enabled and hold
INTERNET (`uid1000-candidates-report.txt`); everything else on the firewall's
uid-1000 list — airlink, DEF, gamekit, the fusion-search pair, nb.service,
wifiprobe, instantshare, synergy, dmsdp, magazine, hiview/iaware/lbs/nearby/
pushagent/systemmanager (the last group disabled by this operation) — cannot run
at all. So of the names the firewall shows, only the residuals above can be the
sender.

### Addendum 2026-09-17 (asked for by name): Yandex + parental control

`targets-addendum.txt`, `logs/apply-20260917T184959Z.log`,
`parentcontrol-neuter.sh`.

* `com.yandex.zenkitpartnerconfig` (label `ZenkitPartnerConfig`, `/preload/app/zenkit`,
  **5.7 KB**, zero permissions, never launched) — **disabled** on both users.
* `com.huawei.parentcontrol` — **the firmware will not let it go** (its own label is
  **"Digital Balance"**: EMUI's screen-time/wellbeing app with parental controls
  inside, which is *why* it is protected — a child must not be able to switch off
  screen-time limits). `pm disable-user`
  → *"not allowed to disable this package"*, `pm uninstall --user N` → *"not allowed
  to uninstall"*, `pm hide` / `pm suspend` → silent no-ops. APK deletion is closed as
  well: `ro.boot.veritymode=green`, bootloader locked, `/system` *is* the root
  dm-verity device (system-as-root) and the product partitions are read-only erofs
  behind dm-verity — writing there breaks verified boot with no repair path on a
  locked bootloader. Verified first that no parental session is active (no
  device/profile owners) so nothing can be stranded by touching it.
  **Applied instead:** `appops RUN_IN_BACKGROUND` + `RUN_ANY_IN_BACKGROUND` =
  **deny**, plus force-stop (`parentcontrol-neuter.sh`) — it cannot run in the
  background and is not running. Revert with
  `cmd appops set com.huawei.parentcontrol RUN_IN_BACKGROUND allow`.
  `com.huawei.kidsmode` (Kids Mode, the separate child launcher) was left as found.

### Correction 2026-09-17: three group-C entries were UI, not plumbing

Reading the pulled APKs (`aapt2 dump badging`/`xmltree`, the same SDK chain the
manager app is built with) showed my group-C description of them was wrong:

| package | label | what it really is |
|---|---|---|
| `com.huawei.hwdockbar` | **"Multi-Window"** | `DockMainService` / `MultiTaskActivity` / `FloatWindowBootsActivity`, needs `SET_WINDOW_MODE`, `MANAGE_ACTIVITY_STACKS`, `READ_FRAME_BUFFER`, `MANAGE_FOLD_SCREEN` — the edge-swipe **multi-window dock** (split screen + floating windows), working in **ordinary tablet mode**. I had described it as the "PC-mode dock"; it is not. |
| `com.huawei.desktop.systemui` | "HwSystemUI" | desktop-mode SystemUI (`STATUS_BAR_SERVICE`, `INJECT_EVENTS`) |
| `com.huawei.desktop.explorer` | "My files" | desktop-mode file window (`PC_MANAGER_API`) |

All three are launcher/UI layers with no telemetry path, and group C was approved
as "PC-assistant / mirroring" — which these are not. They are **re-enabled on
both users** (`targets-correction.txt`, `logs/restore-*.log`), and group D in
`PLAN.md` records the correction. PC mode proper (`desktop.systemui` +
`desktop.explorer`) can still go if wanted — but not `hwdockbar`.

Logs and state: `logs/apply-*.log` (pre/post state, per-package result, health
check), `state/disabled-*.txt` (exactly what this operation disabled, per user).
The rollout was staged: A+B at 23:23, then C at 23:38 — see `logs/`.

Health after the change (in the run logs): `com.android.systemui`,
`com.huawei.android.launcher` and `com.matepad.sumgr` all alive, the crash
buffer empty of any `FATAL EXCEPTION`/`ANR` from a disabled package, and kernel
thermal control untouched (`android.hardware.thermal@2.0-service-hisi`,
`thermal_hotplug`, `/sys/class/thermal/cooling_device*`). The one userspace
thermal *policy* that went away is the Optimizer's (`com.huawei.systemmanager`,
group C) — kernel/hardware throttling is unaffected.

## Residuals (measured, not assumed)

1. **`com.huawei.powergenie` re-enables itself.** It is the only package the
   disable did not stick on: `dumpsys package` shows `enabled=1` (ENABLED) for
   user 0 again about a minute after a successful `pm disable-user`
   (`enabled=3` for user 10 holds). It is PowerGenie/HAware, Huawei's
   background-app *freezer* — not a network or telemetry client, so nothing
   phones home. Group C, i.e. a convenience removal, not a privacy one.
   Force it (reversible): `pm uninstall --user 0 com.huawei.powergenie`,
   restore with `pm install-existing --user 0 com.huawei.powergenie`.
2. **Four persistent services keep running until the next reboot:**
   `com.huawei.hiview`, `com.huawei.iaware`, `com.huawei.nearby`,
   `com.huawei.android.pushagent.PushService`. They run under the shared system
   uid, so `am force-stop` is a no-op for them, and ActivityManager holds their
   service records for this boot and restarts them <5 s after any kill
   (measured, three times). After a reboot PMS will not start them, because the
   components are disabled. `hiview`'s uploaders (`android.chr`,
   `hiviewtunnel`, `hwid`) are *also* disabled and dead, so the collector has no
   path off the device; `pushagent` is itself a network client, so if you want
   its connection closed **now**, `pm uninstall --user 0 com.huawei.android.pushagent`
   (restore: `pm install-existing --user 0` + `pm disable-user --user 0`).
3. **Not addressable with `pm`:** the kernel/vendor logging side — `hwlog_wq`,
   `HW_KERNEL_STP_M/S`, `vendor.huawei.hardware.hwhiview@1.1-service`. Device-
   local ring buffers; the network paths were the packages removed above.

## Safety / verification (measured 2026-09-17, after the change)

Checked on the live device, not assumed:

| check | result |
|---|---|
| reversible **without root** (uid 2000, i.e. plain `adb shell`) | yes — round-tripped `pm enable`/`pm disable-user` on one package, both rc=0; state restored |
| on-device recovery path | `debloat.sh` + `debloat-targets.txt` (all 68) are on the device in `/data/local/tmp`, runnable as shell — so recovery survives the reboot that kills `sud` |
| boot-critical components kept | SystemUI, launcher, resolver, WebView provider, PackageInstaller, telephony/providers — see the "kept" table in `PLAN.md` |
| any enabled app broken by a removed shared library | no — `logcat` has **0** matches for `requires unavailable shared library` |
| any app crashing because of the change | no — **0** `FATAL EXCEPTION` / `ClassNotFoundException`; crash buffer empty |
| kernel/hardware thermal control | intact (`android.hardware.thermal@2.0-service-hisi`, `thermal_hotplug`, `/sys/class/thermal/cooling_device*`) |
| data loss | none — no uninstall, no `pm clear`, no `/system` write, no app data touched; disabled state is a per-user flag in `package-restrictions.xml` |

Rough edges, all measured, all this-boot-only:

* Enabled framework code keeps **retrying binder binds to the disabled
  components**: `com.huawei.systemserver`'s SoftBus adapter
  (`retryBindDevMonitor`), `com.huawei.hwddmp`, `com.huawei.nearby`'s auth
  service lookups (ActivityManager `Unable to start service ... not found`),
  and — since 23:43 — a vendor `uniperf`/`iawareperf` HAL loop
  (`do UniPerfEvent failed, cmdId=13261`, when `iaware`'s restarted process
  callers are gone). Log spam and a little CPU, no failures; all of it stops
  after a reboot because the retrying components then have nothing to retry.
* So: **the reboot is the one step not yet exercised.** Nothing disabled is
  boot-critical and the recovery command works without root, but the *first*
  boot after this change is where the disabled set is first honoured by
  PackageManagerService. If anything looks wrong:
  `adb shell 'sh /data/local/tmp/debloat.sh restore /data/local/tmp/debloat-targets.txt'`
  (or `debloat/apply.sh --restore` from here, which needs the root channel up).
* Trade-offs accepted on purpose: no EMUI/security OTA, no network-location
  fallback (GNSS only), no Huawei push / Find-My-Device, no wallet/pay, no
  cast / PC-mode / cross-device, and Huawei apps that used HMS show degraded
  (login/sync-broken) UI — the offline ones (Contacts, Gallery, Calendar, Notes,
  camera, Files) work locally.

## Reverting

```
debloat/apply.sh --restore      # pm enable for every pair in state/disabled-*.txt
debloat/apply.sh --restore-all  # pm enable for everything in targets.txt
```
Both go through the root channel, so they need `tools/rootshell.sh` up for this
boot (or `su` already running). A single package by hand:
`adb shell '/data/local/tmp/su -c "pm enable --user 0 com.huawei.browser"'`.

## Tooling

| file | what it is |
|---|---|
| `targets.txt` | `group package` list; A/B/C as in `PLAN.md`. `TARGETS=<file>` stages a rollout |
| `device-debloat.sh` | on-device worker: `apply` / `restore` / `reap`, per user, then a single-pass reap |
| `apply.sh` | host driver: push, run, log, record state (`--reap`, `--restore`, `--restore-all`) |
| `chan-trim.sh` | keep exactly one `r.sh` channel loop (22 had accumulated) |
| `cleanup.sh` | kill runaway `debloat.sh` reap loops and spinning `tr` readers |
| `PLAN.md` | per-package rationale + what to replace each removed app with |
| `packages-*.txt` | the pre-change inventory (`pm list packages` variants) |

### Do-not (cost real CPU time on this device)
**Never read `/proc/<pid>/cmdline` in a loop.** Measured 2026-09-17: if the pid
dies between the directory scan and the read, the reader never gets EOF and
spins at 100% CPU for ever. Two orphaned channel scripts from an earlier session
were each doing `tr '\0' ' ' < /proc/<pid>/cmdline` and had been pegging two of
the eight cores (load average ~50) for hours; the first version of the reap loop
here hit the same trap. Use one `ps -A -o PID,ARGS` pass and match in `awk`
(that is what `reap_all` does) — `ps` reads a bounded buffer per file and is
immune. The cleanup recovered ~2 cores (idle 437% → 746% of 800%).

**Never `pkill -f <pattern>` when the pattern appears in your own command line.**
It bit this session twice — on the device (`pkill -f device-sswatch` killed the
very shell that was starting the watcher) and on the host (`pkill -f
host-sswatch` SigTERM'd the calling shell, exit 143). Put a bracket in the
pattern (`pkill -f 'host-sswatc[h]'`): the regex still matches the target's
command line but no longer matches the literal text in your own.

**`ss -tnp` drops the owning process when stdout is not a tty** (112-char
truncation, `COLUMNS` is ignored), so on-device watchers silently capture
addresses with no attribution. Run it through `adb shell` (a pty) —
`host-sswatch.sh` — or resolve socket inodes against `/proc/<pid>/fd`
(`device-sockets.sh` + `analyze-sockets.py`). And this build has no `nc`,
`curl`, `wget` or `openssl`: reachability tests use `ping` plus the iptables
packet counters.
