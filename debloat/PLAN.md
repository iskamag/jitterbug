# Debloat plan — MRX-AL09 (EMUI 11.0.0.205, Android 10)

**Method:** `pm disable-user --user <u>` for every package in `targets.txt`, applied
per user (0 = Владелец, 10 = Fair) through the root channel (`tools/su`).
`disable-user` is the reversible primitive: the app is stopped, removed from the
launcher, and cannot be started or bound to by anything, but its APK and data stay
on disk. **No reboot, no data touched.** `debloat/apply.sh --restore` flips exactly
the pairs recorded in `state/disabled-*.txt` back (`pm enable`).

Rollout: groups **A+B** first, health check, then **C** — so a bad package in the
aggressive set is attributable.

**APPLIED 2026-09-17** — 68 packages, 136 package/user pairs, 0 failures; outcome,
residuals and revert steps in `README.md`. **Correction the same evening: three
of the 68 were UI layers, not plumbing, and were re-enabled** (`hwdockbar`,
`desktop.systemui`, `desktop.explorer` — see group D) → **65 remain disabled**.

Pre-existing state (left as found): `com.huawei.securitypluginbase` (user 0) and
`com.android.stk`, `com.huawei.associateassistant`, `com.huawei.kidsmode`
(user 10) were already disabled before this operation (not ours; `state/` only
records what we disabled).

## A — telemetry, profiling, data egress, ads

| package | what it is | replacement |
|---|---|---|
| `com.huawei.android.chr` | CHR: crash/usage reporting uploader to Huawei | none needed |
| `com.huawei.hiview` | HiView: on-device metric collection + upload | none needed |
| `com.huawei.hiviewtunnel` | transport for HiView/analytics payloads | none needed |
| `com.huawei.nb.service` | behavior/usage data store feeding HiAI + HiBoard | none needed |
| `com.huawei.iaware` | app-usage profiling + scheduling hints | none (kernel perf HAL stays) |
| `com.huawei.def` | "device experience feedback" telemetry | none needed |
| `com.huawei.phoneservice` | HiCare: remote diagnostics, promo, telemetry | none needed |
| `com.huawei.hwdetectrepair` | hardware scan that reports off-device | none needed |
| `com.huawei.tips` / `com.huawei.tipsove` | tips/commerce engine + tracking | none needed |
| `com.huawei.mmitest` | factory test menus (log upload paths) | none needed |
| `com.huawei.android.projectmenu` | hidden engineering menu | none needed |
| `com.huawei.android.hsf` | Huawei Service Framework (the bus HiCare/HiCloud use) | none needed |
| `com.huawei.numberidentity` | sends phone numbers off-device for lookup | none (no SIM in this tablet) |
| `com.huawei.wifiprobqeservice` | uploads Wi-Fi scan/probe results | none needed |
| `com.huawei.hicard` | HiCard lock-screen offers/ads | none needed |
| `com.huawei.magazine` | lock-screen magazine downloads | static wallpaper |
| `com.huawei.intelligent` | HiBoard: news feed + usage-based recommendations | none needed |
| `com.huawei.hifolder` | home-screen "recommended apps" folder (paid placement) | none needed |
| `com.huawei.autoinstallapkfrommcc` | silently installs carrier apps by MCC | none needed |
| `com.huawei.hwstartupguide` | setup wizard / tips | none needed |
| `com.huawei.android.hwupgradeguide` | "upgrade guide" promo prompts | none needed |

## B — HMS ecosystem (online services)

| package | what it is | replacement |
|---|---|---|
| `com.huawei.browser` | **Huawei Browser** (the one you named) | Firefox, Cromite — already installed |
| `com.huawei.browserhomepage` | its news/feed homepage | — |
| `com.huawei.appmarket` | AppGallery store | **Aurora Store** (installed) |
| `com.huawei.hwid` | HMS Core / Huawei ID — the account + data pipeline the rest ride on | none; sign-in to Huawei services stops |
| `com.huawei.hicloud` | Huawei Cloud client | Nextcloud/Syncthing (not installed) |
| `com.huawei.hidisk` | Huawei Drive | Syncthing/Nextcloud |
| `com.huawei.assetsync` + `assetsyncservice` | cloud sync of app/Wi-Fi/bookmark assets | DAVx5 if you want calendar/contacts sync |
| `com.huawei.contacts.sync` | contacts cloud sync | DAVx5 / local export |
| `com.huawei.android.pushagent` | Huawei push (permanent connection to Huawei) | none — HMS apps lose push; XMPP/Jitsi/NetGuard unaffected |
| `com.huawei.search` (HiSearch) | global search + remote suggestions | Firefox/Cromite address bar |
| `com.huawei.hwsearch` | search results provider | — |
| `com.huawei.searchservice` | search indexer/uploader | — |
| `com.huawei.hiassistantoversea` | Celia voice assistant | none |
| `com.huawei.hiai` | HiAI engine (cloud AI offload) | none |
| `com.huawei.scanner` | HiVision / AI Lens: uploads images to Huawei for recognition | none; Simple Code Scanner for QR |
| `com.huawei.fastapp` | Quick Apps (mini-programs) runtime | none |
| `com.huawei.himovie.overseas` | HiMovie store | NewPipe, VLC — installed |
| `com.huawei.easygo` | EasyGo content service | none |
| `com.huawei.hwvoipservice` | MeeTime calls | Jitsi — installed |
| `com.huawei.gameassistant` + `game.kitserver` | Game Center / in-game overlay service | none |
| `com.huawei.android.instantonline` | "instant online" service discovery | none |
| `com.huawei.hwpanpayservice` | Huawei Pay | none |
| `com.huawei.hwblockchain` | wallet/blockchain key store | none |

## C — aggressive: plumbing, stores, cross-device

| package | what it is | replacement |
|---|---|---|
| `com.huawei.android.hwouc` | OTA updater | none — **deliberate: no forced EMUI updates. You also stop getting security patches; update manually via HiSuite or skip.** |
| `com.huawei.lbs` | network location provider | none installed. GNSS (`/dev/hwgnss`) still works; apps lose the Wi-Fi-based location fallback (microG's NLP is the only real substitute) |
| `com.huawei.systemmanager` | "Optimizer": battery/cleanup/permission glue, force-kills apps, userspace thermal policy | AOSP PermissionController + Settings; kernel/hardware thermal (thermal HAL, `thermal_hotplug`, cooling devices) is untouched |
| `com.huawei.powergenie` | HAware: background app freezer | none — background apps actually survive now. **Did not stick**: it re-enables itself for user 0 within a minute (persistent app); not a network client, see `README.md` residuals |
| `com.huawei.behaviorauth` | behavioural biometrics (profiles your interaction patterns) | PIN/password |
| `com.huawei.nearby` | Nearby/device discovery | none |
| `com.huawei.dmsdp` | distributed multi-screen | none |
| `com.huawei.distributed.kms` | cross-device key management | none |
| `com.huawei.deviceauth` | cross-device authentication | none |
| `com.huawei.coauthservice` | collaborative authentication | none |
| `com.huawei.devicegroupmanage` | "Super Device" group manager | none |
| `com.huawei.android.instantshare` | instant share (Huawei↔Huawei) | KDE Connect — installed |
| `com.huawei.synergy` | device collaboration service | KDE Connect |
| `com.huawei.airlink` | AirLink wireless projection | none (Miracast path stays in the framework) |
| `com.huawei.android.mirrorshare` | MirrorShare casting | none |
| `com.huawei.pcassistant` | HiSuite PC bridge over USB | KDE Connect / plain MTP |
| `com.huawei.android.thememanager` | Themes store (online, uploads) | Simple Mobile Tools Launcher theming |
| `com.huawei.android.totemweather` | Weather (sends location) | Breezy Weather (F-Droid) — not installed |

## D — NOT applied (review first)

| package | why left alone |
|---|---|
| ~~`com.huawei.hwdockbar`~~ | **CORRECTION, 2026-09-17:** this was in group C and it was wrong to be. Label **"Multi-Window"**: `DockMainService`, `MultiTaskActivity`, `FloatWindowBootsActivity`, needs `SET_WINDOW_MODE` / `MANAGE_ACTIVITY_STACKS` / `READ_FRAME_BUFFER` / `MANAGE_FOLD_SCREEN`. It is the edge-swipe **multi-window dock** (split screen + floating windows), which works in ordinary tablet mode — a launcher/UI layer, not plumbing and not a telemetry path. **Re-enabled on both users** (`targets-correction.txt`). |
| ~~`com.huawei.desktop.systemui`~~, ~~`com.huawei.desktop.explorer`~~ | **CORRECTION, 2026-09-17:** desktop ("PC") mode's SystemUI (label `HwSystemUI`) and file window (label `My files`) — again a UI layer, no telemetry. **Re-enabled.** If you want PC mode still gone, disable these two *only* (`pm disable-user --user 0 com.huawei.desktop.systemui com.huawei.desktop.explorer`) and leave `hwdockbar` alone. |
| `com.huawei.kidsmode` | Kids Mode, the separate child launcher. Left as found (disabled for user 10 by an earlier session, enabled for user 0) — disabling it is a child-safety decision, asked about separately |
| `com.huawei.hwddmp` | purpose not identified from the APK name (possibly the USB/MTP bridge) — disabling could break USB file transfer |
| `com.huawei.hisight` | AirSharingClient: wireless projection (user-facing feature, not telemetry) |
| `com.huawei.hff` | HMS *libraries* container — inert without `hwid`; leaving it avoids breaking any app that links it |

## E — asked for by name (2026-09-17, `targets-addendum.txt`)

| package | outcome |
|---|---|
| `com.yandex.zenkitpartnerconfig` | **disabled** on both users. Label `ZenkitPartnerConfig`, `/preload/app/zenkit/zenkit.apk`, **5.7 KB**, zero declared permissions, no launcher activity, `stopped=true notLaunched=true` (never ran), and not even installed for user 10. Honest verdict: a partner-config stub, not a real app — the grant is cosmetic. |
| `com.huawei.parentcontrol` | **cannot be removed or disabled on this firmware — measured, not assumed.** All four mechanisms refused: `pm disable-user` → *"not allowed to disable this package"*; `pm uninstall --user N` → *"not allowed to uninstall"*; `pm hide` and `pm suspend` → silent no-ops (state stays `hidden=false`, `suspended=false`). Deleting the APK is closed too: `ro.boot.veritymode=green` + locked bootloader, `/system` is the root dm-verity device (system-as-root) and the product partitions are read-only erofs behind dm-verity (`/hw_product` = dm-8, `/vendor` = dm-12, each with a `*-verity` sibling) — a write there breaks verified boot with no repair path. Checked first that no parental session is active (no device/profile owners, `dumpsys device_policy`) so nothing can be stranded. **Applied instead** (`parentcontrol-neuter.sh`): `appops` `RUN_IN_BACKGROUND` + `RUN_ANY_IN_BACKGROUND` **deny** and a force-stop, so its services/receivers cannot run in the background; it is currently not running. Revert: `cmd appops set com.huawei.parentcontrol RUN_IN_BACKGROUND allow`. |

Note what the app actually is, from its manifest: the *supervisor* tool — it requests
`SET_CANNOT_UNINSTALLED_PERMISSION`, `PROTECTAREA`, and
`com.huawei.browser.HistoryProvider.READ` (parent-side supervision), i.e. it is the
enforcement half of a parental session configured by the device owner, not a
network client aimed at the owner.

## Explicitly kept (and why)

| kept | reason |
|---|---|
| `com.huawei.webview` | the system WebView provider — disabling breaks WebView in every app |
| `com.huawei.android.launcher` | Home/recents/gesture nav |
| `com.huawei.android.internal.app` | intent resolver/chooser |
| `com.huawei.systemserver`, `com.huawei.harmonyos.foundation`, `com.huawei.HwOPServer` | core framework processes (system uid) |
| `com.huawei.camera`, `bluetooth`, `HwMultiScreenShot`, `screenrecorder`, `smartshot`, `notepad`, `calendar`, `email`, `deskclock`, `soundrecorder`, `videoeditor`, `filemanager`, `compass`, `contacts`/`ContactsProvider`, `localBackup`, `HwPhoneClone` | local, offline, user-facing — no data egress once `hwid`/`hicloud` are gone |
| `com.android.mediacenter` (Gallery) | local gallery; its cloud half is dead once `hicloud` is disabled |
| vendor HALs (`vendor.huawei.hardware.hwhiview`, `hwlog_wq`, `HW_KERNEL_STP_*`, `hwservicemanager`…) | kernel/vendor services, not `pm`-addressable; killing them breaks hardware logging/function |

## Out of scope but worth knowing

* `hwlog`/HiView *kernel* logging stays (vendor HALs above) — it writes to
  `/data/log` on-device; deleting the ring is possible but it is a device-local
  buffer, not a network path. The network paths are the packages removed above.
* Per-app network access is still worth enforcing with **NetGuard** (installed).
