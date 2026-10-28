# Free Fire Protection Analysis — ZX-ZOLA Reference

**Source:** `Free fire.zip` (arm64 libraries, OB47)  
**Date:** 2026-10-28  
**Purpose:** Real library audit. Every bypass decision in this codebase must
trace back to a finding here. Update this file when a new game version drops.

---

## Libraries Found

| File | Size | Identity |
|------|------|----------|
| `libanogs.so` | 5.3 MB | Tencent AnoSDK — main anti-cheat |
| `libanort.so` | 1.7 MB | Tencent AnoSDK Runtime — internal runtime helper |
| `libGGP.so` | 9.0 MB | Tencent Bifrost — code virtualizer (SONAME: `libBifrost.so`) |
| `libgpdeku.so` | 369 KB | Google Play DRM — screen capture restriction, **not anti-cheat** |
| `libmain.so` | 6.6 KB | Unity JNI loader — loads `libunity.so` + `libil2cpp.so` |

---

## Protection 1 — AnoSDK Code Integrity Scanner

**Library:** `libanogs.so`  
**Evidence (strings):**
```
inline_hook_opcode_dismatch
ms_hook_opcode
ms_set_inlie_hook
set_inline_hook_error
!skip:0x%08x, bin_patch_cnt:%d
```

**How it works:**  
AnoSDK contains a custom virtual machine (source path found in binary:
`/Users/bkdevops/tpmobile/workspace/.../ano/mvm/source/VM/Memory/BopMemoryOperation.cpp`).
This MVM ("Mobile VM") runs encrypted bytecode scan rules, downloads fresh rules from
`down.qq.com/iedsafe/Client/android/%d/config2.xml`, and scans loaded libraries for
inline hook opcodes.

Detection path:
1. MVM opens libc.so (via `open` → `/system/lib64/libc.so`)
2. Reads function bytes of `openat`, `kill`, `exit`, `dl_iterate_phdr` etc.
3. Compares bytes to known-good signatures
4. Finds Dobby trampoline (e9 xx xx xx = B/BL opcode) → `bin_patch_cnt++`
5. Includes `bin_patch_cnt` in heartbeat payload → server detects → BAN

**Our OLD approach:** Dobby inline patches on libc (`hookSym("libc.so", "openat", ...)`)  
**Status: ❌ DETECTED** — Dobby modifies function bytes; AnoSDK reads them directly.

**Fix:** GOT patching on libanogs.so's own GOT table. GOT entries are function
_pointers_, not function _code_. AnoSDK's scanner checks code bytes, not pointer values.
Patching the GOT is undetectable.

---

## Protection 2 — /proc/self/maps Scanner

**Library:** `libanogs.so`, `libanort.so`  
**Evidence (XOR-0x18 decoded strings):**
```
/proc/self/maps
/proc/%d/maps
/proc/%d/cmdline
/proc/bus/input/devices
```

**How it works:**  
AnoSDK reads `/proc/self/maps` to enumerate loaded libraries and detect injected `.so` files.
It uses the MVM to iterate mapped regions and flag any library not in its whitelist.

**Import analysis:**  
libanogs.so does NOT import plain `openat@LIBC`. It uses:
- `open@LIBC` (JUMP_SLOT 0x50f790, GLOB_DAT 0x50edb0)
- `__open_2@LIBC` (JUMP_SLOT 0x50f700) ← **safety-checked open**
- `__openat_2@LIBC` (JUMP_SLOT 0x50f8b0) ← **safety-checked openat**
- `fopen@LIBC` (JUMP_SLOT 0x50f650, GLOB_DAT 0x50ecf8)
- `syscall@LIBC` (JUMP_SLOT 0x50f780) ← **raw syscall, bypasses all libc hooks**

libanort.so uses the same set (offsets differ).

**Our OLD approach:** Hook `openat` in libc via Dobby  
**Status: ❌ WRONG** — libanogs uses `__openat_2` and `open`, not `openat`. Our hook
was never triggered for AnoSDK's maps reads. Also Dobby-detected per Protection 1.

**Fix:** GOT patch `open`, `__open_2`, `__openat_2`, `fopen`, `popen`, AND `syscall` in
both libanogs.so and libanort.so's GOT tables. The `syscall` hook intercepts
`syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", ...)` that would bypass file-open hooks.
All these hooks serve filtered memfd content (as `make_filtered_maps()` already does).

---

## Protection 3 — dl_iterate_phdr Library Enumeration

**Library:** `libanogs.so`  
**Evidence:**
- Import: `dl_iterate_phdr@LIBC` (JUMP_SLOT 0x50fc28)

**How it works:**  
AnoSDK calls `dl_iterate_phdr` to walk the linker's internal library list and detect
injected `.so` files by name. This is separate from the /proc/self/maps scan and
uses the kernel's link-map directly.

**Our OLD approach:** Dobby inline patch on `dl_iterate_phdr` in libc  
**Status: ❌ DETECTED** — Dobby patches libc bytes → detected (Protection 1).

**Fix:** GOT patch `dl_iterate_phdr` in libanogs.so's GOT (0x50fc28). Our hook
wraps the user-supplied callback and silently skips the entry for `libzx_zola`.

---

## Protection 4 — ptrace Anti-Debug

**Library:** `libanogs.so`, `libanort.so`  
**Evidence:**
- Import: `ptrace@LIBC` (libanogs JUMP_SLOT 0x50f7f0, GLOB_DAT 0x50ee20;
  libanort JUMP_SLOT 0x1658c0)

**How it works:**  
AnoSDK calls `ptrace(PTRACE_TRACEME, 0, 0, 0)`. Success (return 0) means no external
debugger attached. Failure (EPERM) means a debugger already holds a ptrace attach →
AnoSDK reports it.

Some implementations also call `ptrace(PTRACE_ATTACH, getppid(), ...)` to check the parent.

**Our OLD approach:** Not intercepted  
**Status: ❌ MISSING** — ptrace detections are reported to the server.

**Fix:** GOT patch `ptrace` in both libanogs.so and libanort.so. Hook returns 0
unconditionally (PTRACE_TRACEME success = no debugger, PTRACE_ATTACH always fails
for us so returning 0 simulates success for all AnoSDK ptrace calls).

---

## Protection 5 — Fork-Based Self-Check

**Library:** `libanogs.so`, `libanort.so`  
**Evidence:**
- Import: `fork@LIBC` (libanogs JUMP_SLOT 0x50f808, GLOB_DAT 0x50ee48;
  libanort JUMP_SLOT 0x165878)
- Import: `waitpid@LIBC` (libanogs JUMP_SLOT 0x50f818)

**How it works:**  
AnoSDK forks a child process. The child process checks the parent for:
- Modified GOT entries (detecting hooks)
- Unexpected virtual memory regions
- ptrace attachment by the parent

If the child detects modifications it sends the findings to the parent process which
reports them to the server.

**Our OLD approach:** Not intercepted  
**Status: ❌ MISSING** — child process spawned by AnoSDK can detect our hooks.

**Fix:** GOT patch `fork` to return -1/EAGAIN. No child process = no self-inspection.

---

## Protection 6 — Shell Execution (popen)

**Library:** `libanogs.so`  
**Evidence:**
- Import: `popen@LIBC` (JUMP_SLOT 0x50f740)
- Import: `pclose@LIBC` (JUMP_SLOT 0x50f748)

**How it works:**  
AnoSDK uses `popen()` to execute shell commands and read their output. This can detect:
- Presence of `su`, `busybox`, `magisk` binaries in PATH
- Running processes (`ps` output)
- Mounted filesystems (`mount` output)
- Root indicators

**Our OLD approach:** Not intercepted  
**Status: ❌ MISSING** — popen allows AnoSDK to run arbitrary shell probes.

**Fix:** GOT patch `popen` to return NULL. GOT patch `pclose` to return 0.

---

## Protection 7 — Raw Syscall Bypass

**Library:** `libanogs.so`, `libanort.so`  
**Evidence:**
- Import: `syscall@LIBC` (libanogs JUMP_SLOT 0x50f780, GLOB_DAT 0x50eda0;
  libanort JUMP_SLOT 0x1658e8)
- Export from libanort: `tp_syscall_imp` (0x146940) — Tencent custom syscall

**How it works:**  
AnoSDK can call `syscall(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY)` using
libc's `syscall()` C function. This bypasses all libc-level function hooks (Dobby
patches on `open`, `openat`, `fopen`). Even with our GOT patches on `open`/`fopen`,
a `syscall(SYS_openat)` call goes directly from libanogs→GOT→`syscall`→kernel.

`tp_syscall_imp` in libanort.so is libanort's internal raw syscall wrapper (used
internally, not exported for libanogs). libanogs does NOT import from libanort.

**Our OLD approach:** Not intercepted  
**Status: ❌ MISSING** — syscall-based opens of /proc/self/maps bypass all our hooks.

**Fix:** GOT patch `syscall` in libanogs.so and libanort.so. Hook checks if
`number == __NR_openat` and `path` matches is_self_maps(); if so returns filtered memfd.
All other syscall numbers pass through to real libc `syscall`.

---

## Protection 8 — Kill / Exit / Abort Process Termination

**Library:** `libanogs.so`, `libanort.so`  
**Evidence:**
- Imports: `kill`, `exit`, `_exit`, `abort` in both libraries

**How it works:**  
AnoSDK kills the process when it detects cheating. It uses kill/exit/abort from
background threads (not the main thread).

**Our OLD approach:** Dobby inline patches on libc `kill`, `exit`, `_exit`, `abort`  
**Status: ❌ DETECTED** — Dobby on libc = detected by code integrity scanner.

**Fix:** GOT patch `kill`, `exit`, `_exit`, `abort` in libanogs.so and libanort.so.
Same blocking logic as before, but now via GOT (undetectable).

---

## Protection 9 — AnoSDK Network Heartbeat (Server-Side)

**Library:** `libanogs.so`  
**Evidence (decoded strings):**
```
AnoSDKIoctl
AnoSDKGetReportData
AnoSDKOnRecvData
down.qq.com/iedsafe/Client/android/%d/%08X/mrpcsc.data
down.qq.com/iedsafe/Client/android/%d/config2.xml
```

**How it works:**  
AnoSDK sends periodic heartbeat reports containing all scan results to Tencent's
servers. The game calls `AnoSDKIoctl(cmd, ...)` where cmd < 0x10 for init/heartbeat.
Server receives the report and bans the account if detections are present.

**Critical constraint:** `AnoSDKIoctl` cmd < 0x10 MUST always reach the real function.
Blocking heartbeats causes a server-side "heartbeat loss" soft-ban (separate from
cheat detection ban). We must never hook `AnoSDKIoctl` or `AnoSDKInit`.

**Our approach:** Never hook AnoSDK's own exported functions  
**Status: ✅ CORRECT** — heartbeat always passes through.

---

## Protection 10 — Bifrost Code Virtualizer (libGGP.so / libBifrost.so)

**Library:** `libGGP.so`  
**Evidence:**
- SONAME: `libBifrost.so`
- Entry point at 0xf600 (unpacker)
- Only 4 visible section headers (all others stripped)
- No readable symbols, no readable strings
- BIND_NOW flag (all relocations resolved at load)
- 9MB packed size

**How it works:**  
Bifrost is Tencent's native code virtualizer. It protects the game's business logic
(not AnoSDK directly) by:
1. Converting native code to a custom VM bytecode
2. Unpacking and JIT-compiling at runtime
3. Making static analysis impossible (no readable symbols)

Bifrost protects game gameplay code (anti-teleport, anti-speed-hack server-side checks).
It is NOT an active anti-cheat scanner. It protects the game logic that feeds data to
AnoSDK's network reports.

**Our approach:** No interaction with Bifrost  
**Status: ✅ CORRECT** — Bifrost doesn't scan for cheats; it protects game code from
reverse engineering. Our hooks don't touch Bifrost.

---

## Protection 11 — Server-Side Behavioral Detection

**Not in any library — purely server-side.**

**How it works:**  
Tencent's servers analyze game telemetry:
- Headshot rate > 90% over time → flagged
- Kill/death ratio anomalies
- Movement speed violations
- Damage numbers outside weapon stats
- Accuracy on moving targets

**Our situation:**
- Full Aimbot (100% headshots, all enemies) → **HIGH BAN RISK**
- Auto Headshot via aim assist → lower risk than full aimbot
- ESP (outline only, no aimbot) → **very low risk**

**Current feature guidance:**
- Use auto-aim assist style (not full lock), vary target selection
- Full aimbot = eventual behavioral ban regardless of how good our SDK bypass is

---

## Summary: What Was Wrong and What Changed in v2.13

### Root cause of bans:
**Dobby inline patches on libc** → `bin_patch_cnt > 0` → detected in heartbeat → ban.

### Every old mistake, corrected:

| What we did | Why it was wrong | v2.13 fix |
|-------------|-----------------|-----------|
| Dobby on `openat` in libc | libanogs uses `__openat_2`, not `openat` — hook never fired AND libc bytes modified = detected | GOT patch `open`+`__open_2`+`__openat_2`+`fopen` on libanogs.so + libanort.so |
| Dobby on `dl_iterate_phdr` in libc | Modifies libc bytes → detected | GOT patch `dl_iterate_phdr` on libanogs.so |
| Dobby on `kill`/`exit`/`abort` in libc | Modifies libc bytes → detected | GOT patch same functions on libanogs.so + libanort.so |
| No `ptrace` hook | ptrace anti-debug not bypassed | GOT patch `ptrace` |
| No `fork` hook | self-inspection child process spawns | GOT patch `fork` |
| No `popen` hook | shell execution for root detection | GOT patch `popen` |
| No `syscall` hook | raw syscall bypasses all libc hooks | GOT patch `syscall`, filter `SYS_openat` |

### ELF offsets for GOT patching (libanogs.so, this version):

These are **file-relative offsets**. Runtime address = load_base + offset.

```
open           JUMP_SLOT 0x50f790  GLOB_DAT 0x50edb0
__open_2       JUMP_SLOT 0x50f700
__openat_2     JUMP_SLOT 0x50f8b0
fopen          JUMP_SLOT 0x50f650  GLOB_DAT 0x50ecf8
popen          JUMP_SLOT 0x50f740
pclose         JUMP_SLOT 0x50f748
kill           JUMP_SLOT 0x50f5f0  GLOB_DAT 0x50eca8
exit           JUMP_SLOT 0x50fb30
_exit          JUMP_SLOT 0x50f820
abort          JUMP_SLOT 0x50f938
ptrace         JUMP_SLOT 0x50f7f0  GLOB_DAT 0x50ee20
fork           JUMP_SLOT 0x50f808  GLOB_DAT 0x50ee48
syscall        JUMP_SLOT 0x50f780  GLOB_DAT 0x50eda0
dl_iterate_phdr JUMP_SLOT 0x50fc28
```

### ELF offsets for GOT patching (libanort.so, this version):

```
__open_2       JUMP_SLOT 0x1655e0
fopen          JUMP_SLOT 0x1655f0
open           JUMP_SLOT 0x1655f8
__openat_2     JUMP_SLOT 0x165620
kill           JUMP_SLOT 0x165790
_exit          JUMP_SLOT 0x165888
ptrace         JUMP_SLOT 0x1658c0
fork           JUMP_SLOT 0x165878
syscall        JUMP_SLOT 0x1658e8
```

> NOTE: The ELF parser in `startWatcher()` finds these by symbol name (dynamic
> relocation table walk), so hardcoded offsets are a fallback/documentation only.
> The symbol-name approach survives minor GOT layout changes across updates.
