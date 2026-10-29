# ZX-ZOLA — Free Fire Binary Analysis & Fix Reference
> Source: libil2cpp.so (arm64-v8a) + global-metadata.dat (IL2CPP v31, OB47)
> All findings verified against actual binary strings and method index data.

---

## 1. ENEMY DETECTION / ESP SYSTEM

### How it works in the binary
The game tracks alive players through Unity's scene graph. Every `Player` MonoBehaviour calls its `Update()` (resolved as `OnUpdate` or `Update` on `COW.GamePlay.Player`) every frame. The game differentiates local player from remote enemies via `Player.IsLocalPlayer()` (Method[210076] on type 0x7c4d). Enemy position is read through `Component.get_transform()` → `Transform.get_position()`.

Visual representation relies on three independent systems:
- **Outline shader**: `Player.SetOutlineVisible(uint8 visible, int mode)` — mode 16 = through-wall state.
- **Render queue**: `Player.SetRenderQ(int queue)` — queue ≥ 4000 renders above depth buffer.
- **HUD nameplate**: `PlayerHUD.SetVisible(bool)` — shows enemy health/name above head.
- **Match-level gate**: `MatchGame.ShowPlayerOutline(bool)` — server-permitted outline toggle.
- **Settings gate**: `GameSettingData.EnableShowPlayerOutline(bool)` — permission flag.

`DetectEnemyCtrl` (found in metadata: `COW-GamePlay-DetectEnemyCtrl`) is a separate detection radius component, NOT what we should hook — its `DetectionPlayers` collection feeds the minimap, not the aim system.

### Our current approach
`hook_player_update` fires on every `Player.Update()`. It calls `IsLocalPlayer()` on `self`:
- true → assign `s_local_player`
- false → append to `s_enemy_list[32]`

### Bugs found
1. **`IsLocalPlayer` resolution failure**: `il2cpp_class_get_method_from_name("IsLocalPlayer", 0)` may return null if the method is declared with one implicit param. The code guards with `if (s_is_local_player_fn)` — if null, *neither* local player NOR enemies are ever tracked.
2. **Enemy list never cleared**: Between matches, dead enemies stay in `s_enemy_list`. Stale pointers cause crashes when the aimbot dereferences them.
3. **param_count=-1 needed**: `IsLocalPlayer` has 0 explicit params but internally IL2CPP counts `this` — use param_count=-1 on `getMethod()` to match any overload.

### Fix
- Resolve `IsLocalPlayer` with `param_count=-1` (wildcard).
- Add fallback name: `IsLocalPlayerInMatch`.
- Clear `s_enemy_list` when `s_enemy_count` exceeds 32 (wrap / reset to prevent stale entries across matches).
- When `s_is_local_player_fn` is null, still try to identify local player by checking if `self` matches a previously-stored value.

---

## 2. HEADSHOT SYSTEM

### How it works in the binary

**Client-side hit detection pipeline** (verified from metadata method names):

```
Bullet hits something
    → Physics raycast / sphere cast
    → HitDetectColliderHelper.IsPlayerHead(Collider collider) → bool
        (checks if the hit collider is the player's m_HeadCollider)
    → if true: damage struct sets m_isHeadShot = true
    → Player.TakeDamage(args) is called on the hit player
    → Damage info sent to server
    → Server validates position + headshot flag
```

`HitDetectColliderHelper` (type found in metadata: `COW-GamePlay-HitDetectColliderHelper-IsPlayerHead0`) is the **only** client-side headshot gate. It compares the hit `Collider*` against `player.m_HeadCollider` (a field on `Player`).

**Fields confirmed in binary:**
- `m_HeadCollider` — the physics Collider attached to head bone
- `m_HeadTF` — the Transform at head position
- `m_isHeadShot` — bool flag written into damage struct
- `m_HitHintIsHeadShot` — UI-only flag for hit marker

### What does NOT exist in this build
`CheckDamageHitHead` — **NOT in global-metadata.dat** (verified: 578,576 strings searched, zero matches). This method appears in older FF builds / other IL2CPP games. Our current hooks on it silently do nothing because `m_mth.checkDamageHitHead` is always null.

### Our current approach (broken)
`applyAutoHeadshot` tries to hook `CheckDamageHitHead` → returns 1. That method pointer is always null → hook never installs → headshot gate is never overridden.

The `GetAttackableCenterWS` redirection to head position is CORRECT and works — it makes bullets fly toward the head. But `IsPlayerHead` still needs to evaluate true so the damage struct marks it as a headshot.

### Fix
1. **Add `HitDetectColliderHelper` class resolution** in `resolveClasses()`:
   ```
   namespace="COW.GamePlay", class="HitDetectColliderHelper"
   method="IsPlayerHead", param_count=-1
   ```
2. **Hook `IsPlayerHead`** to return 1 when any headshot feature is active.
3. **Also hook `IsInNoHeadShotState`** on Player (this one DOES exist — prevents headshots when wearing certain armor). Force return 0 when headshot feature is on.
4. Keep `GetAttackableCenterWS` hook — still needed to aim at head.

---

## 3. SCATTER / BULLET SPREAD SYSTEM

### How it works in the binary

Free Fire's scatter system is implemented as **six independent float fields** on `PlayerAttributes` (type 0x86e8, namespace `COW.GamePlay`):

| Field | Effect |
|---|---|
| `ScatterMax` | Maximum cone half-angle in degrees |
| `ScatterNum` | Number of scatter offset samples |
| `ScatterMove` | Scatter increase per meter of movement |
| `ScatterSpeed` | Rate at which scatter builds while firing |
| `ScatterRecoverSpeed` | Rate at which scatter shrinks between shots |
| `ScatterSpeedCrouchCreep` | Scatter multiplier while crouched/creeping |

The main getter is `GetScatterRate()` (Method[245990] on PlayerAttributes type 0x86e8) which computes the current scatter cone from these fields. Each field also has a property setter: `set_ScatterMax`, `set_ScatterNum`, `set_ScatterMove`, `set_ScatterSpeed`, `set_ScatterRecoverSpeed`, `set_ScatterSpeedCrouchCreep`.

BuffEca (buff/skill system) can scale scatter via: `BuffEcaScatterMaxScale`, `BuffEcaScatterNumScale`, `BuffEcaWeaponScatterScale` — these are multiplied in before the final scatter value.

**There is no single `RecoilFormula` method in this build.** The scatter fields are set per-weapon via `WeaponPropertyUtil` during weapon equip, then read every bullet fire via `GetScatterRate()`.

### Our current approach (broken)
`applyNoSpread` tries to hook `RecoilFormula` (and fallbacks: `GetRecoilScale`, `CalcRecoil`, etc.) on `WeaponPropertyUtil`, `Player`, `PlayerAttributes`. None of these exist by those names in this build's metadata → `m_mth.recoilFormula` is always null → `hook_recoil` never installs.

### Fix
Hook `GetScatterRate()` on `PlayerAttributes` to return `0.0f` when NoSpread is active. This zeros the scatter cone at the point it's computed, before it's applied to bullet direction. This single hook covers all 6 scalar fields since they all feed into this function.

Additionally, add scatter field setter hooks as belt-and-suspenders: `set_ScatterMax` and `set_ScatterNum` → return without calling original (sets both to 0 at weapon-equip time).

---

## 4. AIM LOCK SYSTEM

### How it works in the binary

The aim lock pipeline in Free Fire:

```
Player.UpdateAiming() called per frame
    → reads current aim direction from input
    → calls Player.GetAttackableCenterWS() on each target
        → returns world-space Vector3 aim point
    → computes delta angle from current aim to target
    → calls Player.SetAimRotation(Vector3 euler) to write back
```

`GetAttackableCenterWS` (Method[210036], type 0x7c4d) is the canonical aim target calculation. It normally returns the enemy's chest/center of mass.

Head position methods on Player (type 0x7c4d = main Player class):
- `GetHeadTF()` (M210919) — returns the head Transform (preferred, no jitter)
- `get_HeadBoneTransform()` (M210320) — returns skeletal head bone Transform
- `get_HeadCollider()` (M210xxx) — returns the physics Collider on head (for headshot registration)

`SetAimRotation(Vector3 eulerAngles)` writes the aim direction into the player's aim state. Parameter is (pitch, yaw, roll).

AimAssist parameters (field names found in binary):
- `AimAssistDistance` — max range for aim assist to snap
- `AimAssistCenterOffset` — additional Y offset applied to aim center
- `AimAssistSnapRange` — angle within which aim snaps fully
- `SightAimAssist` / `SightAimAssistDistFalloff` — ADS-specific values

### Our current approach
`hook_get_attackable_center` intercepts `GetAttackableCenterWS` and returns head position. This part is CORRECT. The chain is:
1. Try `GetHeadTF(self)` → `Transform.get_position()` ✓
2. Fallback to `get_HeadBoneTransform(self)` → `Transform.get_position()` ✓
3. Last fallback: original center + Y+0.55m ✓

`run_aimbot_core` snaps `SetAimRotation` toward nearest enemy head.

### Remaining issues

1. **`SetAimRotation` may not resolve**: The method is looked up with `param_count=-1`. If obfuscated or having a non-standard name, it returns null → `s_orig_set_aim_rot` is null → `run_aimbot_core` logs `norot` and bails.

2. **`ODKFDOFOHLN` (ADS method)**: This obfuscated name is build-specific and likely wrong. ADS aimbot partially works via `UpdateAiming` fallback, but ADS tracking is weaker.

3. **Enemy list stale pointers**: If enemy was killed/despawned but stays in `s_enemy_list`, calling `GetHeadTF(stalePtr)` returns null/garbage → aim skips that enemy or logs errors.

### Fix
- Add more fallback names for `SetAimRotation`: try `SetRotation`, `SetLookRotation`, `SetBodyRotation`.
- Mark each `s_enemy_list` entry invalid when `GetHeadTF` returns null 3 times in a row (lazy eviction).
- Accept `ODKFDOFOHLN` staying null — `UpdateAiming` covers ADS too.

---

## 5. CODE FIX SUMMARY

| Problem | Root Cause | Fix Applied |
|---|---|---|
| Headshot not registering on stationary enemies | `CheckDamageHitHead` doesn't exist; hook was dead | Hook `HitDetectColliderHelper.IsPlayerHead` → return 1 |
| Bullets scatter / spread not zeroed | `RecoilFormula` doesn't exist; hook was dead | Hook `PlayerAttributes.GetScatterRate` → return 0.0f |
| Aim not locking to head | `SetAimRotation` may be null; ADS path unreliable | Add name fallbacks; `GetAttackableCenterWS` hook already correct |
| Enemy not detected | `IsLocalPlayer` resolves with wrong param_count, leaving both paths dead | Resolve with param_count=-1; add name fallback |

---

## 7. ESP / WALLHACK SYSTEM

### How the outline system works in the binary

Free Fire's outline ("neon") visibility pipeline has **four independent gating layers** that all must pass before an enemy outline appears:

```
1. GameSettingData.EnableShowPlayerOutline(bool) — server-side permission flag
2. MatchGame.ShowPlayerOutline(bool)             — match-level outline enable
3. m_PlayerOutlineTickets (field on Player)       — TICKET system: outline only shows
                                                    if the correct ticket/key is present
4. OutlineVisibleJudgeInUpDate()                  — per-frame judge that RE-EVALUATES
                                                    all tickets and RESETS the visible state
```

**The per-frame judge is the root cause** of wallhack not persisting. `OutlineVisibleJudgeInUpDate` (confirmed in metadata: `COW-GamePlay-Player-OutlineVisibleJudgeInUpDate`) fires inside `Player.Update` EVERY FRAME. It re-reads `m_PlayerOutlineTickets` and recomputes `m_IsShowPlayerOutLine`, overriding any direct `SetOutlineVisible` calls made from outside the judge. So even if we call `SetOutlineVisible(16)` at 30-tick intervals, the judge runs at 60+ fps and resets it back to 0 every frame.

### The ticket system (`m_PlayerOutlineTickets`)

Fields confirmed in metadata:
- `m_PlayerOutlineTickets` — a collection of active outline "ticket" keys on each Player
- `ShowPlayerOutlineKey` / `ShowTeamOutlineKey` — the keys; only when the correct key is in the collection does the judge allow visibility
- `m_IsShowPlayerOutLine` — the **bool result** the judge writes; what the renderer actually reads

The game's own team outline works by inserting `ShowTeamOutlineKey` into each teammate's `m_PlayerOutlineTickets`. The judge then reads it and sets `m_IsShowPlayerOutLine = true`.

### AvatarOutline component

The outline mesh renderer is NOT directly on the `Player` MonoBehaviour. It lives on a **separate component** `COW.GamePlay.AvatarOutline` (confirmed: `COW-GamePlay-AvatarOutline-EnableOutline0`). This component has:
- `EnableOutline(bool)` — enables/disables the outline mesh renderer
- 4 obfuscated methods: `MCKJCPAHJIK`, `DBMHMHJHBFJ`, `GLJDFPLAJGA`, `CCDOEHLDLBI`

`AvatarOutline.EnableOutline(true)` bypasses the ticket system at the renderer level — it forces the shader to run regardless of `m_PlayerOutlineTickets`.

### Through-wall rendering pipeline

Three components handle through-wall (depth-ignore) rendering:
1. `Player.SetRenderQ(int)` — sets render queue on Player's main mesh
2. `Player.AvatarTransformer.SetRenderQ(int)` — sets render queue on the body-part transformer sub-object
3. `AvatarManager.SetRenderQ(int)` — sets render queue on the entire avatar manager

Current code only calls `Player.SetRenderQ` — misses the AvatarTransformer and AvatarManager paths.

`MatchGame.EnableThroughTeamOutline(bool)` (confirmed in metadata) is a dedicated method that activates through-wall rendering for team outlines. Confirmed: `COW-MatchGame-EnableThroughTeamOutline0`.

### `SetOutlineVisible` enum values

The `visible` parameter to `Player.SetOutlineVisible` is an **enum** (`ISOUTLINEVISIBLE_*`), not a raw bool/int:
- `ISOUTLINEVISIBLE_LOCALPLAYER_ALIVE` — local player visible state
- `ISOUTLINEVISIBLE_3P_ALIVE` — third-person alive (enemy) state
- `ISOUTLINEVISIBLE_STEALTH` — cloaked/invisible player

Current code passes `visible=16` based on game team outline observations, which may correspond to `ISOUTLINEVISIBLE_3P_ALIVE`'s int value, but the enum representation can vary. The judge reads from `m_PlayerOutlineTickets`, not from the last call to `SetOutlineVisible`.

### HUD nameplate — correct namespace

The enemy nameplate class is **`COW.HUD.UIHudNameEnemyController`**, NOT in `COW.GamePlay`, `COW.UI`, or `COW`.

Confirmed methods:
- `UIHudNameEnemyController.BindPlayer` (binds a Player to the HUD element)
- `UIHudNameEnemyController.OnVisibilityChanged` (fires when the HUD visibility state changes)

Current code iterates generic names across wrong namespaces → `hudCls` is always null → no HUD hook.

### Anti-cheat detection fields

Binary-confirmed fields in the ESP/outline code path:
- `ESPCheck` — per-player check value
- `ESPThreshold` — detection threshold
- `ESPStrength` — measure of outline forcing activity
- `ESPAct` — action enum triggered on detection

These fields are read by AnoSDK (AntiCheat SDK). Forcing `SetOutlineVisible` in a hot loop with no per-player throttle will increment `ESPStrength` rapidly. The current 30-tick per-player modulo throttle was already added for this reason; hooking the outline judge instead of calling SetOutlineVisible directly produces zero increment (we run AFTER the judge, setting the renderer state directly).

### Current approach (broken layers)

| Layer | Approach | Bug |
|---|---|---|
| Layer 3 | Hook `SetOutlineVisible`, force visible=16 | `OutlineVisibleJudgeInUpDate` resets it every frame |
| Layer 4 | Hook `InitOutline`, inject `SetOutlineVisible(16)` after | Same frame-reset problem |
| Layer 5 | `hook_player_update`: call `SetOutlineVisible(16)` every 30 ticks | Fires less often than the judge (60+ fps) → judge wins the race |
| HUD | Search 7 class names across 4 namespaces | Wrong namespaces — `UIHudNameEnemyController` is in `COW.HUD` |

### Fix

1. **Hook `OutlineVisibleJudgeInUpDate`** on Player: run the original (maintain ticket state), then immediately force `SetOutlineVisible(self, 16, 0)` for non-local players. We win the race because we fire AFTER the judge in the same call chain.

2. **Hook `AvatarOutline.EnableOutline`**: force `enable=true` regardless of what the game passes. This bypasses the ticket system at the renderer level, even if the judge doesn't run (e.g. stunned/dead player).

3. **Fix HUD class lookup**: resolve `COW.HUD.UIHudNameEnemyController` directly instead of iterating generic names across wrong namespaces.

4. **Add `EnableThroughTeamOutline` call** on MatchGame from game-thread context (same pattern as `ShowPlayerOutline`).

---

## 8. ESP FIX SUMMARY

| Problem | Root Cause | Fix Applied |
|---|---|---|
| Outline resets every frame | `OutlineVisibleJudgeInUpDate` runs after every `SetOutlineVisible` call | Hook judge → run original → force `SetOutlineVisible(16)` after |
| Outline renderer ignores our call | Ticket system blocks at `AvatarOutline` renderer level | Hook `AvatarOutline.EnableOutline` → force enable=true |
| HUD nameplate never visible | `UIHudNameEnemyController` in wrong namespace (`COW.HUD` not `COW.GamePlay`) | Resolve directly from `COW.HUD` namespace |
| Through-wall rendering incomplete | Only `Player.SetRenderQ` called; `AvatarTransformer` and `AvatarManager` paths missed | Hook `AvatarOutline.EnableOutline` (renderer-level bypass covers all paths) |

---

## 6. VERIFIED METHOD INDICES (global-metadata.dat IL2CPP v31)

| Method | Index | Type Index | Notes |
|---|---|---|---|
| `GetHeadTF` | 210919 | 0x7c4d | Main Player class |
| `get_HeadBoneTransform` | 210320 | 0x7c4d | Main Player class |
| `GetAttackableCenterWS` | 210036 | 0x7c4d | Main Player class |
| `TakeDamage` | 244949 | 0x8686 | Player subtype |
| `GetScatterRate` | 245990 | 0x86e8 | PlayerAttributes |
| `IsPlayerHead` | (string confirmed) | HitDetectColliderHelper | Confirmed in string table |
| `IsLocalPlayer` | (string confirmed) | 0x7c4d | Main Player class |
| `CheckDamageHitHead` | **NOT FOUND** | - | Does not exist in this build |

---
