# ZX-ZOLA — Free Fire Binary Analysis & Fix Reference
> Source: libil2cpp.so (arm64-v8a) + global-metadata.dat (IL2CPP v31, OB47)
> All findings verified against actual binary strings (578,576 strings searched).
> Last updated: v2.15

---

## 1. ENEMY DETECTION / PLAYER TRACKING

### How it works in the binary
The game tracks alive players through Unity's scene graph. Every `Player` MonoBehaviour calls its
`Update()` each frame (resolved from `COW.GamePlay.Player`). The game differentiates local player
from remote enemies via `Player.IsLocalPlayer()` (confirmed: `COW-GamePlay-Player-IsLocalPlayer0`,
Method[210076] on type 0x7c4d).

Enemy position is read through `Component.get_transform()` → `Transform.get_position()`.

`DetectEnemyCtrl` (found in metadata: `COW-GamePlay-DetectEnemyCtrl`) is a separate detection
radius component — feeds the minimap only, NOT the aim system.

### Bugs found (and status)

| Bug | Root Cause | Fix in v2.14 | Status |
|---|---|---|---|
| `IsLocalPlayer` resolution fails | param_count=0 passed; IL2CPP counts `this` internally | Resolve with param_count=-1 + name fallback `IsLocalPlayerInMatch` | ✅ Fixed |
| Enemy list never cleared | Dead enemies stay in `s_enemy_list[32]` across matches → null-deref in aimbot | Swap-and-pop eviction when `GetHeadTF` returns null 3× | ✅ Fixed |

---

## 2. HEADSHOT SYSTEM

### How it works in the binary

Client-side hit detection pipeline (verified from metadata method names):

```
Bullet hits something
    → Physics raycast / sphere cast
    → HitDetectColliderHelper.IsPlayerHead(Collider collider) → bool
        (checks if hit collider == player.m_HeadCollider)
    → if true: damage struct sets m_isHeadShot = true
    → Player.TakeDamage(args) called on hit player
    → Damage info sent to server
    → Server validates position + headshot flag
```

`HitDetectColliderHelper` (confirmed: `COW-GamePlay-HitDetectColliderHelper-IsPlayerHead0`) is the
**only** client-side headshot gate. It compares the hit `Collider*` against `player.m_HeadCollider`.

**Fields confirmed in binary:**
- `m_HeadCollider` — physics Collider on head bone
- `m_HeadTF` — Transform at head position
- `m_isHeadShot` — bool flag written into damage struct
- `m_HitHintIsHeadShot` — UI-only flag for hit marker

### What does NOT exist in this build
`CheckDamageHitHead` — **NOT in global-metadata.dat** (zero matches out of 578,576 strings).
Our hooks on it silently did nothing in v2.13. Fixed in v2.14 by hooking `IsPlayerHead` instead.

### Fix summary (v2.14)

| Step | Fix |
|---|---|
| Hook `HitDetectColliderHelper.IsPlayerHead` → return 1 | Forces every bullet hit to register as headshot |
| Hook `Player.IsInNoHeadShotState` → return 0 | Bypasses armor-based headshot-block states |
| Keep `GetAttackableCenterWS` redirect to head position | Aims bullets at head (unchanged from v2.13) |

---

## 3. SCATTER / BULLET SPREAD SYSTEM

### How it works in the binary

Free Fire's scatter system uses **six independent float fields** on `PlayerAttributes` (type 0x86e8,
namespace `COW.GamePlay`):

| Field | Effect |
|---|---|
| `ScatterMax` | Maximum cone half-angle in degrees |
| `ScatterNum` | Number of scatter offset samples |
| `ScatterMove` | Scatter increase per meter of movement |
| `ScatterSpeed` | Rate at which scatter builds while firing |
| `ScatterRecoverSpeed` | Rate at which scatter shrinks between shots |
| `ScatterSpeedCrouchCreep` | Scatter multiplier while crouched/creeping |

The main computation is `GetScatterRate()` (Method[245990] on PlayerAttributes type 0x86e8),
which computes the current scatter cone from all these fields. Property setters exist for each:
`set_ScatterMax`, `set_ScatterNum`, `set_ScatterMove`, `set_ScatterSpeed`, `set_ScatterRecoverSpeed`.

**There is no `RecoilFormula` method in this build.** Zero matches in the full string table.
Our v2.13 hooks on it silently did nothing.

### Fix (v2.14)
- Hook `GetScatterRate()` → return `0.0f` (primary: zeros the cone at computation root)
- Hook `set_ScatterMax` + `set_ScatterNum` → force value to 0.0f (belt-and-suspenders at equip time)

---

## 4. AIM LOCK SYSTEM

### How it works in the binary

```
Player.UpdateAiming() called per frame
    → reads current aim direction from input
    → calls Player.GetAttackableCenterWS() on each target
        → returns world-space Vector3 aim point
    → computes delta angle from current aim to target
    → calls Player.SetAimRotation(Vector3 euler) to write back
```

`GetAttackableCenterWS` (Method[210036], type 0x7c4d) normally returns enemy chest/center.
We redirect it to return head position.

Head position methods on Player (type 0x7c4d):
- `GetHeadTF()` (M210919) — head Transform (preferred, stable)
- `get_HeadBoneTransform()` (M210320) — skeletal head bone Transform
- `get_HeadCollider()` — physics Collider on head (for headshot registration)

### Remaining issues

1. **`SetAimRotation` may be null** — resolved with fallback name list in v2.14:
   `SetAimRotation → SetRotation → SetLookRotation → SetBodyRotation → SetAimDir → SetAimEuler`
2. **`ODKFDOFOHLN` (ADS method)** — obfuscated name, may be wrong per build.
   ADS aimbot falls back to `UpdateAiming` which runs for both hip and ADS.
3. **Anti-Aim flag never read** — `s_anti_aim` is set by `applyAntiAim` but never checked
   in any hook. See §9 for the fix.

---

## 5. ESP / WALLHACK SYSTEM

### Four-layer gating (binary-verified)

```
1. GameSettingData.EnableShowPlayerOutline(bool) — server-side permission flag
2. MatchGame.ShowPlayerOutline(bool)             — match-level outline enable
3. m_PlayerOutlineTickets (field on Player)       — TICKET system: outline only shows
                                                    when correct ticket/key is present
4. OutlineVisibleJudgeInUpDate()                  — per-frame judge that RE-EVALUATES
                                                    tickets and RESETS m_IsShowPlayerOutLine
```

**The per-frame judge is the root cause of wallhack not persisting.** `OutlineVisibleJudgeInUpDate`
(confirmed: `COW-GamePlay-Player-OutlineVisibleJudgeInUpDate0`) fires inside `Player.Update` EVERY
FRAME. It recomputes `m_IsShowPlayerOutLine` from `m_PlayerOutlineTickets`, overriding all
`SetOutlineVisible` calls. Our 30-tick proactive calls fired less often than 60fps judge → judge
always won the race.

### The ticket system
- `m_PlayerOutlineTickets` — collection of active outline "keys" on each Player instance
- `ShowPlayerOutlineKey` / `ShowTeamOutlineKey` — the keys; judge allows visibility only when present
- `m_IsShowPlayerOutLine` — bool the judge writes; what the renderer reads

### AvatarOutline component
The outline mesh renderer is **NOT** directly on `Player`. It lives on a separate
`COW.GamePlay.AvatarOutline` component (confirmed: `COW-GamePlay-AvatarOutline-EnableOutline0`).
- `AvatarOutline.EnableOutline(bool)` — enables/disables the outline shader mesh
- Bypasses the ticket system at the renderer level

### HUD nameplate — correct namespace
Real class: **`COW.HUD.UIHudNameEnemyController`** (confirmed: `COW-HUD-UIHudNameEnemyController-BindPlayer0`,
`COW-HUD-UIHudNameEnemyController-OnVisibilityChanged0`). Our code searched `COW.GamePlay`, `COW.UI`,
`COW` — all wrong → `hudCls` was always null.

### Through-wall rendering
- `Player.SetRenderQ(int)` — sets render queue on Player's main mesh ✓ in code
- `Player.AvatarTransformer.SetRenderQ(int)` — sub-object render queue (missed)
- `AvatarManager.SetRenderQ(int)` — avatar manager queue (missed)
- `MatchGame.EnableThroughTeamOutline(bool)` — dedicated through-wall outline gate (confirmed, missed)

### Anti-cheat detection fields
- `ESPCheck`, `ESPThreshold`, `ESPStrength`, `ESPAct` — FF reads these during AnoSDK reporting.
- Calling `SetOutlineVisible` in a hot loop increments `ESPStrength`.
- Hooking the judge and letting it run first produces zero increment (we only post-process).

### Fix (v2.15)

| Layer | Fix |
|---|---|
| Layer 8 | Hook `OutlineVisibleJudgeInUpDate`: run original (preserves ticket state), then force `SetOutlineVisible(self, 16, 0)` for enemies. We execute after the judge → always win the race. |
| Layer 9 | Hook `AvatarOutline.EnableOutline`: force `enable=true`. Bypasses ticket system at renderer level. |
| HUD | Resolve `COW.HUD.UIHudNameEnemyController` directly. Use `OnVisibilityChanged` as hook target. |
| Through-wall | Cache `MatchGame.EnableThroughTeamOutline` → call from game thread alongside `ShowPlayerOutline`. |

---

## 6. FEATURES WITH BUGS NOT YET FIXED

### 6.1 Anti-Aim — flag set, never read (BROKEN)
`applyAntiAim` sets `s_anti_aim = enable` but the flag is **never checked in any hook**.
The comment claims `hook_get_attackable_center` handles it — it does not; only
`s_auto_headshot || s_silent_aim || s_full_aimbot` are checked there.

**Fix needed**: In `hook_get_attackable_center`, add:
```cpp
// Anti-aim: for the local player, return a position far away so enemy aimbot
// cannot lock onto us by abusing GetAttackableCenterWS.
if (s_anti_aim && s_local_player && self == s_local_player) {
    using Fn = Vec3 (*)(void *, void *);
    Vec3 real = reinterpret_cast<Fn>(s_orig_attackable_ctr)(self, method);
    return {real.x + 9999.f, real.y + 9999.f, real.z + 9999.f}; // mislead enemy aim
}
```
Also: `applyAntiAim` must install the `GetAttackableCenterWS` hook (currently it doesn't call
`installAimCenterHook`).

**Confirmed metadata methods for body rotation misdirection (stronger anti-aim)**:
- `Player.GetBodyRotation` / `Player.EnableBodyRotation` (confirmed: `COW-GamePlay-Player-GetBodyRotation0`)
- `set_bodyRotation` / `get_bodyRotation` (confirmed in metadata)

---

### 6.2 MaxHealth — stub only (BROKEN)
`applyMaxHealth` logs "pending obfuscated field offset" and does nothing.

**Confirmed metadata methods:**
- `Player.set_CurHP(float)` — confirmed: `COW-GamePlay-Player-set_CurHP0`
- `Player.get_CurHP()` — confirmed: `COW-GamePlay-Player-get_CurHP0`
- `Player.set_MaxHP(float)` — confirmed: `COW-GamePlay-Player-set_MaxHP0`
- `Player.get_MaxHP()` — confirmed: `COW-GamePlay-Player-get_MaxHP0`
- `PlayerAttributes.IsInvincible()` — confirmed: `COW-GamePlay-PlayerAttributes-IsInvincible0`
- `PlayerAttributes.SetIsInvincibleByImmortalitySkill(bool)` — confirmed: `COW-GamePlay-PlayerAttributes-SetIsInvincibleByImmortalitySkill0`

**Fix needed**: Resolve `Player.set_CurHP` and `Player.set_MaxHP` and call them from `hook_player_update`
(game thread, same pattern as outline calls) to keep HP at max every frame for the local player.
Alternatively hook `PlayerAttributes.IsInvincible` → return 1 (simpler, one method).

---

### 6.3 GodMode — aliased to AntiDamage (WEAK)
`ZX_GOD_MODE` dispatches to `applyAntiDamage`. The anti-damage hook intercepts `TakeDamage` and
returns early. This works but has two weaknesses:
1. `TakeDamage` signature may differ between overloads — `param_count=-1` picks the first one,
   which may not be the one called in all damage contexts.
2. The cleaner approach is `PlayerAttributes.SetIsInvincibleByImmortalitySkill(true)` which uses
   the game's own invincibility state — less likely to be flagged.

**Confirmed invincibility path:**
- `PlayerAttributes.SetIsInvincibleByImmortalitySkill(bool)` — toggles invincibility system flag
- `PlayerAttributes.IsInvincible()` — the read gate; returning 1 here would block all damage server-side

---

### 6.4 WallShoot — hook target class wrong (BROKEN)
`applyWallShoot` searches for `CanFire`, `CheckCanFire`, etc. on `VerticleBulletController`.
`VerticleBulletController` only has: `SetData`, `SetEffectData`, `OnRetrunPool`, `OnFixedUpdate`,
`Awake`, `LateUpdate`, and 3 obfuscated methods. None of the searched names exist on it.

**Confirmed actual wall/fire check methods in metadata:**
- `COW-GamePlay-Player-CanFireByCurrentState0` — on Player
- `COW-MatchGame-CanFire0` — on MatchGame
- `COW-UIHudCrosshairsController-CheckIsWallPenetratable0` — HUD wall penetration check

**Fix needed**: Change class target from `VerticleBulletController` to `Player`, method
`CanFireByCurrentState` — return 1 when `s_wall_shoot`. Or hook `MatchGame.CanFire` → return 1.

---

### 6.5 InfiniteAmmo — class resolution wrong (BROKEN / UNCERTAIN)
`get_IsAmmoFree` is resolved on `PlayerAttributes` (`m_cls.Character`). However, the metadata
string `get_IsAmmoFree` appears without a class qualifier. There is no
`COW-GamePlay-PlayerAttributes-get_IsAmmoFree0` entry in the string table. The correct class is
likely `WeaponProperty` or a weapon-specific attributes class.

**Also confirmed in metadata:**
- `EActivityAttchment_InfiniteAmmo` — activity attachment flag for infinite ammo
- `m_InfiniteAmmo` — field name (may be on WeaponPropertyUtil or PlayerAttributes)

**Fix needed**: Resolve `get_IsAmmoFree` with class scan (try `WeaponPropertyUtil` → `PlayerAttributes`
→ `Player` → fallback), or hook `Player.IsReloading` + add ammo count check bypass.

---

### 6.6 AutoRevive — getter hook may not trigger revive (UNCERTAIN)
Current code hooks `Player.get_IsPendingRevive` → return 1. The confirmed metadata method name is
`Player.get_IsKnockDownKeepForwardAsAiming` (which is NOT `get_IsPendingRevive`). The code resolves
`get_IsPendingRevive` which may return null (not in metadata string table).

**Confirmed methods in metadata:**
- `COW-GamePlay-Player-SetIsPendingRevive0` — sets the pending revive state directly
- `COW-GamePlay-Player-UpdatePendingReviveState0` — state machine update
- `COW-GamePlay-Player-StopPendingRevive0` — cancels revive

**Fix needed**: Call `Player.SetIsPendingRevive(true)` from game thread (like outline calls in
`hook_player_update`) for the local player when `s_auto_revive` is active. The getter-hook approach
is backwards — the game reads the state, not our getter.

---

### 6.7 Teleport — uses Transform instead of CharacterController (UNCERTAIN)
Current teleport uses `Transform.set_position` which moves the GameObject but may not update the
internal CharacterController state, causing visual desync or snap-back.

**Confirmed correct method in metadata:**
- `COW-GamePlay-Player-COW.GamePlay.IPhysicalCharacter.APICCTTeleport0` — interface-qualified CCT teleport

**Fix**: Use `APICCTTeleport` interface method instead of raw Transform position setter.
Resolution: `Il2CppApi::getMethod(m_cls.Player, "COW.GamePlay.IPhysicalCharacter.APICCTTeleport", 1)`

---

## 7. VERIFIED METHOD/FIELD TABLE (global-metadata.dat IL2CPP v31)

### Confirmed present (string-verified)

| Symbol | Class (metadata) | Notes |
|---|---|---|
| `GetAttackableCenterWS` | `COW.GamePlay.Player` | M210036, returns Vec3 head-center |
| `GetHeadTF` | `COW.GamePlay.Player` | M210919 — stable head transform |
| `get_HeadBoneTransform` | `COW.GamePlay.Player` | M210320 — skeletal head bone |
| `get_HeadCollider` | `COW.GamePlay.Player` | Real physics hitbox collider |
| `IsLocalPlayer` | `COW.GamePlay.Player` | M210076, param_count=-1 required |
| `SetOutlineVisible` | `COW.GamePlay.Player` | uint8 visible, int mode |
| `InitOutline` | `COW.GamePlay.Player` | Outline init |
| `SetRenderQ` | `COW.GamePlay.Player` | Render queue override |
| `OutlineVisibleJudgeInUpDate` | `COW.GamePlay.Player` | Per-frame visibility judge |
| `SetIsPendingRevive` | `COW.GamePlay.Player` | Sets pending revive state |
| `UpdatePendingReviveState` | `COW.GamePlay.Player` | State machine tick |
| `get_CurHP` / `set_CurHP` | `COW.GamePlay.Player` | Current HP getter/setter |
| `get_MaxHP` / `set_MaxHP` | `COW.GamePlay.Player` | Max HP getter/setter |
| `GetBodyRotation` / `EnableBodyRotation` | `COW.GamePlay.Player` | Anti-aim body rotation |
| `IsReloading` | `COW.GamePlay.Player` | Reload state check |
| `CanFireByCurrentState` | `COW.GamePlay.Player` | Wall shoot gate |
| `APICCTTeleport` | `COW.GamePlay.Player` (IPhysicalCharacter interface) | CCT-safe teleport |
| `IsPlayerHead` | `COW.GamePlay.HitDetectColliderHelper` | REAL headshot gate |
| `GetScatterRate` | `COW.GamePlay.PlayerAttributes` | M245990 — scatter cone computation |
| `set_ScatterMax/Num/Move/Speed/RecoverSpeed` | `COW.GamePlay.PlayerAttributes` | Scatter field setters |
| `IsInvincible` | `COW.GamePlay.PlayerAttributes` | Invincibility gate |
| `SetIsInvincibleByImmortalitySkill` | `COW.GamePlay.PlayerAttributes` | Sets invincibility flag |
| `EnableOutline` | `COW.GamePlay.AvatarOutline` | Outline renderer enable |
| `ShowPlayerOutline` | `COW.MatchGame` | Match-level outline enable |
| `TryInitPlayerOutlineRes` | `COW.MatchGame` | Outline resource init |
| `EnableThroughTeamOutline` | `COW.MatchGame` | Through-wall outline toggle |
| `CanFire` | `COW.MatchGame` | Global fire permission gate |
| `EnableShowPlayerOutline` | `COW.GameSettingData` | Permission flag |
| `EnableShowTeamOutline` | `COW.GameSettingData` | Team outline permission |
| `BindPlayer` | `COW.HUD.UIHudNameEnemyController` | Binds enemy HUD to player |
| `OnVisibilityChanged` | `COW.HUD.UIHudNameEnemyController` | HUD visibility hook target |

### Confirmed ABSENT in this build (OB47)

| Symbol | Notes |
|---|---|
| `CheckDamageHitHead` | Not in metadata — hooks were dead in v2.13 |
| `RecoilFormula` | Not in metadata — hooks were dead in v2.13 |
| `GetRecoilScale` / `CalcRecoil` | Not present |
| `get_IsPendingRevive` | Not confirmed — use `SetIsPendingRevive` instead |

---

## 8. FIX STATUS SUMMARY

| Feature | Status | Issue |
|---|---|---|
| AntiRecoil | ⚠️ Partial | RecoilFormula missing; relies on GetScatterRate hook fallback |
| NoSpread | ✅ Fixed v2.14 | GetScatterRate + ScatterMax/Num hooks |
| RapidFire | ⚠️ Unknown | RateOfFire method not confirmed in binary |
| WidePOV | ✅ Works | Camera.set_fieldOfView — UnityEngine confirmed |
| ESP / Wallhack | ✅ Fixed v2.15 | OutlineJudge + AvatarOutline hooks |
| SpeedHack | ⚠️ Unknown | SetSpecialRunSpeedScale — name not confirmed in metadata |
| HighJump | ⚠️ Unknown | GiveDeltaSpeedScaleByKeyAndValue — name not confirmed |
| VehicleSpeed | ⚠️ Unknown | GetCurrentMaxSpeed — name not confirmed |
| AntiDamage | ✅ Works | TakeDamage no-op (works, any sig) |
| GodMode | ⚠️ Weak | Same as AntiDamage; IsInvincible hook would be stronger |
| MaxHealth | ❌ Broken | Stub only; set_CurHP/set_MaxHP hooks needed |
| InfiniteAmmo | ❌ Broken | get_IsAmmoFree class resolution wrong |
| NoReload | ✅ Likely works | IsReloading confirmed on Player |
| WallShoot | ❌ Broken | VerticleBulletController has no CanFire; use Player.CanFireByCurrentState |
| AutoRevive | ❌ Broken | get_IsPendingRevive not confirmed; use SetIsPendingRevive |
| NoClip | ✅ Correct | OnControllerColliderHit interface method confirmed |
| Teleport | ⚠️ Weak | Transform.set_position works but APICCTTeleport is safer |
| SilentAim | ✅ Fixed v2.14 | GetAttackableCenterWS → head + IsPlayerHead hook |
| AutoHeadshot | ✅ Fixed v2.14 | IsPlayerHead + IsInNoHeadShotState hooks |
| FullAimbot | ✅ Works | UpdateAiming + GetAttackableCenterWS hooks |
| AntiAim | ❌ Broken | Flag set but never read in any hook |
| AutoRevive | ❌ Broken | Getter-hook approach wrong; call SetIsPendingRevive instead |

---
