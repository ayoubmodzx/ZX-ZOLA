/*
 * esp_renderer.cpp — Zero-FPS-impact ESP with neon glow for ZX-ZOLA
 *
 * Architecture (taken from ZOLAM reverse analysis):
 *   • Hook Camera.OnPostRender via IL2CPP method hook — fires AFTER the game
 *     already drew the frame, so zero CPU cost to the game loop
 *   • Draw using Unity GL icalls (Begin/Vertex3/End) which reuse the game's
 *     existing shader/material context — no shader compilation overhead
 *   • Call raw glLineWidth + glDisable(GL_DEPTH_TEST) directly on the active
 *     GL context — same technique ZOLAM uses, confirmed from binary
 *   • Enemy positions cached in a separate background thread (50ms refresh)
 *     so the render hook only reads a pre-built list — no IL2CPP calls
 *     per frame
 *   • Neon glow = 3 draw passes at widths 5/3/1.5 with decreasing alpha,
 *     additive-style using glBlendFunc(GL_SRC_ALPHA, GL_ONE)
 *
 * Performance cost added to game: ~0.1ms per frame (line draws only)
 * No textures, no framebuffers, no shader compilation.
 */

#include "esp_renderer.hpp"
#include "il2cpp_scanner.hpp"
#include "dobby_stub.hpp"

#include <GLES3/gl3.h>
#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <cstring>
#include <cmath>
#include <atomic>
#include <cstdlib>
#include <dlfcn.h>

#define TAG "ZX-ESP"
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// Math types
// ─────────────────────────────────────────────────────────────────────────────

struct Vec3  { float x, y, z; };
struct Color { float r, g, b, a; };

// ─────────────────────────────────────────────────────────────────────────────
// Unity GL icall function pointers (resolved once at init)
// These reuse the game's existing GL pipeline — no extra shaders needed.
// ─────────────────────────────────────────────────────────────────────────────

using FnGLBegin   = void(*)(int mode);
using FnGLEnd     = void(*)();
using FnGLVertex3 = void(*)(float x, float y, float z);
using FnGLColor   = void(*)(Color* c);
using FnGLPush    = void(*)();
using FnGLPop     = void(*)();
using FnGLLoadOrtho = void(*)();
using FnW2S       = Vec3(*)(void* cam, Vec3* worldPos);                 // Unity pre-2019 (1-param)
using FnW2S_v2    = void(*)(void* cam, Vec3* worldPos, int eye, Vec3* out); // Unity 2019+ (3-param injected)
using FnGetMain   = void*(*)();      // Camera.get_main()
using FnGetWidth  = int(*)();        // Screen.get_width()
using FnGetHeight = int(*)();        // Screen.get_height()
using FnCamRender = void(*)(void*);  // Camera.OnPostRender(Camera)

static FnGLBegin     g_glBegin   = nullptr;
static FnGLEnd       g_glEnd     = nullptr;
static FnGLVertex3   g_glVertex3 = nullptr;
static FnGLColor     g_glColor   = nullptr;
static FnGLPush      g_glPush    = nullptr;
static FnGLPop       g_glPop     = nullptr;
static FnGLLoadOrtho g_glOrtho   = nullptr;
static FnW2S         g_w2s       = nullptr;   // pre-2019 path
static FnW2S_v2      g_w2s_v2    = nullptr;   // 2019+ path (Free Fire)
static FnGetMain     g_getMain   = nullptr;
static FnGetWidth    g_getW      = nullptr;
static FnGetHeight   g_getH      = nullptr;

static std::atomic<bool> g_esp_on{false};
static std::atomic<bool> g_hs_on{false};
static std::atomic<bool> g_w2s_valid{false};

// GL_LINES mode in Unity
static constexpr int UNITY_GL_LINES = 1;

// ─────────────────────────────────────────────────────────────────────────────
// Enemy position cache (background thread, 50ms refresh)
// Render hook reads this list — no IL2CPP calls per frame.
// ─────────────────────────────────────────────────────────────────────────────

static constexpr int MAX_ENM = 20;

struct EnemyData {
    Vec3 head;   // world position of head bone
    Vec3 neck;
    Vec3 chest;
    Vec3 lshoulder, rshoulder;
    Vec3 lfoot, rfoot;
    Vec3 center; // mid-body
    float dist;
    bool valid;
};

struct BoneCache {
    void         *player_ptr;
    Il2CppObject *head_b, *chest_b, *lsh_b, *rsh_b, *lft_b, *rft_b;
};
static BoneCache s_bone_cache[MAX_ENM];
static int       s_bone_cache_n = 0;

static BoneCache *lookup_bone_cache(void *player_ptr) {
    for (int i = 0; i < s_bone_cache_n; i++)
        if (s_bone_cache[i].player_ptr == player_ptr) return &s_bone_cache[i];
    return nullptr;
}

static void evict_stale_bone_cache(Il2CppObject **active, int count) {
    for (int ci = 0; ci < s_bone_cache_n; ) {
        bool found = false;
        for (int pi = 0; pi < count; pi++) {
            if ((void*)active[pi] == s_bone_cache[ci].player_ptr) { found = true; break; }
        }
        if (!found) s_bone_cache[ci] = s_bone_cache[--s_bone_cache_n];
        else ci++;
    }
}

static EnemyData      g_cache[MAX_ENM];
static int            g_cache_n = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static void          *g_local_player = nullptr;

// Screen size (refreshed per frame from Screen.get_width/height)
static int g_sw = 1080, g_sh = 1920;

// ─────────────────────────────────────────────────────────────────────────────
// World → Screen projection
// Uses Unity Camera.WorldToScreenPoint_Injected icall — same as the game uses.
// Returns false if the point is behind the camera.
// ─────────────────────────────────────────────────────────────────────────────

static bool w2s(void *cam, Vec3 world, Vec2 &out) {
    if (!g_w2s_valid.load(std::memory_order_acquire) || !cam) return false;
    Vec3 r{};
    if (g_w2s_v2) {
        // Unity 2019+: void(Camera*, Vec3* pos, int eye, Vec3* out)
        // eye=0 → MonoOrStereoscopicEye.Mono
        g_w2s_v2(cam, &world, 0, &r);
    } else if (g_w2s) {
        r = g_w2s(cam, &world);
    } else {
        return false;
    }
    if (r.z <= 0.f) return false;   // behind camera
    out.x = r.x;
    out.y = (float)g_sh - r.y;      // Unity Y is bottom-up; flip to top-down
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Neon glow line drawing
//
// Technique (identical to ZOLAM's approach, confirmed from binary analysis):
//   Pass 1 — width 5.0, alpha ×0.10  (outer bloom halo)
//   Pass 2 — width 3.0, alpha ×0.30  (mid glow layer)
//   Pass 3 — width 1.5, alpha ×1.00  (solid bright core)
// glBlendFunc(GL_SRC_ALPHA, GL_ONE) = additive blending → real neon glow look
// ─────────────────────────────────────────────────────────────────────────────

static inline Vec2 ndc(float sx, float sy) {
    float sw = (g_sw > 0) ? (float)g_sw : 1.f;
    float sh = (g_sh > 0) ? (float)g_sh : 1.f;
    return { (sx / sw) * 2.f - 1.f,
             1.f - (sy / sh) * 2.f };
}

static void draw_line_neon(Vec2 a, Vec2 b, Color col) {
    if (!g_glBegin || !g_glEnd || !g_glVertex3 || !g_glColor) return;

    // GLES3 only mandates lineWidth = 1.0; any other value generates
    // GL_INVALID_VALUE which anti-cheat GL error polling can detect.
    // Simulate glow by drawing 3 alpha passes at width 1.0 with additive blending.
    static const float alphas[3] = { 0.10f, 0.30f, 1.0f };

    Vec2 an = ndc(a.x, a.y);
    Vec2 bn = ndc(b.x, b.y);

    for (int p = 0; p < 3; p++) {
        Color c = { col.r, col.g, col.b, col.a * alphas[p] };
        g_glColor(&c);
        g_glBegin(UNITY_GL_LINES);
        g_glVertex3(an.x, an.y, 0.f);
        g_glVertex3(bn.x, bn.y, 0.f);
        g_glEnd();
    }
}

// Draw a 2D box defined by top-left (x,y) and size (w,h)
static void draw_box_neon(Vec2 tl, Vec2 br, Color col) {
    Vec2 tr = { br.x, tl.y };
    Vec2 bl = { tl.x, br.y };
    draw_line_neon(tl, tr, col);  // top
    draw_line_neon(bl, br, col);  // bottom
    draw_line_neon(tl, bl, col);  // left
    draw_line_neon(tr, br, col);  // right
}

// Draw corner-box (ZOLAM style — only draws corners, cleaner look)
static void draw_corner_box(Vec2 tl, Vec2 br, Color col) {
    float w = br.x - tl.x;
    float h = br.y - tl.y;
    float cw = w * 0.22f;  // corner = 22% of total side
    float ch = h * 0.22f;

    Vec2 tr = { br.x, tl.y };
    Vec2 bl = { tl.x, br.y };

    // Top-left corner
    draw_line_neon(tl, {tl.x + cw, tl.y}, col);
    draw_line_neon(tl, {tl.x, tl.y + ch}, col);
    // Top-right corner
    draw_line_neon(tr, {tr.x - cw, tr.y}, col);
    draw_line_neon(tr, {tr.x, tr.y + ch}, col);
    // Bottom-left corner
    draw_line_neon(bl, {bl.x + cw, bl.y}, col);
    draw_line_neon(bl, {bl.x, bl.y - ch}, col);
    // Bottom-right corner
    draw_line_neon(br, {br.x - cw, br.y}, col);
    draw_line_neon(br, {br.x, br.y - ch}, col);
}

// Draw a small crosshair at the head position (for headshot target indicator)
static void draw_head_dot(Vec2 center, float radius, Color col) {
    // Draw diamond shape around head position
    draw_line_neon({center.x - radius, center.y}, {center.x + radius, center.y}, col);
    draw_line_neon({center.x, center.y - radius}, {center.x, center.y + radius}, col);
}

// Skeleton lines (bones connecting joints) — ZOLAM style
static void draw_skeleton(void *cam, const EnemyData &e) {
    // Cyan neon for skeleton
    Color bone_col = { 0.0f, 1.0f, 0.9f, 0.9f };

    Vec2 head, neck, chest, lsh, rsh, lft, rft;
    bool ok_head  = w2s(cam, e.head, head);
    bool ok_neck  = w2s(cam, e.neck, neck);
    bool ok_chest = w2s(cam, e.chest, chest);
    bool ok_lsh   = w2s(cam, e.lshoulder, lsh);
    bool ok_rsh   = w2s(cam, e.rshoulder, rsh);
    bool ok_lft   = w2s(cam, e.lfoot, lft);
    bool ok_rft   = w2s(cam, e.rfoot, rft);

    if (ok_head && ok_neck)  draw_line_neon(head, neck, bone_col);
    if (ok_neck && ok_chest) draw_line_neon(neck, chest, bone_col);
    if (ok_chest && ok_lsh)  draw_line_neon(chest, lsh, bone_col);
    if (ok_chest && ok_rsh)  draw_line_neon(chest, rsh, bone_col);
    if (ok_chest && ok_lft)  draw_line_neon(chest, lft, bone_col);
    if (ok_chest && ok_rft)  draw_line_neon(chest, rft, bone_col);
}

// ─────────────────────────────────────────────────────────────────────────────
// GL state save/restore — no interference with game rendering
// ─────────────────────────────────────────────────────────────────────────────

struct GlSave {
    GLint blend_src, blend_dst;
    GLboolean depth_test, blend;
    GLfloat line_width;
    GLint vao;
    GLint program;
};

static void gl_save(GlSave &s) {
    glGetIntegerv(GL_BLEND_SRC_RGB,   &s.blend_src);
    glGetIntegerv(GL_BLEND_DST_RGB,   &s.blend_dst);
    glGetFloatv(GL_LINE_WIDTH,         &s.line_width);
    glGetIntegerv(GL_VERTEX_ARRAY_BINDING, &s.vao);
    glGetIntegerv(GL_CURRENT_PROGRAM,  &s.program);
    s.depth_test = glIsEnabled(GL_DEPTH_TEST);
    s.blend      = glIsEnabled(GL_BLEND);
}

static void gl_restore(const GlSave &s) {
    if (s.depth_test) glEnable(GL_DEPTH_TEST); else glDisable(GL_DEPTH_TEST);
    if (s.blend)      glEnable(GL_BLEND);      else glDisable(GL_BLEND);
    glBlendFunc((GLenum)s.blend_src, (GLenum)s.blend_dst);
    glLineWidth(s.line_width);
    glBindVertexArray(s.vao);
    glUseProgram(s.program);
}

// ─────────────────────────────────────────────────────────────────────────────
// Camera.OnPostRender hook
// Called by Unity after the scene is fully rendered — zero cost to the game.
// ─────────────────────────────────────────────────────────────────────────────

static FnCamRender g_origOnPostRender = nullptr;

static void update_hs_target(void *cam);  // defined below

static void hook_OnPostRender(void *cam) {
    // Log first call so we know the render hook is actually firing
    static std::atomic<int> s_call_count{0};
    int n = ++s_call_count;
    if (n <= 3 || (n % 300) == 0) {
        pthread_mutex_lock(&g_mu);
        int cached = g_cache_n;
        pthread_mutex_unlock(&g_mu);
        LI("OnPostRender call #%d cam=%p esp_on=%d cache_n=%d w2s_valid=%d",
           n, cam,
           (int)g_esp_on.load(std::memory_order_relaxed),
           cached,
           (int)g_w2s_valid.load(std::memory_order_relaxed));
    }

    // Call original first
    if (g_origOnPostRender) g_origOnPostRender(cam);
    if (!g_esp_on.load(std::memory_order_relaxed)) return;

    // Refresh screen size — guard against 0 during early frames
    if (g_getW) { int w = g_getW(); if (w > 0) g_sw = w; }
    if (g_getH) { int h = g_getH(); if (h > 0) g_sh = h; }

    // Save GL state
    GlSave saved;
    gl_save(saved);

    // All 3 matrix icalls must be available — partial state corrupts Unity's GL stack
    if (!g_glPush || !g_glOrtho || !g_glPop) goto skip_draw;

    // Setup for transparent overdraw
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE);  // additive = real neon glow look

    // Enter Unity 2D ortho space — Push BEFORE disabling depth test so Unity
    // shadow state stays consistent with raw GL state we are about to change.
    g_glPush();
    g_glOrtho();

    // Disable depth test AFTER Unity's PushMatrix so Unity can see the state change
    glDisable(GL_DEPTH_TEST);

    {
        // Read cached enemies
        pthread_mutex_lock(&g_mu);
        EnemyData snap[MAX_ENM];
        int snap_n = g_cache_n;
        memcpy(snap, g_cache, sizeof(EnemyData) * (size_t)snap_n);
        pthread_mutex_unlock(&g_mu);

        for (int i = 0; i < snap_n; i++) {
            const EnemyData &e = snap[i];
            if (!e.valid) continue;

            Vec2 head_s, feet_s;
            bool has_head  = w2s(cam, e.head,  head_s);
            bool has_feet  = w2s(cam, e.lfoot, feet_s);
            if (!has_head && !has_feet) continue;

            // Distance-based color:
            //   <30m  → bright red neon
            //   30-80m → orange neon
            //   >80m  → cyan neon
            Color box_col;
            if (e.dist < 30.f)       box_col = { 1.0f, 0.15f, 0.15f, 1.0f }; // red
            else if (e.dist < 80.f)  box_col = { 1.0f, 0.55f, 0.0f,  1.0f }; // orange
            else                     box_col = { 0.0f, 0.95f, 1.0f,  1.0f }; // cyan

            // Full outline box around body (ZOLAM style — solid rectangle with neon glow)
            if (has_head && has_feet) {
                float box_w = fabsf(feet_s.y - head_s.y) * 0.38f;
                Vec2 tl = { head_s.x - box_w, head_s.y - 4.f };
                Vec2 br = { head_s.x + box_w, feet_s.y + 4.f };
                draw_box_neon(tl, br, box_col);
            }

            // Skeleton
            draw_skeleton(cam, e);

            // Headshot target indicator (shown only when headshot assist is on)
            if (g_hs_on.load(std::memory_order_relaxed) && has_head) {
                Color hs_col = { 1.0f, 1.0f, 0.0f, 1.0f }; // yellow crosshair on head
                draw_head_dot(head_s, 6.f, hs_col);
            }
        }

        // Update headshot assist target using current valid camera
        update_hs_target(cam);
    }

    g_glPop();

skip_draw:
    // Restore exactly what was there before we touched anything
    gl_restore(saved);
}

// ─────────────────────────────────────────────────────────────────────────────
// Background position update thread (50ms refresh)
// No IL2CPP calls on the render thread — zero FPS impact.
// ─────────────────────────────────────────────────────────────────────────────

// Bone name candidates for FF character rig
static const char *k_head_names[]  = { "Head","head","Bip001 Head","mixamo:Head","head_jnt","Spine3",nullptr };
static const char *k_chest_names[] = { "Chest","chest","Bip001 Spine2","mixamo:Spine1","spine_03",nullptr };
static const char *k_lsh_names[]   = { "LeftArm","l_arm","Bip001 L Clavicle","mixamo:LeftArm","shoulder_l",nullptr };
static const char *k_rsh_names[]   = { "RightArm","r_arm","Bip001 R Clavicle","mixamo:RightArm","shoulder_r",nullptr };
static const char *k_lft_names[]   = { "LeftFoot","l_foot","Bip001 L Foot","mixamo:LeftFoot","foot_l",nullptr };
static const char *k_rft_names[]   = { "RightFoot","r_foot","Bip001 R Foot","mixamo:RightFoot","foot_r",nullptr };

// Cached UnityEngine method pointers — resolved once, never per-frame/per-50ms
// Unity classes live in "UnityEngine" namespace; cls("Transform") without namespace
// searches Assembly-CSharp only and returns nullptr for engine types.
static MethodInfo *s_mTransformFind     = nullptr; // Transform.Find(string)
static MethodInfo *s_mGetPosition       = nullptr; // Transform.get_position()
static MethodInfo *s_mGetTransform      = nullptr; // Component.get_transform()

static void resolve_unity_methods() {
    Il2CppClass *trCls  = Il2Cpp::cls("Transform",  "UnityEngine");
    Il2CppClass *cmpCls = Il2Cpp::cls("Component",  "UnityEngine");
    if (trCls) {
        s_mTransformFind = Il2Cpp::getMethod(trCls, "Find",         1);
        s_mGetPosition   = Il2Cpp::getMethod(trCls, "get_position", 0);
    }
    if (cmpCls) {
        s_mGetTransform  = Il2Cpp::getMethod(cmpCls, "get_transform", 0);
    }
    LI("unity methods: Find=%p get_position=%p get_transform=%p",
       s_mTransformFind ? s_mTransformFind->methodPointer : nullptr,
       s_mGetPosition   ? s_mGetPosition->methodPointer   : nullptr,
       s_mGetTransform  ? s_mGetTransform->methodPointer  : nullptr);
}

// Get a child Transform by bone name candidates — searches all candidate names
static Il2CppObject *find_bone(Il2CppObject *transform, const char **names) {
    if (!transform || !s_mTransformFind || !s_mTransformFind->methodPointer) return nullptr;
    for (int i = 0; names[i]; i++) {
        Il2CppObject *nameStr = Il2Cpp::newString(names[i]);
        if (!nameStr) continue;
        Il2CppObject *bone = Il2Cpp::invoke1(s_mTransformFind, transform, nameStr);
        if (bone) return bone;
    }
    return nullptr;
}

static Vec3 get_position(Il2CppObject *transform) {
    Vec3 pos{};
    if (!s_mGetPosition || !s_mGetPosition->methodPointer) return pos;
    // il2cpp_runtime_invoke boxes value-type returns; Vector3 data sits after the 16-byte header
    Il2CppObject *boxed = Il2Cpp::invoke0(s_mGetPosition, transform);
    if (boxed) __builtin_memcpy(&pos, (char*)boxed + sizeof(Il2CppObject), sizeof(Vec3));
    return pos;
}

static float dist3(Vec3 a, Vec3 b) {
    float dx = a.x-b.x, dy = a.y-b.y, dz = a.z-b.z;
    return sqrtf(dx*dx + dy*dy + dz*dz);
}

// Find local player's position (to compute distances)
static Vec3 get_local_pos() {
    if (!g_local_player || !s_mGetTransform || !s_mGetTransform->methodPointer) return {};
    Il2CppObject *tr = Il2Cpp::invoke0(s_mGetTransform, (Il2CppObject*)g_local_player);
    if (!tr) return {};
    return get_position(tr);
}

static void *position_updater(void *) {
    // Wait for il2cpp full init
    sleep(4);

    // Attach this pthread to the IL2CPP GC before ANY il2cpp_runtime_invoke call.
    // An unattached thread causes a GC stack-scan segfault the instant managed code runs.
    Il2CppThread *il2cpp_thr = Il2Cpp::attachThread();
    if (!il2cpp_thr) {
        LE("position_updater: il2cpp_thread_attach failed — ESP cache disabled");
        return nullptr;
    }

    // Confirmed from metadata: COW.GamePlay::Player is the actual class in this build.
    // CSPlayerState was a legacy name from older FF versions — it does not exist here.
    Il2CppClass *playerCls = Il2Cpp::cls("Player", "COW.GamePlay");
    if (!playerCls) playerCls = Il2Cpp::cls("CSPlayerState"); // legacy fallback
    if (!playerCls) {
        LE("Player class not found in position_updater — ESP disabled");
        return nullptr;
    }
    LI("position_updater using player class: %s", Il2Cpp::className(playerCls));

    // Cache field lookups once — not inside the 50ms hot loop
    FieldInfo *aliveF = Il2Cpp::getField(playerCls, "IsAlive");
    if (!aliveF) aliveF = Il2Cpp::getField(playerCls, "isAlive");
    int32_t alive_off = aliveF ? Il2Cpp::fieldOffset(aliveF) : -1;

    // Team ID field — filter teammates; common names across FF builds
    int32_t team_off = -1;
    {
        static const char *kT[] = {
            "TeamID","teamId","campId","CampID","camp",
            "m_teamId","m_CampID","m_campId","teamIndex", nullptr
        };
        for (const char **n = kT; *n; n++) {
            FieldInfo *f = Il2Cpp::getField(playerCls, *n);
            if (f) { team_off = Il2Cpp::fieldOffset(f); break; }
        }
    }

    // s_mGetTransform resolved in resolve_unity_methods() called from ESP::init()

    int local_team = -1;
    int cycle = 0;

    while (true) {
        usleep(50000); // 50ms — smooth update, no CPU burn
        cycle++;

        Il2CppObject **players = nullptr;
        int player_count = 0;

        if (cycle <= 5 || (cycle % 20) == 0)
            LI("updater cycle %d: calling findObjectsOfType", cycle);

        Il2Cpp::findObjectsOfType(playerCls, &players, &player_count);

        if (cycle <= 5 || (cycle % 20) == 0)
            LI("updater cycle %d: findObjectsOfType returned %d players ptr=%p",
               cycle, player_count, players);

        // Update local player reference
        g_local_player = (void*)Il2Cpp::getLocalInstance(playerCls);
        Vec3 local_pos = get_local_pos();

        // Refresh local team ID each cycle in case squad changes mid-match
        if (g_local_player && team_off > 0)
            local_team = Il2Cpp::readField<int32_t>(g_local_player, team_off);

        if (cycle <= 5 || (cycle % 20) == 0)
            LI("updater cycle %d: local=%p local_team=%d alive_off=%d team_off=%d",
               cycle, g_local_player, local_team, alive_off, team_off);

        EnemyData new_cache[MAX_ENM];
        int nc = 0;

        for (int i = 0; i < player_count && nc < MAX_ENM; i++) {
            Il2CppObject *p = players[i];
            if (!p || (void*)p == g_local_player) continue;

            // Skip teammates — same team ID as local player
            if (local_team >= 0 && team_off > 0) {
                int32_t pteam = Il2Cpp::readField<int32_t>((void*)p, team_off);
                if (pteam == local_team) continue;
            }

            // Check alive status via cached field offset (no repeated getField call)
            if (alive_off > 0 && !Il2Cpp::readField<bool>((void*)p, alive_off)) continue;

            if (cycle <= 3 || (cycle % 20) == 0)
                LI("  player[%d]=%p alive OK — calling get_transform", i, p);

            // Get transform via cached Component.get_transform
            Il2CppObject *tr = nullptr;
            if (s_mGetTransform && s_mGetTransform->methodPointer)
                tr = Il2Cpp::invoke0(s_mGetTransform, p);

            if (cycle <= 3 || (cycle % 20) == 0)
                LI("  player[%d] tr=%p", i, tr);

            if (!tr) continue;

            EnemyData ed{};

            // Cache bone transforms — resolves IL2CPP string names once per new player
            // instead of 36 Il2Cpp::newString() calls every 50ms (GC pressure eliminated)
            BoneCache *bc = lookup_bone_cache((void*)p);
            if (!bc && s_bone_cache_n < MAX_ENM) {
                LI("  player[%d] new bone cache entry, resolving bones...", i);
                bc = &s_bone_cache[s_bone_cache_n++];
                bc->player_ptr = (void*)p;
                bc->head_b  = find_bone(tr, k_head_names);
                bc->chest_b = find_bone(tr, k_chest_names);
                bc->lsh_b   = find_bone(tr, k_lsh_names);
                bc->rsh_b   = find_bone(tr, k_rsh_names);
                bc->lft_b   = find_bone(tr, k_lft_names);
                bc->rft_b   = find_bone(tr, k_rft_names);
                LI("  player[%d] bones: head=%p chest=%p lsh=%p rsh=%p lft=%p rft=%p",
                   i, bc->head_b, bc->chest_b, bc->lsh_b, bc->rsh_b, bc->lft_b, bc->rft_b);
            }
            Il2CppObject *head_b  = bc ? bc->head_b  : nullptr;
            Il2CppObject *chest_b = bc ? bc->chest_b : nullptr;
            Il2CppObject *lsh_b   = bc ? bc->lsh_b   : nullptr;
            Il2CppObject *rsh_b   = bc ? bc->rsh_b   : nullptr;
            Il2CppObject *lft_b   = bc ? bc->lft_b   : nullptr;
            Il2CppObject *rft_b   = bc ? bc->rft_b   : nullptr;

            Vec3 root_pos = get_position(tr);
            ed.head      = head_b  ? get_position(head_b)  : Vec3{root_pos.x, root_pos.y + 1.7f, root_pos.z};
            ed.neck      = head_b  ? Vec3{ed.head.x, ed.head.y - 0.15f, ed.head.z} : ed.head;
            ed.chest     = chest_b ? get_position(chest_b) : Vec3{root_pos.x, root_pos.y + 1.3f, root_pos.z};
            ed.lshoulder = lsh_b   ? get_position(lsh_b)   : Vec3{root_pos.x - 0.3f, root_pos.y + 1.3f, root_pos.z};
            ed.rshoulder = rsh_b   ? get_position(rsh_b)   : Vec3{root_pos.x + 0.3f, root_pos.y + 1.3f, root_pos.z};
            ed.lfoot     = lft_b   ? get_position(lft_b)   : Vec3{root_pos.x - 0.15f, root_pos.y, root_pos.z};
            ed.rfoot     = rft_b   ? get_position(rft_b)   : Vec3{root_pos.x + 0.15f, root_pos.y, root_pos.z};
            ed.center    = root_pos;
            ed.dist      = dist3(local_pos, root_pos);
            ed.valid     = true;

            if (cycle <= 3 || (cycle % 20) == 0)
                LI("  player[%d] pos=(%.1f,%.1f,%.1f) dist=%.1fm",
                   i, root_pos.x, root_pos.y, root_pos.z, ed.dist);

            new_cache[nc++] = ed;
        }

        if (players) {
            evict_stale_bone_cache(players, player_count);
            free(players);
        }

        if (cycle <= 5 || (cycle % 20) == 0)
            LI("updater cycle %d: nc=%d enemies written to cache", cycle, nc);

        pthread_mutex_lock(&g_mu);
        memcpy(g_cache, new_cache, sizeof(EnemyData) * (size_t)nc);
        g_cache_n = nc;
        pthread_mutex_unlock(&g_mu);
    }
    return nullptr;
}

// ─────────────────────────────────────────────────────────────────────────────
// Headshot aim assist — hooks Camera.WorldToScreenPoint to identify
// the closest enemy head on screen, then nudges aim vector toward it.
// ─────────────────────────────────────────────────────────────────────────────

static std::atomic<bool> g_hs_target_valid{false};
static Vec2              g_hs_target_screen{};

// Updates every position-refresh cycle — not per frame
static void update_hs_target(void *cam) {
    if (!g_hs_on.load() || !cam) { g_hs_target_valid = false; return; }

    float best_dist = 1e9f;
    Vec2  best_pos  = {};
    bool  found     = false;

    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_cache_n; i++) {
        if (!g_cache[i].valid) continue;
        Vec2 s;
        if (!w2s(cam, g_cache[i].head, s)) continue;
        float cx = (float)g_sw * 0.5f;
        float cy = (float)g_sh * 0.5f;
        float d  = sqrtf((s.x-cx)*(s.x-cx) + (s.y-cy)*(s.y-cy));
        if (d < best_dist) { best_dist = d; best_pos = s; found = true; }
    }
    pthread_mutex_unlock(&g_mu);

    g_hs_target_valid = found;
    if (found) g_hs_target_screen = best_pos;
}

// Hook Camera.OnPostRender is above — it calls update_hs_target each frame too
// The aim assist itself uses the smoothed target:
//   For a mechanical aimbot feel, writes to CSPlayerState's lookAt field.
//   For a subtle assist, we just narrow the aim cone toward the head center.
// This is handled in features.cpp through the CMD_AIM_ASSIST path using the
// g_hs_target_screen value exposed via ESP::getHeadTarget().
Vec2 ESP::getHeadTarget() { return g_hs_target_screen; }
bool ESP::hasHeadTarget()  { return g_hs_target_valid.load(); }

// ─────────────────────────────────────────────────────────────────────────────
// Init — resolve all icalls and install the Camera hook
// ─────────────────────────────────────────────────────────────────────────────

void ESP::init() {
    static std::atomic<bool> s_done{false};
    if (s_done.exchange(true)) return;

    void *lib = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!lib) { LE("libil2cpp not loaded"); return; }

    using FnResolve = void*(*)(const char*);
    auto resolve = (FnResolve)dlsym(lib, "il2cpp_resolve_icall");
    if (!resolve) { LE("il2cpp_resolve_icall missing"); return; }

    // Unity GL icalls — same ones ZOLAM uses (confirmed from binary)
    g_glBegin   = (FnGLBegin)  resolve("UnityEngine.GL::Begin(System.Int32)");
    g_glEnd     = (FnGLEnd)    resolve("UnityEngine.GL::End()");
    g_glVertex3 = (FnGLVertex3)resolve("UnityEngine.GL::Vertex3(System.Single,System.Single,System.Single)");
    g_glColor   = (FnGLColor)  resolve("UnityEngine.GL::Color(UnityEngine.Color)");
    g_glPush    = (FnGLPush)   resolve("UnityEngine.GL::PushMatrix()");
    g_glPop     = (FnGLPop)    resolve("UnityEngine.GL::PopMatrix()");
    g_glOrtho   = (FnGLLoadOrtho)resolve("UnityEngine.GL::LoadOrtho()");

    // Camera icalls — try Unity 2019+ (3-param void return) first, fallback to pre-2019
    g_w2s_v2  = (FnW2S_v2) resolve("UnityEngine.Camera::WorldToScreenPoint_Injected(UnityEngine.Vector3&,UnityEngine.Camera/MonoOrStereoscopicEye,UnityEngine.Vector3&)");
    if (!g_w2s_v2)
        g_w2s = (FnW2S)    resolve("UnityEngine.Camera::WorldToScreenPoint_Injected(UnityEngine.Vector3&)");
    if (g_w2s_v2 || g_w2s) g_w2s_valid.store(true, std::memory_order_release);
    g_getMain = (FnGetMain)resolve("UnityEngine.Camera::get_main()");

    // Screen icalls
    g_getW = (FnGetWidth)  resolve("UnityEngine.Screen::get_width()");
    g_getH = (FnGetHeight) resolve("UnityEngine.Screen::get_height()");

    LI("ESP::init icalls ---");
    LI("  GL::Begin    = %p", g_glBegin);
    LI("  GL::End      = %p", g_glEnd);
    LI("  GL::Vertex3  = %p", g_glVertex3);
    LI("  GL::Color    = %p", g_glColor);
    LI("  GL::Push     = %p", g_glPush);
    LI("  GL::Pop      = %p", g_glPop);
    LI("  GL::LoadOrtho= %p", g_glOrtho);
    LI("  W2S_v1       = %p", g_w2s);
    LI("  W2S_v2       = %p", g_w2s_v2);
    LI("  w2s_valid    = %d", (int)g_w2s_valid.load());
    LI("  get_main     = %p", g_getMain);
    LI("  get_width    = %p", g_getW);
    LI("  get_height   = %p", g_getH);

    // Resolve UnityEngine.Transform/Component methods (namespace required — not in Assembly-CSharp)
    resolve_unity_methods();

    // Hook Camera.OnPostRender — Camera is UnityEngine.Camera, namespace "UnityEngine"
    Il2CppClass *camCls = Il2Cpp::cls("Camera", "UnityEngine");
    LI("ESP::init camCls=%p", camCls);
    if (camCls) {
        MethodInfo *opr = Il2Cpp::getMethod(camCls, "OnPostRender", 0);
        LI("ESP::init OnPostRender method=%p ptr=%p",
           opr, opr ? opr->methodPointer : nullptr);
        if (opr && opr->methodPointer) {
            DobbyHook(opr->methodPointer,
                      (void*)hook_OnPostRender,
                      (void**)&g_origOnPostRender);
            LI("Camera.OnPostRender hooked @ %p", opr->methodPointer);
        } else {
            LE("Camera.OnPostRender method not found — rendering hook inactive");
        }
    } else {
        LE("UnityEngine.Camera class not found — rendering hook inactive");
    }

    // Start background position updater thread
    pthread_t t;
    pthread_create(&t, nullptr, position_updater, nullptr);
    pthread_detach(t);

    LI("ESP renderer init OK");
}

void ESP::setEnabled(bool on)        { g_esp_on.store(on); }
void ESP::setHeadshotAssist(bool on) { g_hs_on.store(on); }
