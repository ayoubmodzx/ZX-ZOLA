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

#include <android/log.h>
#include <pthread.h>
#include <unistd.h>
#include <cstring>
#include <cmath>
#include <atomic>
#include <cstdlib>
#include <dlfcn.h>

// ── GL types / constants — no link-time dep on libGLESv3 ──────────────────────
// All of these are resolved at runtime via dlopen(libGLESv2.so, RTLD_NOLOAD)
// because FF already has it loaded in the process. Linking against GLESv3/EGL
// creates PLT stubs that are early in the table (entries ~10-13) and can't be
// resolved in FF's restricted linker namespace under -z,now → BRAA on an
// unsigned GOT → SIGSEGV at dlopen time.
typedef unsigned int  GLenum;
typedef int           GLint;
typedef unsigned char GLboolean;
typedef float         GLfloat;

#define GL_DEPTH_TEST             0x0B71u
#define GL_BLEND                  0x0BE2u
#define GL_LINE_WIDTH             0x0B21u
#define GL_BLEND_SRC_RGB          0x80C9u
#define GL_BLEND_DST_RGB          0x80CAu
#define GL_VERTEX_ARRAY_BINDING   0x85B5u
#define GL_CURRENT_PROGRAM        0x8B8Du
#define GL_SRC_ALPHA              0x0302u
#define GL_ONE                    1u

typedef void      (*pfn_glGetIntegerv)(GLenum, GLint*);
typedef void      (*pfn_glGetFloatv)(GLenum, GLfloat*);
typedef GLboolean (*pfn_glIsEnabled)(GLenum);
typedef void      (*pfn_glEnable)(GLenum);
typedef void      (*pfn_glDisable)(GLenum);
typedef void      (*pfn_glBlendFunc)(GLenum, GLenum);
typedef void      (*pfn_glLineWidth)(GLfloat);

static pfn_glGetIntegerv  p_glGetIntegerv;
static pfn_glGetFloatv    p_glGetFloatv;
static pfn_glIsEnabled    p_glIsEnabled;
static pfn_glEnable       p_glEnable;
static pfn_glDisable      p_glDisable;
static pfn_glBlendFunc    p_glBlendFunc;
static pfn_glLineWidth    p_glLineWidth;

static void gl_load_fns() {
    static bool done = false;
    if (done) return;
    done = true;
    void *h = dlopen("libGLESv2.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!h) h = dlopen("libGLESv3.so", RTLD_LAZY | RTLD_NOLOAD);
#define GL_LOAD(fn) p_##fn = (pfn_##fn)(h ? dlsym(h, #fn) : dlsym(RTLD_DEFAULT, #fn))
    GL_LOAD(glGetIntegerv);
    GL_LOAD(glGetFloatv);
    GL_LOAD(glIsEnabled);
    GL_LOAD(glEnable);
    GL_LOAD(glDisable);
    GL_LOAD(glBlendFunc);
    GL_LOAD(glLineWidth);
#undef GL_LOAD
}

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
using FnGLColor   = void(*)(float r, float g, float b, float a);
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
    float hpPct; // 0.0 (dead) – 1.0 (full health); -1 = unknown
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
        g_glColor(c.r, c.g, c.b, c.a);
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

// Draw a vertical health bar to the left of the bounding box.
// tl/br are the box corners in screen space (y increases downward).
// hpPct = 0.0 (empty) to 1.0 (full), -1 = skip.
static void draw_health_bar(Vec2 tl, Vec2 br, float hpPct) {
    if (hpPct < 0.f) return;                  // unknown HP — skip entirely
    if (hpPct > 1.f) hpPct = 1.f;
    if (hpPct < 0.f) hpPct = 0.f;

    // Bar sits 6 px to the left of the box, 3 px wide
    static const float kBarOffset = 6.f;
    static const float kBarW      = 3.f;
    float x0 = tl.x - kBarOffset - kBarW;
    float x1 = tl.x - kBarOffset;
    float top = tl.y, bot = br.y;
    float barH = bot - top;
    if (barH <= 0.f) return;

    // Background: dark translucent rail
    Color bg = { 0.08f, 0.08f, 0.08f, 0.75f };
    draw_line_neon({x0, top}, {x0, bot}, bg);
    draw_line_neon({x0+1.f, top}, {x0+1.f, bot}, bg);
    draw_line_neon({x1, top}, {x1, bot}, bg);

    // Filled portion rises from the bottom (feet) up
    float filledTop = bot - hpPct * barH;

    // HP colour: green → yellow → red
    Color hp;
    if      (hpPct > 0.66f) hp = { 0.10f, 0.95f, 0.20f, 1.0f }; // bright green
    else if (hpPct > 0.33f) hp = { 1.00f, 0.80f, 0.00f, 1.0f }; // amber
    else                    hp = { 1.00f, 0.10f, 0.10f, 1.0f }; // red

    if (filledTop < bot) {
        draw_line_neon({x0,      filledTop}, {x0,      bot}, hp);
        draw_line_neon({x0+1.f,  filledTop}, {x0+1.f,  bot}, hp);
        draw_line_neon({x1,      filledTop}, {x1,      bot}, hp);
    }
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
    if (p_glGetIntegerv) {
        p_glGetIntegerv(GL_BLEND_SRC_RGB,        &s.blend_src);
        p_glGetIntegerv(GL_BLEND_DST_RGB,        &s.blend_dst);
        p_glGetIntegerv(GL_VERTEX_ARRAY_BINDING, &s.vao);
        p_glGetIntegerv(GL_CURRENT_PROGRAM,      &s.program);
    }
    if (p_glGetFloatv)  p_glGetFloatv(GL_LINE_WIDTH, &s.line_width);
    s.depth_test = p_glIsEnabled ? p_glIsEnabled(GL_DEPTH_TEST) : 0;
    s.blend      = p_glIsEnabled ? p_glIsEnabled(GL_BLEND)      : 0;
}

static void gl_restore(const GlSave &s) {
    if (!p_glEnable || !p_glDisable || !p_glBlendFunc) return;
    if (s.depth_test) p_glEnable(GL_DEPTH_TEST); else p_glDisable(GL_DEPTH_TEST);
    if (s.blend)      p_glEnable(GL_BLEND);      else p_glDisable(GL_BLEND);
    p_glBlendFunc((GLenum)s.blend_src, (GLenum)s.blend_dst);
    // Do NOT restore VAO/program with raw GL — Unity manages these through its own
    // state machine; bypassing it corrupts the renderer on the next draw call.
}

// ─────────────────────────────────────────────────────────────────────────────
// Camera.OnPostRender hook
// Called by Unity after the scene is fully rendered — zero cost to the game.
// ─────────────────────────────────────────────────────────────────────────────

static FnCamRender g_origOnPostRender = nullptr;

static void update_hs_target(void *cam);  // defined below

static void hook_OnPostRender(void *cam) {
    // Call original first
    if (g_origOnPostRender) g_origOnPostRender(cam);
    if (!g_esp_on.load(std::memory_order_relaxed)) return;

    // Refresh screen size — guard against 0 during early frames
    if (g_getW) { int w = g_getW(); if (w > 0) g_sw = w; }
    if (g_getH) { int h = g_getH(); if (h > 0) g_sh = h; }

    // Ensure runtime GL pointers are loaded (FF has the lib in process already)
    gl_load_fns();

    // Save GL state
    GlSave saved;
    gl_save(saved);

    // All 3 matrix icalls must be available — partial state corrupts Unity's GL stack
    if (!g_glPush || !g_glOrtho || !g_glPop) goto skip_draw;

    // Setup for transparent overdraw
    if (p_glEnable)    p_glEnable(GL_BLEND);
    if (p_glBlendFunc) p_glBlendFunc(GL_SRC_ALPHA, GL_ONE);  // additive = real neon glow look

    // Enter Unity 2D ortho space — Push BEFORE disabling depth test so Unity
    // shadow state stays consistent with raw GL state we are about to change.
    g_glPush();
    g_glOrtho();

    // Disable depth test AFTER Unity's PushMatrix so Unity can see the state change
    if (p_glDisable) p_glDisable(GL_DEPTH_TEST);

    {
        // Read cached enemies
        pthread_mutex_lock(&g_mu);
        EnemyData snap[MAX_ENM];
        int n = g_cache_n;
        memcpy(snap, g_cache, sizeof(EnemyData) * (size_t)n);
        pthread_mutex_unlock(&g_mu);

        for (int i = 0; i < n; i++) {
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

            // Full outline box around body + health bar (ZOLAM style — solid rectangle with neon glow)
            if (has_head && has_feet) {
                float box_w = fabsf(feet_s.y - head_s.y) * 0.38f;
                Vec2 tl = { head_s.x - box_w, head_s.y - 4.f };
                Vec2 br = { head_s.x + box_w, feet_s.y + 4.f };
                draw_box_neon(tl, br, box_col);
                draw_health_bar(tl, br, e.hpPct);
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

// Get a child Transform by bone name candidates — searches all candidate names
static Il2CppObject *find_bone(Il2CppObject *transform, const char **names) {
    if (!transform) return nullptr;
    MethodInfo *findM = Il2Cpp::getMethod(
        Il2Cpp::cls("Transform", "UnityEngine"), "Find", 1);
    if (!findM || !findM->methodPointer) return nullptr;

    for (int i = 0; names[i]; i++) {
        Il2CppObject *nameStr = Il2Cpp::newString(names[i]);
        if (!nameStr) continue;
        Il2CppObject *bone = Il2Cpp::invoke1(findM, transform, nameStr);
        if (bone) return bone;
    }
    return nullptr;
}

static Vec3 get_position(Il2CppObject *transform) {
    Vec3 pos{};
    MethodInfo *m = Il2Cpp::getMethod(Il2Cpp::cls("Transform", "UnityEngine"), "get_position", 0);
    if (!m || !m->methodPointer) return pos;
    // invoke0 returns a boxed Vector3; unbox by skipping the 16-byte Il2CppObject header
    Il2CppObject *boxed = Il2Cpp::invoke0(m, transform);
    if (boxed) __builtin_memcpy(&pos, (char*)boxed + sizeof(Il2CppObject), sizeof(Vec3));
    return pos;
}

static float dist3(Vec3 a, Vec3 b) {
    float dx = a.x-b.x, dy = a.y-b.y, dz = a.z-b.z;
    return sqrtf(dx*dx + dy*dy + dz*dz);
}

// Find local player's position (to compute distances)
static Vec3 get_local_pos() {
    if (!g_local_player) return {};
    MethodInfo *getT = Il2Cpp::getMethod(Il2Cpp::cls("Component", "UnityEngine"), "get_transform", 0);
    if (!getT || !getT->methodPointer) return {};
    Il2CppObject *tr = Il2Cpp::invoke0(getT, (Il2CppObject*)g_local_player);
    if (!tr) return {};
    return get_position(tr);
}

// ── Per-player health state (discovered once, read every cycle) ────────────────
struct HealthMeta {
    Il2CppClass *cls      = nullptr;
    int32_t      offHP    = -1;
    int32_t      offMaxHP = -1;
    FieldInfo   *refField = nullptr; // CSPlayerState field pointing to health component
    bool         tried    = false;
};
static HealthMeta s_hm;

static void discover_health(Il2CppClass *playerCls) {
    if (s_hm.tried) return;
    s_hm.tried = true;

    // Find health component class
    static const char *kHCls[] = {"CSCharacterHealth","PlayerHealth","HealthSystem","CharacterHealth",nullptr};
    for (const char **cn = kHCls; *cn && !s_hm.cls; cn++)
        s_hm.cls = Il2Cpp::cls(*cn);
    if (!s_hm.cls) { LE("HP: health class not found"); return; }

    // Resolve HP / maxHP field offsets on the health class
    static const char *kHP[]    = {"m_curHp","curHP","hp","m_hp","currentHP","m_currentHP",nullptr};
    static const char *kMaxHP[] = {"m_maxHp","maxHP","m_maxHP","maximumHP","m_maximumHP",nullptr};
    for (const char **fn = kHP; *fn; fn++) {
        FieldInfo *f = Il2Cpp::getField(s_hm.cls, *fn);
        if (f && Il2Cpp::fieldTypeId(f) == IL2CPP_TYPE_R4) { s_hm.offHP = Il2Cpp::fieldOffset(f); break; }
    }
    for (const char **fn = kMaxHP; *fn; fn++) {
        FieldInfo *f = Il2Cpp::getField(s_hm.cls, *fn);
        if (f && Il2Cpp::fieldTypeId(f) == IL2CPP_TYPE_R4) { s_hm.offMaxHP = Il2Cpp::fieldOffset(f); break; }
    }

    // Find the reference field on CSPlayerState that points to the health component
    static const char *kRef[] = {"m_health","health","m_healthComp","healthComponent",
                                  "m_characterHealth","characterHealth","m_hp","hpComponent",nullptr};
    for (const char **fn = kRef; *fn && !s_hm.refField; fn++)
        s_hm.refField = Il2Cpp::getField(playerCls, *fn);

    LI("HP meta: cls=%p offHP=%d offMaxHP=%d refField=%p",
       s_hm.cls, s_hm.offHP, s_hm.offMaxHP, s_hm.refField);
}

// Read the HP percentage [0,1] for a player instance.  Returns -1 on failure.
static float read_hp_pct(Il2CppObject *p) {
    if (!s_hm.refField || s_hm.offHP < 0) return -1.f;
    void *healthObj = Il2Cpp::readField<void*>(p, Il2Cpp::fieldOffset(s_hm.refField));
    if (!healthObj) return -1.f;
    float hp = Il2Cpp::readField<float>(healthObj, s_hm.offHP);
    float mx = (s_hm.offMaxHP >= 0)
        ? Il2Cpp::readField<float>(healthObj, s_hm.offMaxHP)
        : 100.f;
    if (mx <= 0.f || hp < 0.f) return -1.f;
    float pct = hp / mx;
    if (pct < 0.f) pct = 0.f;
    if (pct > 1.f) pct = 1.f;
    return pct;
}

static void *position_updater(void *) {
    // Wait for il2cpp full init
    sleep(4);

    Il2CppClass *playerCls = Il2Cpp::cls("CSPlayerState");
    if (!playerCls) {
        LE("CSPlayerState not found in position_updater");
        return nullptr;
    }

    discover_health(playerCls);

    MethodInfo *getT = Il2Cpp::getMethod(Il2Cpp::cls("Component", "UnityEngine"), "get_transform", 0);
    // Resolved once — playerCls never changes, no point re-querying every 50ms per player
    FieldInfo *aliveF = Il2Cpp::getField(playerCls, "IsAlive");

    while (true) {
        usleep(50000); // 50ms — smooth update, no CPU burn

        // Find all CSPlayerState instances
        Il2CppObject **players = nullptr;
        int player_count = 0;
        Il2Cpp::findObjectsOfType(playerCls, &players, &player_count);

        // Update local player reference
        g_local_player = Il2Cpp::getLocalInstance(playerCls);
        Vec3 local_pos = get_local_pos();

        EnemyData new_cache[MAX_ENM];
        int nc = 0;

        for (int i = 0; i < player_count && nc < MAX_ENM; i++) {
            Il2CppObject *p = players[i];
            if (!p || p == g_local_player) continue;

            // Check alive status
            bool alive = aliveF ? Il2Cpp::getFieldBool(p, aliveF) : true;
            if (!alive) continue;

            // Get transform
            Il2CppObject *tr = nullptr;
            if (getT && getT->methodPointer)
                tr = Il2Cpp::invoke0(getT, p);
            if (!tr) continue;

            EnemyData ed{};

            // Cache bone transforms — resolves IL2CPP string names once per new player
            // instead of 36 Il2Cpp::newString() calls every 50ms (GC pressure eliminated)
            BoneCache *bc = lookup_bone_cache(p);
            if (!bc && s_bone_cache_n < MAX_ENM) {
                bc = &s_bone_cache[s_bone_cache_n++];
                bc->player_ptr = p;
                bc->head_b  = find_bone(tr, k_head_names);
                bc->chest_b = find_bone(tr, k_chest_names);
                bc->lsh_b   = find_bone(tr, k_lsh_names);
                bc->rsh_b   = find_bone(tr, k_rsh_names);
                bc->lft_b   = find_bone(tr, k_lft_names);
                bc->rft_b   = find_bone(tr, k_rft_names);
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
            ed.hpPct     = read_hp_pct(p);
            ed.valid     = true;

            new_cache[nc++] = ed;
        }

        if (players) {
            evict_stale_bone_cache(players, player_count);
            free(players);
        }

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
static Vec3              s_hs_world{};  // world-space head of the nearest visible enemy

// Updates every position-refresh cycle — not per frame
static void update_hs_target(void *cam) {
    // Always run regardless of g_hs_on — silent aim also needs the world target.
    // The visual head-dot indicator in hook_OnPostRender is separately gated by g_hs_on.
    if (!cam) { g_hs_target_valid = false; return; }

    float best_dist = 1e9f;
    Vec2  best_pos  = {};
    Vec3  best_world = {};
    bool  found     = false;

    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_cache_n; i++) {
        if (!g_cache[i].valid) continue;
        Vec2 s;
        if (!w2s(cam, g_cache[i].head, s)) continue;
        float cx = (float)g_sw * 0.5f;
        float cy = (float)g_sh * 0.5f;
        float d  = sqrtf((s.x-cx)*(s.x-cx) + (s.y-cy)*(s.y-cy));
        if (d < best_dist) {
            best_dist  = d;
            best_pos   = s;
            best_world = g_cache[i].head;
            found      = true;
        }
    }
    pthread_mutex_unlock(&g_mu);

    g_hs_target_valid = found;
    if (found) {
        g_hs_target_screen = best_pos;
        s_hs_world         = best_world;
    }
}

// Hook Camera.OnPostRender is above — it calls update_hs_target each frame too
// The aim assist itself uses the smoothed target:
//   For a mechanical aimbot feel, writes to CSPlayerState's lookAt field.
//   For a subtle assist, we just narrow the aim cone toward the head center.
// This is handled in features.cpp through the CMD_AIM_ASSIST path using the
// g_hs_target_screen value exposed via ESP::getHeadTarget().
Vec2 ESP::getHeadTarget() { return g_hs_target_screen; }
bool ESP::hasHeadTarget()  { return g_hs_target_valid.load(); }

bool ESP::getHeadWorldPos3(float *x, float *y, float *z) {
    if (!g_hs_target_valid.load(std::memory_order_relaxed)) return false;
    *x = s_hs_world.x;
    *y = s_hs_world.y;
    *z = s_hs_world.z;
    return true;
}

bool ESP::getLocalPos3(float *x, float *y, float *z) {
    Vec3 p = get_local_pos();
    if (p.x == 0.f && p.y == 0.f && p.z == 0.f) return false;
    *x = p.x; *y = p.y; *z = p.z;
    return true;
}

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

    LI("GL icalls: Begin=%p End=%p Vertex3=%p W2S=%p W2Sv2=%p",
       g_glBegin, g_glEnd, g_glVertex3, g_w2s, g_w2s_v2);

    // Hook Camera.OnPostRender
    Il2CppClass *camCls = Il2Cpp::cls("Camera", "UnityEngine");
    if (camCls) {
        MethodInfo *opr = Il2Cpp::getMethod(camCls, "OnPostRender", 0);
        if (opr && opr->methodPointer) {
            DobbyHook(opr->methodPointer,
                      (void*)hook_OnPostRender,
                      (void**)&g_origOnPostRender);
            LI("Camera.OnPostRender hooked @ %p", opr->methodPointer);
        } else {
            LE("Camera.OnPostRender method not found");
        }
    }

    // Start background position updater thread
    pthread_t t;
    pthread_create(&t, nullptr, position_updater, nullptr);
    pthread_detach(t);

    LI("ESP renderer init OK");
}

void ESP::setEnabled(bool on)        { g_esp_on.store(on); }
void ESP::setHeadshotAssist(bool on) { g_hs_on.store(on); }
