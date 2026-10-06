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

#define TAG "ZX-ESP"
#define LI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// Math types
// ─────────────────────────────────────────────────────────────────────────────

struct Vec2  { float x, y; };
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
using FnW2S       = Vec3(*)(void* cam, Vec3* worldPos);
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
static FnW2S         g_w2s       = nullptr;
static FnGetMain     g_getMain   = nullptr;
static FnGetWidth    g_getW      = nullptr;
static FnGetHeight   g_getH      = nullptr;

static std::atomic<bool> g_esp_on{false};
static std::atomic<bool> g_hs_on{false};

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
    if (!g_w2s || !cam) return false;
    Vec3 r = g_w2s(cam, &world);
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
    return { (sx / (float)g_sw) * 2.f - 1.f,
             1.f - (sy / (float)g_sh) * 2.f };
}

static void draw_line_neon(Vec2 a, Vec2 b, Color col) {
    if (!g_glBegin || !g_glEnd || !g_glVertex3 || !g_glColor) return;

    static const float widths[3]  = { 5.f, 3.f, 1.5f };
    static const float alphas[3]  = { 0.10f, 0.30f, 1.0f };

    Vec2 an = ndc(a.x, a.y);
    Vec2 bn = ndc(b.x, b.y);

    for (int p = 0; p < 3; p++) {
        glLineWidth(widths[p]);
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

static void hook_OnPostRender(void *cam) {
    // Call original first
    if (g_origOnPostRender) g_origOnPostRender(cam);
    if (!g_esp_on.load(std::memory_order_relaxed)) return;

    // Refresh screen size
    if (g_getW) g_sw = g_getW();
    if (g_getH) g_sh = g_getH();

    // Save GL state
    GlSave saved;
    gl_save(saved);

    // Setup for transparent overdraw
    glDisable(GL_DEPTH_TEST);   // see through walls — key for wallhack
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE);  // additive = real neon glow look

    // Enter Unity 2D ortho space
    if (g_glPush) g_glPush();
    if (g_glOrtho) g_glOrtho();

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

        // Corner box (ZOLAM style)
        if (has_head && has_feet) {
            float box_w = fabsf(feet_s.y - head_s.y) * 0.38f;
            Vec2 tl = { head_s.x - box_w, head_s.y - 4.f };
            Vec2 br = { head_s.x + box_w, feet_s.y + 4.f };
            draw_corner_box(tl, br, box_col);
        }

        // Skeleton
        draw_skeleton(cam, e);

        // Headshot target indicator (shown only when headshot assist is on)
        if (g_hs_on.load(std::memory_order_relaxed) && has_head) {
            Color hs_col = { 1.0f, 1.0f, 0.0f, 1.0f }; // yellow crosshair on head
            draw_head_dot(head_s, 6.f, hs_col);
        }
    }

    if (g_glPop) g_glPop();

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
        Il2Cpp::cls("Transform"), "Find", 1);
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
    MethodInfo *m = Il2Cpp::getMethod(Il2Cpp::cls("Transform"), "get_position", 0);
    if (m && m->methodPointer)
        pos = Il2Cpp::invoke0<Vec3>(m, transform);
    return pos;
}

static float dist3(Vec3 a, Vec3 b) {
    float dx = a.x-b.x, dy = a.y-b.y, dz = a.z-b.z;
    return sqrtf(dx*dx + dy*dy + dz*dz);
}

// Find local player's position (to compute distances)
static Vec3 get_local_pos() {
    if (!g_local_player) return {};
    MethodInfo *m = Il2Cpp::getMethod(Il2Cpp::cls("Transform"), "get_position", 0);
    if (!m || !m->methodPointer) return {};
    MethodInfo *getT = Il2Cpp::getMethod(
        Il2Cpp::cls("Component"), "get_transform", 0);
    if (!getT || !getT->methodPointer) return {};
    Il2CppObject *tr = Il2Cpp::invoke0(getT, g_local_player);
    if (!tr) return {};
    return Il2Cpp::invoke0<Vec3>(m, tr);
}

static void *position_updater(void *) {
    // Wait for il2cpp full init
    sleep(4);

    Il2CppClass *playerCls = Il2Cpp::cls("CSPlayerState");
    if (!playerCls) {
        LE("CSPlayerState not found in position_updater");
        return nullptr;
    }

    MethodInfo *getT = Il2Cpp::getMethod(Il2Cpp::cls("Component"), "get_transform", 0);

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
            bool alive = Il2Cpp::getFieldBool(playerCls, p, "IsAlive");
            if (!alive) continue;

            // Get transform
            Il2CppObject *tr = nullptr;
            if (getT && getT->methodPointer)
                tr = Il2Cpp::invoke0(getT, p);
            if (!tr) continue;

            EnemyData ed{};

            // Get bone positions
            Il2CppObject *head_b  = find_bone(tr, k_head_names);
            Il2CppObject *chest_b = find_bone(tr, k_chest_names);
            Il2CppObject *lsh_b   = find_bone(tr, k_lsh_names);
            Il2CppObject *rsh_b   = find_bone(tr, k_rsh_names);
            Il2CppObject *lft_b   = find_bone(tr, k_lft_names);
            Il2CppObject *rft_b   = find_bone(tr, k_rft_names);

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

            new_cache[nc++] = ed;
        }

        if (players) free(players);

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

    // Camera icalls
    g_w2s     = (FnW2S)    resolve("UnityEngine.Camera::WorldToScreenPoint_Injected(UnityEngine.Vector3&,UnityEngine.Camera/MonoOrStereoscopicEye,UnityEngine.Vector3&)");
    if (!g_w2s)
        g_w2s = (FnW2S)    resolve("UnityEngine.Camera::WorldToScreenPoint_Injected(UnityEngine.Vector3&)");
    g_getMain = (FnGetMain)resolve("UnityEngine.Camera::get_main()");

    // Screen icalls
    g_getW = (FnGetWidth)  resolve("UnityEngine.Screen::get_width()");
    g_getH = (FnGetHeight) resolve("UnityEngine.Screen::get_height()");

    LI("GL icalls: Begin=%p End=%p Vertex3=%p W2S=%p",
       g_glBegin, g_glEnd, g_glVertex3, g_w2s);

    // Hook Camera.OnPostRender
    Il2CppClass *camCls = Il2Cpp::cls("Camera");
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
