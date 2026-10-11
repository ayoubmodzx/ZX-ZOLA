/*
 * esp_renderer.cpp — Zero-FPS-impact ESP with neon glow for ZX-ZOLA
 *
 * Architecture:
 *   • Hook Camera.OnPostRender via IL2CPP method hook — fires AFTER the game
 *     already drew the frame, so zero CPU cost to the game loop
 *   • Draw using pure GLES3 (compiled GLSL shader + VBO) — no Unity GL icalls
 *     that crash on Vulkan/GLES3 builds of Unity 2021.
 *   • Enemy positions cached in a separate background thread (50ms refresh)
 *     so the render hook only reads a pre-built list — no IL2CPP calls per frame
 *   • Neon glow = 3 draw passes with decreasing alpha (additive blending)
 */

#include "esp_renderer.hpp"
#include "il2cpp_scanner.hpp"
#include "dobby_stub.hpp"
#include "zx_logbuf.hpp"

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
#define LI(fmt, ...) LOGBUF_I(TAG, fmt, ##__VA_ARGS__)
#define LE(fmt, ...) LOGBUF_E(TAG, fmt, ##__VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// Math types
// ─────────────────────────────────────────────────────────────────────────────

// Vec2, Vec3, Color from zx_types.hpp (included via esp_renderer.hpp)

// ─────────────────────────────────────────────────────────────────────────────
// Screen-space icall function pointers (world→screen projection + screen size)
// Unity GL icalls (Begin/End/Vertex3/PushMatrix etc.) are intentionally NOT
// used — they crash in Unity 2021 when the active renderer is Vulkan/GLES3.
// ─────────────────────────────────────────────────────────────────────────────

using FnW2S       = Vec3(*)(void* cam, Vec3* worldPos);
using FnW2S_v2    = void(*)(void* cam, Vec3* worldPos, int eye, Vec3* out);
using FnGetMain   = void*(*)();
using FnGetWidth  = int(*)();
using FnGetHeight = int(*)();
using FnCamRender = void(*)(void*, void*);  // Camera.OnPostRender: thisPtr + MethodInfo*

static FnW2S       g_w2s    = nullptr;
static FnW2S_v2    g_w2s_v2 = nullptr;
static FnGetMain   g_getMain = nullptr;
static FnGetWidth  g_getW   = nullptr;
static FnGetHeight g_getH   = nullptr;

static std::atomic<bool> g_esp_on{false};
static std::atomic<bool> g_hs_on{false};
static std::atomic<bool> g_w2s_valid{false};

// Screen size — declared here so gles_flush() can reference them
static int g_sw = 1080, g_sh = 1920;

// ─────────────────────────────────────────────────────────────────────────────
// Pure GLES3 line renderer — compiled shader + VBO, no Unity GL icalls
// ─────────────────────────────────────────────────────────────────────────────

static const char k_vs[] =
    "#version 300 es\n"
    "uniform vec2 u_scr;\n"
    "layout(location=0) in vec2 a_pos;\n"
    "layout(location=1) in vec4 a_col;\n"
    "out vec4 v_col;\n"
    "void main(){\n"
    "  gl_Position=vec4((a_pos.x/u_scr.x)*2.0-1.0,\n"
    "                   1.0-(a_pos.y/u_scr.y)*2.0,0.0,1.0);\n"
    "  v_col=a_col;\n"
    "}\n";

static const char k_fs[] =
    "#version 300 es\n"
    "precision mediump float;\n"
    "in vec4 v_col;\n"
    "out vec4 o;\n"
    "void main(){o=v_col;}\n";

struct LineVtx { float x, y, r, g, b, a; };

static constexpr int MAX_VERTS = 2048;
static LineVtx  s_vbuf[MAX_VERTS];
static int      s_nverts  = 0;
static GLuint   s_vbo     = 0;
static GLuint   s_vao     = 0;
static GLuint   s_prog    = 0;
static GLint    s_u_scr   = -1;
static bool     s_gles_ok = false;

static GLuint compile_shader(GLenum type, const char *src) {
    GLuint s = glCreateShader(type);
    glShaderSource(s, 1, &src, nullptr);
    glCompileShader(s);
    GLint ok = 0;
    glGetShaderiv(s, GL_COMPILE_STATUS, &ok);
    if (!ok) {
        char buf[512];
        glGetShaderInfoLog(s, 512, nullptr, buf);
        LE("shader compile err: %s", buf);
        glDeleteShader(s);
        return 0;
    }
    return s;
}

static void gles_init() {
    if (s_gles_ok) return;
    GLuint vs = compile_shader(GL_VERTEX_SHADER,   k_vs);
    GLuint fs = compile_shader(GL_FRAGMENT_SHADER, k_fs);
    if (!vs || !fs) { glDeleteShader(vs); glDeleteShader(fs); return; }
    s_prog = glCreateProgram();
    glAttachShader(s_prog, vs);
    glAttachShader(s_prog, fs);
    glLinkProgram(s_prog);
    glDeleteShader(vs);
    glDeleteShader(fs);
    GLint ok = 0;
    glGetProgramiv(s_prog, GL_LINK_STATUS, &ok);
    if (!ok) { glDeleteProgram(s_prog); s_prog = 0; LE("shader link failed"); return; }
    s_u_scr = glGetUniformLocation(s_prog, "u_scr");
    glGenBuffers(1, &s_vbo);
    glGenVertexArrays(1, &s_vao);
    glBindVertexArray(s_vao);
    glBindBuffer(GL_ARRAY_BUFFER, s_vbo);
    glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, sizeof(LineVtx), (void*)0);
    glEnableVertexAttribArray(0);
    glVertexAttribPointer(1, 4, GL_FLOAT, GL_FALSE, sizeof(LineVtx), (void*)(2 * sizeof(float)));
    glEnableVertexAttribArray(1);
    glBindVertexArray(0);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
    s_gles_ok = true;
    LI("GLES3 renderer init OK prog=%u vao=%u vbo=%u", s_prog, s_vao, s_vbo);
}

static void gles_push(Vec2 a, Vec2 b, Color c) {
    if (s_nverts + 2 > MAX_VERTS) return;
    s_vbuf[s_nverts++] = { a.x, a.y, c.r, c.g, c.b, c.a };
    s_vbuf[s_nverts++] = { b.x, b.y, c.r, c.g, c.b, c.a };
}

static void gles_flush() {
    if (!s_gles_ok || s_nverts == 0) { s_nverts = 0; return; }
    glUseProgram(s_prog);
    glUniform2f(s_u_scr, (float)g_sw, (float)g_sh);
    glBindVertexArray(s_vao);
    glBindBuffer(GL_ARRAY_BUFFER, s_vbo);
    glBufferData(GL_ARRAY_BUFFER, s_nverts * (GLsizeiptr)sizeof(LineVtx), nullptr,       GL_STREAM_DRAW);
    glBufferData(GL_ARRAY_BUFFER, s_nverts * (GLsizeiptr)sizeof(LineVtx), s_vbuf,        GL_STREAM_DRAW);
    glDrawArrays(GL_LINES, 0, s_nverts);
    glBindVertexArray(0);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
    s_nverts = 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Enemy position cache (background thread, 50ms refresh)
// Render hook reads this list — no IL2CPP calls per frame.
// ─────────────────────────────────────────────────────────────────────────────

static constexpr int MAX_ENM = 20;

struct EnemyData {
    Vec3 head;
    Vec3 neck;
    Vec3 chest;
    Vec3 lshoulder, rshoulder;
    Vec3 lfoot, rfoot;
    Vec3 center;
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

static EnemyData       g_cache[MAX_ENM];
static int             g_cache_n = 0;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static void           *g_local_player = nullptr;

// ─────────────────────────────────────────────────────────────────────────────
// World → Screen projection
// Uses Unity Camera.WorldToScreenPoint_Injected icall — renderer-agnostic.
// Returns false if the point is behind the camera.
// ─────────────────────────────────────────────────────────────────────────────

static bool w2s(void *cam, Vec3 world, Vec2 &out) {
    if (!g_w2s_valid.load(std::memory_order_acquire) || !cam) return false;
    Vec3 r{};
    if (g_w2s_v2) {
        g_w2s_v2(cam, &world, 0, &r);
    } else if (g_w2s) {
        r = g_w2s(cam, &world);
    } else {
        return false;
    }
    if (r.z <= 0.f) return false;
    out.x = r.x;
    out.y = (float)g_sh - r.y;  // Unity Y is bottom-up; flip to top-down
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Neon glow line drawing via GLES3 batch
// 3 alpha passes to simulate glow (outer/mid/core) at additive blend
// ─────────────────────────────────────────────────────────────────────────────

static void draw_line_neon(Vec2 a, Vec2 b, Color col) {
    static const float alphas[3] = { 0.10f, 0.30f, 1.0f };
    for (int p = 0; p < 3; p++) {
        Color c = { col.r, col.g, col.b, col.a * alphas[p] };
        gles_push(a, b, c);
    }
}

static void draw_box_neon(Vec2 tl, Vec2 br, Color col) {
    Vec2 tr = { br.x, tl.y };
    Vec2 bl = { tl.x, br.y };
    draw_line_neon(tl, tr, col);
    draw_line_neon(bl, br, col);
    draw_line_neon(tl, bl, col);
    draw_line_neon(tr, br, col);
}

static void draw_corner_box(Vec2 tl, Vec2 br, Color col) {
    float w = br.x - tl.x;
    float h = br.y - tl.y;
    float cw = w * 0.22f;
    float ch = h * 0.22f;

    Vec2 tr = { br.x, tl.y };
    Vec2 bl = { tl.x, br.y };

    draw_line_neon(tl, {tl.x + cw, tl.y}, col);
    draw_line_neon(tl, {tl.x, tl.y + ch}, col);
    draw_line_neon(tr, {tr.x - cw, tr.y}, col);
    draw_line_neon(tr, {tr.x, tr.y + ch}, col);
    draw_line_neon(bl, {bl.x + cw, bl.y}, col);
    draw_line_neon(bl, {bl.x, bl.y - ch}, col);
    draw_line_neon(br, {br.x - cw, br.y}, col);
    draw_line_neon(br, {br.x, br.y - ch}, col);
}

static void draw_head_dot(Vec2 center, float radius, Color col) {
    draw_line_neon({center.x - radius, center.y}, {center.x + radius, center.y}, col);
    draw_line_neon({center.x, center.y - radius}, {center.x, center.y + radius}, col);
}

static void draw_skeleton(void *cam, const EnemyData &e) {
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
    GLint vao;
    GLint program;
};

static void gl_save(GlSave &s) {
    glGetIntegerv(GL_BLEND_SRC_RGB,       &s.blend_src);
    glGetIntegerv(GL_BLEND_DST_RGB,       &s.blend_dst);
    glGetIntegerv(GL_VERTEX_ARRAY_BINDING, &s.vao);
    glGetIntegerv(GL_CURRENT_PROGRAM,      &s.program);
    s.depth_test = glIsEnabled(GL_DEPTH_TEST);
    s.blend      = glIsEnabled(GL_BLEND);
}

static void gl_restore(const GlSave &s) {
    if (s.depth_test) glEnable(GL_DEPTH_TEST); else glDisable(GL_DEPTH_TEST);
    if (s.blend)      glEnable(GL_BLEND);      else glDisable(GL_BLEND);
    glBlendFunc((GLenum)s.blend_src, (GLenum)s.blend_dst);
    glBindVertexArray(s.vao);
    glUseProgram(s.program);
}

// ─────────────────────────────────────────────────────────────────────────────
// Camera.OnPostRender hook
// ─────────────────────────────────────────────────────────────────────────────

static FnCamRender g_origOnPostRender = nullptr;

static void *s_eglGetCurrentCtxFn = nullptr;
static bool  s_egl_init            = false;

static bool has_egl_context() {
    if (!s_egl_init) {
        s_egl_init = true;
        void *egl = dlopen("libEGL.so", RTLD_LAZY | RTLD_NOLOAD);
        if (egl) s_eglGetCurrentCtxFn = dlsym(egl, "eglGetCurrentContext");
        LI("EGL: lib=%p getCtx=%p", egl, s_eglGetCurrentCtxFn);
    }
    if (!s_eglGetCurrentCtxFn) return false;
    typedef void* (*Fn)();
    return ((Fn)s_eglGetCurrentCtxFn)() != nullptr;
}

static void update_hs_target(void *cam);

static void hook_OnPostRender(void *cam, void *mi) {
    static std::atomic<int> s_call_count{0};
    int n = ++s_call_count;
    if (n <= 3 || (n % 300) == 0) {
        pthread_mutex_lock(&g_mu);
        int cached = g_cache_n;
        pthread_mutex_unlock(&g_mu);
        LI("OnPostRender #%d cam=%p esp_on=%d cache_n=%d w2s_valid=%d",
           n, cam,
           (int)g_esp_on.load(std::memory_order_relaxed),
           cached,
           (int)g_w2s_valid.load(std::memory_order_relaxed));
    }

    if (g_origOnPostRender) g_origOnPostRender(cam, mi);
    if (!g_esp_on.load(std::memory_order_relaxed)) return;

    if (g_getW) { int w = g_getW(); if (w > 0) g_sw = w; }
    if (g_getH) { int h = g_getH(); if (h > 0) g_sh = h; }

    if (!has_egl_context()) {
        if (n <= 3) LI("OnPostRender #%d: no EGL ctx — skipping draw", n);
        update_hs_target(cam);
        return;
    }

    // Compile shader once on first frame with a valid EGL context
    gles_init();
    if (!s_gles_ok) {
        update_hs_target(cam);
        return;
    }

    GlSave saved;
    gl_save(saved);

    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE);
    glDisable(GL_DEPTH_TEST);

    {
        pthread_mutex_lock(&g_mu);
        EnemyData snap[MAX_ENM];
        int snap_n = g_cache_n;
        memcpy(snap, g_cache, sizeof(EnemyData) * (size_t)snap_n);
        pthread_mutex_unlock(&g_mu);

        for (int i = 0; i < snap_n; i++) {
            const EnemyData &e = snap[i];
            if (!e.valid) continue;

            Vec2 head_s, feet_s;
            bool has_head = w2s(cam, e.head,  head_s);
            bool has_feet = w2s(cam, e.lfoot, feet_s);
            if (!has_head && !has_feet) continue;

            Color box_col;
            if (e.dist < 30.f)      box_col = { 1.0f, 0.15f, 0.15f, 1.0f };
            else if (e.dist < 80.f) box_col = { 1.0f, 0.55f, 0.0f,  1.0f };
            else                    box_col = { 0.0f, 0.95f, 1.0f,  1.0f };

            if (has_head && has_feet) {
                float box_w = fabsf(feet_s.y - head_s.y) * 0.38f;
                Vec2 tl = { head_s.x - box_w, head_s.y - 4.f };
                Vec2 br = { head_s.x + box_w, feet_s.y + 4.f };
                draw_box_neon(tl, br, box_col);
            }

            draw_skeleton(cam, e);

            if (g_hs_on.load(std::memory_order_relaxed) && has_head) {
                Color hs_col = { 1.0f, 1.0f, 0.0f, 1.0f };
                draw_head_dot(head_s, 6.f, hs_col);
            }
        }

        update_hs_target(cam);
    }

    gles_flush();
    gl_restore(saved);
}

// ─────────────────────────────────────────────────────────────────────────────
// Background position update thread (50ms refresh)
// ─────────────────────────────────────────────────────────────────────────────

static const char *k_head_names[]  = { "Head","head","Bip001 Head","mixamo:Head","head_jnt","Spine3",nullptr };
static const char *k_chest_names[] = { "Chest","chest","Bip001 Spine2","mixamo:Spine1","spine_03",nullptr };
static const char *k_lsh_names[]   = { "LeftArm","l_arm","Bip001 L Clavicle","mixamo:LeftArm","shoulder_l",nullptr };
static const char *k_rsh_names[]   = { "RightArm","r_arm","Bip001 R Clavicle","mixamo:RightArm","shoulder_r",nullptr };
static const char *k_lft_names[]   = { "LeftFoot","l_foot","Bip001 L Foot","mixamo:LeftFoot","foot_l",nullptr };
static const char *k_rft_names[]   = { "RightFoot","r_foot","Bip001 R Foot","mixamo:RightFoot","foot_r",nullptr };

static MethodInfo *s_mTransformFind = nullptr;
static MethodInfo *s_mGetPosition   = nullptr;
static MethodInfo *s_mGetTransform  = nullptr;

static void resolve_unity_methods() {
    Il2CppClass *trCls  = Il2Cpp::cls("Transform", "UnityEngine");
    Il2CppClass *cmpCls = Il2Cpp::cls("Component", "UnityEngine");
    if (trCls) {
        s_mTransformFind = Il2Cpp::getMethod(trCls, "Find",         1);
        s_mGetPosition   = Il2Cpp::getMethod(trCls, "get_position", 0);
    }
    if (cmpCls) {
        s_mGetTransform = Il2Cpp::getMethod(cmpCls, "get_transform", 0);
    }
    LI("unity methods: Find=%p get_position=%p get_transform=%p",
       s_mTransformFind ? s_mTransformFind->methodPointer : nullptr,
       s_mGetPosition   ? s_mGetPosition->methodPointer   : nullptr,
       s_mGetTransform  ? s_mGetTransform->methodPointer  : nullptr);
}

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
    Il2CppObject *boxed = Il2Cpp::invoke0(s_mGetPosition, transform);
    if (boxed) __builtin_memcpy(&pos, (char*)boxed + sizeof(Il2CppObject), sizeof(Vec3));
    return pos;
}

static float dist3(Vec3 a, Vec3 b) {
    float dx = a.x-b.x, dy = a.y-b.y, dz = a.z-b.z;
    return sqrtf(dx*dx + dy*dy + dz*dz);
}

static Vec3 get_local_pos() {
    if (!g_local_player || !s_mGetTransform || !s_mGetTransform->methodPointer) return {};
    Il2CppObject *tr = Il2Cpp::invoke0(s_mGetTransform, (Il2CppObject*)g_local_player);
    if (!tr) return {};
    return get_position(tr);
}

static void *position_updater(void *) {
    sleep(4);

    Il2CppThread *il2cpp_thr = Il2Cpp::attachThread();
    if (!il2cpp_thr) {
        LE("position_updater: il2cpp_thread_attach failed — ESP cache disabled");
        return nullptr;
    }

    Il2CppClass *playerCls = Il2Cpp::cls("Player", "COW.GamePlay");
    if (!playerCls) playerCls = Il2Cpp::cls("CSPlayerState");
    if (!playerCls) {
        LE("Player class not found — ESP disabled");
        return nullptr;
    }
    LI("position_updater using player class: %s", Il2Cpp::className(playerCls));

    FieldInfo *aliveF = Il2Cpp::getField(playerCls, "IsAlive");
    if (!aliveF) aliveF = Il2Cpp::getField(playerCls, "isAlive");
    int32_t alive_off = aliveF ? Il2Cpp::fieldOffset(aliveF) : -1;

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

    int local_team = -1;
    int cycle = 0;

    while (true) {
        usleep(50000);
        cycle++;

        Il2CppObject **players = nullptr;
        int player_count = 0;

        if (cycle <= 5 || (cycle % 20) == 0)
            LI("updater cycle %d: calling findObjectsOfType", cycle);

        Il2Cpp::findObjectsOfType(playerCls, &players, &player_count);

        if (cycle <= 5 || (cycle % 20) == 0)
            LI("updater cycle %d: findObjectsOfType returned %d players ptr=%p",
               cycle, player_count, players);

        g_local_player = (void*)Il2Cpp::getLocalInstance(playerCls);
        Vec3 local_pos = get_local_pos();
        g_local_world_pos = local_pos;

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

            if (local_team >= 0 && team_off > 0) {
                int32_t pteam = Il2Cpp::readField<int32_t>((void*)p, team_off);
                if (pteam == local_team) continue;
            }

            if (alive_off > 0 && !Il2Cpp::readField<bool>((void*)p, alive_off)) continue;

            if (cycle <= 3 || (cycle % 20) == 0)
                LI("  player[%d]=%p alive OK — calling get_transform", i, p);

            Il2CppObject *tr = nullptr;
            if (s_mGetTransform && s_mGetTransform->methodPointer)
                tr = Il2Cpp::invoke0(s_mGetTransform, p);

            if (cycle <= 3 || (cycle % 20) == 0)
                LI("  player[%d] tr=%p", i, tr);

            if (!tr) continue;

            EnemyData ed{};

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
// Headshot aim assist
// ─────────────────────────────────────────────────────────────────────────────

static std::atomic<bool> g_hs_target_valid{false};
static Vec2              g_hs_target_screen{};
static Vec3              g_hs_world_head{};
static Vec3              g_local_world_pos{};

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
        if (d < best_dist) { best_dist = d; best_pos = s; found = true; g_hs_world_head = g_cache[i].head; }
    }
    pthread_mutex_unlock(&g_mu);

    g_hs_target_valid = found;
    if (found) g_hs_target_screen = best_pos;
}

Vec2 ESP::getHeadTarget()    { return g_hs_target_screen; }
bool ESP::hasHeadTarget()    { return g_hs_target_valid.load(); }
Vec3 ESP::getHeadWorldPos()  { return g_hs_world_head; }
Vec3 ESP::getLocalPos()      { return g_local_world_pos; }

// ─────────────────────────────────────────────────────────────────────────────
// Init — resolve icalls and install Camera hook
// ─────────────────────────────────────────────────────────────────────────────

void ESP::init() {
    static std::atomic<bool> s_done{false};
    if (s_done.exchange(true)) return;

    void *lib = dlopen("libil2cpp.so", RTLD_LAZY | RTLD_NOLOAD);
    if (!lib) { LE("libil2cpp not loaded"); return; }

    using FnResolve = void*(*)(const char*);
    auto resolve = (FnResolve)dlsym(lib, "il2cpp_resolve_icall");
    if (!resolve) { LE("il2cpp_resolve_icall missing"); return; }

    // World-to-screen projection (renderer-agnostic — pure math, no GL context needed)
    g_w2s_v2 = (FnW2S_v2)resolve("UnityEngine.Camera::WorldToScreenPoint_Injected(UnityEngine.Vector3&,UnityEngine.Camera/MonoOrStereoscopicEye,UnityEngine.Vector3&)");
    if (!g_w2s_v2)
        g_w2s = (FnW2S)resolve("UnityEngine.Camera::WorldToScreenPoint_Injected(UnityEngine.Vector3&)");
    if (g_w2s_v2 || g_w2s) g_w2s_valid.store(true, std::memory_order_release);
    g_getMain = (FnGetMain)resolve("UnityEngine.Camera::get_main()");

    // Screen size
    g_getW = (FnGetWidth)  resolve("UnityEngine.Screen::get_width()");
    g_getH = (FnGetHeight) resolve("UnityEngine.Screen::get_height()");

    LI("ESP::init icalls ---");
    LI("  W2S_v1     = %p", g_w2s);
    LI("  W2S_v2     = %p", g_w2s_v2);
    LI("  w2s_valid  = %d", (int)g_w2s_valid.load());
    LI("  get_main   = %p", g_getMain);
    LI("  get_width  = %p", g_getW);
    LI("  get_height = %p", g_getH);

    resolve_unity_methods();

    Il2CppClass *camCls = Il2Cpp::cls("Camera", "UnityEngine");
    LI("ESP::init camCls=%p", camCls);
    if (camCls) {
        MethodInfo *opr = Il2Cpp::getMethod(camCls, "OnPostRender", 0);
        LI("ESP::init OnPostRender method=%p ptr=%p",
           opr, opr ? opr->methodPointer : nullptr);
        if (opr && opr->methodPointer) {
            DobbyHook(opr->methodPointer,
                      (void*)(FnCamRender)hook_OnPostRender,
                      (void**)&g_origOnPostRender);
            LI("Camera.OnPostRender hooked @ %p", opr->methodPointer);
        } else {
            LE("Camera.OnPostRender method not found — rendering hook inactive");
        }
    } else {
        LE("UnityEngine.Camera class not found — rendering hook inactive");
    }

    pthread_t t;
    pthread_create(&t, nullptr, position_updater, nullptr);
    pthread_detach(t);

    LI("ESP renderer init OK");
}

void ESP::setEnabled(bool on)        { g_esp_on.store(on); }
void ESP::setHeadshotAssist(bool on) { g_hs_on.store(on); }
