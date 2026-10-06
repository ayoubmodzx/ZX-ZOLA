#pragma once
#include <string>
#include <vector>
#include <functional>
#include <atomic>

// ZX Menu — rendered as Android system overlay (TYPE_APPLICATION_OVERLAY)
// Zero GL hooks, zero render thread interference
struct ZxFeature {
    std::string  name;
    std::string  category;
    std::atomic<bool> enabled{false};
    std::function<void(bool)> onToggle;  // callback when user toggles

    ZxFeature(std::string n, std::string cat, std::function<void(bool)> cb)
        : name(std::move(n)), category(std::move(cat)), onToggle(std::move(cb)) {}
    ZxFeature(const ZxFeature &) = delete;
    ZxFeature &operator=(const ZxFeature &) = delete;
};

class ZxMenu {
public:
    static ZxMenu &get();

    void init(JNIEnv *env, jobject context);
    void registerFeature(const char *category, const char *name,
                         std::function<void(bool)> callback);
    void show();
    void hide();
    bool isVisible() const;

private:
    ZxMenu() = default;

    JNIEnv   *m_env     = nullptr;
    jobject   m_context = nullptr;
    std::vector<ZxFeature *> m_features;
    std::atomic<bool> m_visible{false};

    // JNI bridge to the overlay Activity
    jclass   m_menuClass  = nullptr;
    jmethodID m_showMethod = nullptr;
    jmethodID m_hideMethod = nullptr;
};
