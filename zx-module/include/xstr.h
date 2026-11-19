#pragma once
#include <cstddef>
#include <cstdint>

template<size_t N>
struct XorLit {
    char enc[N]{};
    static constexpr uint8_t K = 0x5A;
    consteval XorLit(const char (&s)[N]) {
        for (size_t i = 0; i < N; ++i)
            enc[i] = static_cast<char>(s[i] ^ K);
    }
};

template<XorLit V>
inline const char* xdec() {
    static char buf[sizeof(V.enc)];
    static bool once = []() -> bool {
        for (size_t i = 0; i < sizeof(V.enc); ++i)
            buf[i] = static_cast<char>(V.enc[i] ^ XorLit<1>::K);
        return true;
    }();
    (void)once;
    return buf;
}

#define X(s) xdec<XorLit(s)>()
