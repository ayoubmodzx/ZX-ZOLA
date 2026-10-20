// zx_client — root binary that controls Zygisk module via Unix socket
// Replaces ptrace injector: no injection, no ptrace, just IPC.
//
// Usage: zx_client <cmd> <enable> [intensity]
//   cmd       — ZxCmd enum value (1-16)
//   enable    — 1 = on, 0 = off
//   intensity — optional float (multiplier, angle, etc.)
//
// Or: zx_client --loop   (reads lines "cmd enable [intensity]" from stdin)
//
// Run via: su -c /data/app/.../lib/arm64/libzx_client.so --loop

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <android/log.h>

#define TAG "ZX-CLIENT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static constexpr char kSockName[] = "zx_zola";

#pragma pack(push, 1)
struct ZxPacket {
    uint8_t cmd;
    uint8_t enable;
    float   intensity;
};
#pragma pack(pop)

static int connectToModule() {
    int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (sock < 0) { LOGE("socket(): %s", strerror(errno)); return -1; }

    struct sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    memset(addr.sun_path, 0, sizeof(addr.sun_path));
    size_t name_len = strlen(kSockName);
    memcpy(addr.sun_path + 1, kSockName, name_len);
    socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_len);

    // Retry up to 30s — module may not have started server yet
    for (int i = 0; i < 60; i++) {
        if (connect(sock, reinterpret_cast<struct sockaddr *>(&addr), addr_len) == 0) {
            LOGI("Connected to Zygisk module");
            return sock;
        }
        usleep(500000); // 500ms
    }
    LOGE("connect(\\0%s): %s", kSockName, strerror(errno));
    close(sock);
    return -1;
}

static bool sendCmd(int sock, int cmd, int enable, float intensity) {
    ZxPacket pkt{};
    pkt.cmd       = (uint8_t)cmd;
    pkt.enable    = (uint8_t)(enable != 0 ? 1 : 0);
    pkt.intensity = intensity;

    if (send(sock, &pkt, sizeof(pkt), MSG_NOSIGNAL) != (ssize_t)sizeof(pkt)) {
        LOGE("send failed: %s", strerror(errno));
        return false;
    }
    // Wait for ACK
    uint8_t ack = 0;
    recv(sock, &ack, 1, 0);
    return ack == 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cmd> <enable> [intensity]\n", argv[0]);
        fprintf(stderr, "   or: %s --loop\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--loop") == 0) {
        // Loop mode: read commands from stdin, one per line
        // Format: "CMD_ID ENABLE [INTENSITY]\n"
        LOGI("Starting in loop mode — waiting for module...");
        int sock = connectToModule();
        if (sock < 0) return 2;

        char line[64];
        while (fgets(line, sizeof(line), stdin)) {
            int cmd = 0, enable = 0;
            float intensity = 0.f;
            int parsed = sscanf(line, "%d %d %f", &cmd, &enable, &intensity);
            if (parsed < 2 || cmd <= 0) continue;

            if (!sendCmd(sock, cmd, enable, intensity)) {
                LOGE("Send failed — reconnecting...");
                close(sock);
                sock = connectToModule();
                if (sock < 0) return 3;
                // Retry
                sendCmd(sock, cmd, enable, intensity);
            }
        }
        close(sock);
        return 0;
    }

    // Single command mode
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <cmd> <enable> [intensity]\n", argv[0]);
        return 1;
    }
    int   cmd       = atoi(argv[1]);
    int   enable    = atoi(argv[2]);
    float intensity = argc > 3 ? atof(argv[3]) : 0.f;

    int sock = connectToModule();
    if (sock < 0) return 2;

    bool ok = sendCmd(sock, cmd, enable, intensity);
    close(sock);
    return ok ? 0 : 4;
}
