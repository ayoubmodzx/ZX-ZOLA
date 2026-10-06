#pragma once
// Dobby inline hook API — link against libdobby.a from your NDK toolchain
#ifdef __cplusplus
extern "C" {
#endif
int  DobbyHook(void *addr, void *replace, void **origin);
int  DobbyDestroy(void *addr);
void *DobbySymbolResolver(const char *lib, const char *sym);
#ifdef __cplusplus
}
#endif
