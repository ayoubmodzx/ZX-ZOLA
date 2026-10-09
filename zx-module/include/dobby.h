#pragma once
// Dobby inline hook API
#ifdef __cplusplus
extern "C" {
#endif

int DobbyHook(void *address, void *replace_call, void **origin_call);
int DobbyDestroy(void *address);
void *DobbySymbolResolver(const char *image_name, const char *symbol_name);

#ifdef __cplusplus
}
#endif
