#pragma once
#include <cstdint>
void install_stealth_ext7();
bool is_hookable_arm64(const void *fn);
// Patch libanogs's GOT entry for a named import — no bionic body modification
bool anogs_patch_got_import(uintptr_t ano_base, const char *sym_name, void *new_fn);
