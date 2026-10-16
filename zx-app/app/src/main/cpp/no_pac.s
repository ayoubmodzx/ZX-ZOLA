/*
 * no_pac.s — force lld to generate plain BR X16 PLT stubs (no BRAA / PAC auth).
 *
 * Root cause of the PAC crash (PC=0xd67f... SIGSEGV in do_dlopen):
 *   -mbranch-protection=none makes the compiler emit NO GNU_PROPERTY note at all,
 *   not a note with PAC=0. lld treats an absent note as "all features enabled"
 *   when computing the AND of input objects. libc++_static.a objects have
 *   GNU_PROPERTY_AARCH64_FEATURE_1_PAC set. The AND is therefore PAC=1, so lld
 *   generates BRAA X16,X17 PLT stubs and bionic signs each GOT slot with pacia().
 *   FF's linker (a different bionic instance) replicates the pacia() signing
 *   incorrectly for our payload, causing BRAA authentication to fail → SIGSEGV.
 *
 * Fix: this object explicitly emits GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0.
 *   AND(0, any) = 0 → PAC cleared → lld emits plain BR X16 stubs → bionic
 *   writes unsigned pointers into GOT → BR X16 on unsigned GOT works on every
 *   device, PAC-capable or not.
 *
 * Note layout (ELF note, 8-byte aligned):
 *   namesz  = 4        ("GNU\0")
 *   descsz  = 16       (one property: type+datasz+data+pad = 4+4+4+4)
 *   type    = 5        (NT_GNU_PROPERTY_TYPE_0)
 *   name    = "GNU\0"
 *   pr_type = 0xc0000001 (GNU_PROPERTY_AARCH64_FEATURE_1_AND)
 *   pr_datasz = 4
 *   pr_data = 0        (BTI=0, PAC=0)
 *   pad     = 0
 */

	.section ".note.gnu.property", "a", %note
	.p2align 3
	.long 4              /* namesz */
	.long 16             /* descsz: 4+4+4+4 = 16 */
	.long 5              /* NT_GNU_PROPERTY_TYPE_0 */
	.byte 'G','N','U',0  /* name: "GNU\0" */
	.long 0xc0000001     /* GNU_PROPERTY_AARCH64_FEATURE_1_AND */
	.long 4              /* pr_datasz */
	.long 0              /* pr_data: PAC=0, BTI=0 */
	.long 0              /* padding to 8-byte boundary */
