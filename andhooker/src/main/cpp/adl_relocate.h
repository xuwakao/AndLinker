//
// Instruction relocation interface for inline hook trampoline
//

#ifndef ANDHOOKER_ADL_RELOCATE_H
#define ANDHOOKER_ADL_RELOCATE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

// Build a trampoline: relocate instructions from [target, target+hook_size)
// into trampoline buffer, then append a jump back to target+hook_size.
//
// Parameters:
//   target       - original function address (no Thumb bit)
//   hook_size    - number of bytes being overwritten
//   is_thumb     - ARM32 only: true if target is Thumb code
//   trampoline   - output buffer (must be executable, at least PAGE_SIZE)
//
// Returns: total bytes written to trampoline, or 0 on failure
size_t adl_build_trampoline(void *target, size_t hook_size, bool is_thumb,
                            uint8_t *trampoline);

// Determine the actual hook size needed (may be larger than minimum
// if instructions span boundaries or IT blocks need expansion).
//
// Parameters:
//   target       - function address (no Thumb bit)
//   min_size     - minimum bytes to overwrite (architecture-specific)
//   is_thumb     - ARM32 only
//
// Returns: actual hook size (>= min_size), or 0 on failure
size_t adl_calc_hook_size(void *target, size_t min_size, bool is_thumb);

__END_DECLS

#endif //ANDHOOKER_ADL_RELOCATE_H
