#include <stddef.h>
#include "../build/src/elf_structs.h"

const struct SymbolEntry64 *findSymbolEntry64(const struct SymbolEntry64 *entries, int count, const void *extra, int (* predicate)(const struct SymbolEntry64 *, const void *)) {
    for (int i = 0; i < count; i++) {
        if (predicate(entries + i, extra)) {
            return entries + i;
        }
    }

    return NULL;
}