#include <stddef.h>
#include "../build/src/elf_structs.h"

const struct SectionEntry *findSectionEntry(const struct SectionEntry *entries, int count, const void *extra, int (* predicate)(const struct SectionEntry *, const void *)) {
    for (int i = 0; i < count; i++) {
        if (predicate(entries + i, extra)) {
            return entries + i;
        }
    }

    return NULL;
}