#include <stddef.h>
#include "elf_structs.h"

const struct SectionEntry *findSectionEntry(const struct SectionEntry *entries, int count, const char *stringTable, int (* predicate)(const struct SectionEntry *, const char *)) {
    for (int i = 0; i < count; i++) {
        if (predicate(entries + i, stringTable)) {
            return entries + i;
        }
    }

    return NULL;
}