#include <stddef.h>
#include "elf_structs.h"

const struct ProgramEntry *findProgramEntry(const struct ProgramEntry *entries, int count, int (* predicate)(const struct ProgramEntry *)) {
    for (int i = 0; i < count; i++) {
        if (predicate(entries + i)) {
            return entries + i;
        }
    }

    return NULL;
}