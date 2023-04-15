#ifndef _SECTIONS_H_
#define _SECTIONS_H_

#include "../build/src/elf_structs.h"

const struct SectionEntry *findSectionEntry(const struct SectionEntry *entries, int count, const void *extra, int (* predicate)(const struct SectionEntry *, const void *));

#endif // _SECTIONS_H_