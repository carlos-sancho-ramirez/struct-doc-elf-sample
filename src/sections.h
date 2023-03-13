#ifndef _SECTIONS_H_
#define _SECTIONS_H_

#include "elf_structs.h"

const struct SectionEntry *findSectionEntry(const struct SectionEntry *entries, int count, const char *stringTable, int (* predicate)(const struct SectionEntry *, const char *));

#endif // _SECTIONS_H_