#ifndef _PROGRAM_H_
#define _PROGRAM_H_

#include "../build/src/elf_structs.h"

const struct ProgramEntry *findProgramEntry(const struct ProgramEntry *entries, int count, int (* predicate)(const struct ProgramEntry *));

#endif // _PROGRAM_H_