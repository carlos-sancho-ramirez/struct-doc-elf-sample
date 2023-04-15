#ifndef _PARSERS_H_
#define _PARSERS_H_

#include <stdio.h>
#include "../build/src/elf_structs.h"

int parseHeader(FILE *file, struct Header *header);
int parseHeaderX(FILE *file, struct HeaderX *headerX);
int parseProgramEntry(FILE *file, struct ProgramEntry *entry);
int parseSectionEntry(FILE *file, struct SectionEntry *entry);
int parseSymbolEntry64(FILE *file, struct SymbolEntry64 *data);
int parseRelocationEntry64WithAddend(FILE *file, struct RelocationEntry64WithAddend *entry);
int parseDynamicEntry(FILE *file, struct DynamicEntry *entry);

#endif // _PARSERS_H_