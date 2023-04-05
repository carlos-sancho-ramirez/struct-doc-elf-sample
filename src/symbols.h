#ifndef _SYMBOLS_H_
#define _SYMBOLS_H_

#include "elf_structs.h"

const struct SymbolEntry64 *findSymbolEntry64(const struct SymbolEntry64 *entries, int count, const void *extra, int (* predicate)(const struct SymbolEntry64 *, const void *));

#endif // _SYMBOLS_H_