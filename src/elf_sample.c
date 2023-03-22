#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sections.h"

#define HEADER_FILE_SIZE 16
#define HEADERX_FILE_SIZE 48
#define PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE 56
#define SECTION_HEADER_TABLE_ENTRY_FILE_SIZE 64
#define SYMBOL_ENTRY_64_FILE_SIZE 24
#define RELOCATION_ENTRY_WITH_ADDEND_64_FILE_SIZE 24
#define DYNAMIC_TABLE_ENTRY_64_FILE_SIZE 16

#define SECTION_ENTRY_TYPE_SYMBOL_TABLE 2
#define SECTION_ENTRY_TYPE_STRING_TABLE 3
#define SECTION_ENTRY_TYPE_RELOCATION_TABLE_WITH_ADDENDS 4
#define SECTION_ENTRY_TYPE_DYNAMIC_TABLE 6
#define SECTION_ENTRY_TYPE_DYNAMIC_SYMBOL_TABLE 11

int parseHeader(FILE *file, struct Header *header) {
    char buffer[HEADER_FILE_SIZE];
    if (fread(buffer, 1, HEADER_FILE_SIZE, file) < HEADER_FILE_SIZE) {
        fprintf(stderr, "Unexpected end of file\n");
        return 1;
    }

    if (buffer[0] != 0x7F || buffer[1] != 'E' || buffer[2] != 'L' || buffer[3] != 'F') {
        fprintf(stderr, "Invalid file signature. It does not seem to eb an ELF file\n");
        return 1;
    }

    header->class = buffer[4];
    header->data = buffer[5];
    header->version = buffer[6];
    header->osabi = buffer[7];
    header->abiVersion = buffer[8];

    return 0;
}

uint16_t readWord16LittleEndian(const void *addr) {
    const unsigned char *casted = (const unsigned char *) addr;
    uint16_t result = casted[1];
    return (result << 8) + casted[0];
}

uint32_t readWord32LittleEndian(const void *addr) {
    const unsigned char *casted = (const unsigned char *) addr;
    uint32_t result = casted[3];
    for (int i = 2; i >= 0; i--) {
        result = (result << 8) + casted[i];
    }

    return result;
}

uint64_t readWord64LittleEndian(const void *addr) {
    const unsigned char *casted = (const unsigned char *) addr;
    uint64_t result = casted[7];
    for (int i = 6; i >= 0; i--) {
        result = (result << 8) + casted[i];
    }

    return result;
}

int parseHeaderX(FILE *file, struct HeaderX *headerX) {
    char buffer[HEADERX_FILE_SIZE];
    if (fread(buffer, 1, HEADERX_FILE_SIZE, file) < HEADERX_FILE_SIZE) {
        fprintf(stderr, "Unexpected end of file\n");
        return 1;
    }

    headerX->type = readWord16LittleEndian(buffer);
    headerX->machine = readWord16LittleEndian(buffer + 2);
    headerX->version = readWord32LittleEndian(buffer + 4);
    headerX->entry = readWord64LittleEndian(buffer + 8);
    headerX->programHeaderTable = readWord64LittleEndian(buffer + 16);
    headerX->sectionHeaderTable = readWord64LittleEndian(buffer + 24);
    headerX->flags = readWord32LittleEndian(buffer + 32);
    headerX->headerSize = readWord16LittleEndian(buffer + 36);
    headerX->programHeaderTableEntrySize = readWord16LittleEndian(buffer + 38);
    headerX->programHeaderTableEntryCount = readWord16LittleEndian(buffer + 40);
    headerX->sectionHeaderTableEntrySize = readWord16LittleEndian(buffer + 42);
    headerX->sectionHeaderTableEntryCount = readWord16LittleEndian(buffer + 44);
    headerX->sectionHeaderTableStringTableIndex = readWord16LittleEndian(buffer + 46);

    return 0;
}

int parseProgramEntry(FILE *file, struct ProgramEntry *entry) {
    char buffer[PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE];
    if (fread(buffer, 1, PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE, file) < PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE) {
        fprintf(stderr, "Unexpected end of file\n");
        return 1;
    }

    entry->type = readWord32LittleEndian(buffer);
    entry->flags = readWord32LittleEndian(buffer + 4);
    entry->offset = readWord64LittleEndian(buffer + 8);
    entry->virtualAddress = readWord64LittleEndian(buffer + 16);
    entry->physicalAddress = readWord64LittleEndian(buffer + 24);
    entry->fileSize = readWord64LittleEndian(buffer + 32);
    entry->memSize = readWord64LittleEndian(buffer + 40);
    entry->alignment = readWord64LittleEndian(buffer + 48);

    return 0;
}

int parseSectionEntry(FILE *file, struct SectionEntry *entry) {
    char buffer[SECTION_HEADER_TABLE_ENTRY_FILE_SIZE];
    if (fread(buffer, 1, SECTION_HEADER_TABLE_ENTRY_FILE_SIZE, file) < SECTION_HEADER_TABLE_ENTRY_FILE_SIZE) {
        fprintf(stderr, "Unexpected end of file\n");
        return 1;
    }

    entry->name = readWord32LittleEndian(buffer);
    entry->type = readWord32LittleEndian(buffer + 4);
    entry->flags = readWord32LittleEndian(buffer + 8);
    entry->virtualAddress = readWord64LittleEndian(buffer + 16);
    entry->offset = readWord64LittleEndian(buffer + 24);
    entry->fileSize = readWord64LittleEndian(buffer + 32);
    entry->link = readWord32LittleEndian(buffer + 40);
    entry->info = readWord32LittleEndian(buffer + 44);
    entry->alignment = readWord64LittleEndian(buffer + 48);
    entry->entrySize = readWord64LittleEndian(buffer + 56);

    return 0;
}

int parseDynamicSymbolEntry(FILE *file, struct SymbolEntry64 *entry) {
    char buffer[SYMBOL_ENTRY_64_FILE_SIZE];
    if (fread(buffer, 1, SYMBOL_ENTRY_64_FILE_SIZE, file) < SYMBOL_ENTRY_64_FILE_SIZE) {
        fprintf(stderr, "Unexpected end of file\n");
        return 1;
    }

    entry->name = readWord32LittleEndian(buffer);
    entry->info = buffer[4];
    entry->other = buffer[5];
    entry->sectionIndex = readWord16LittleEndian(buffer + 6);
    entry->value = readWord64LittleEndian(buffer + 8);
    entry->size = readWord64LittleEndian(buffer + 16);

    return 0;
}

int parseRelocationEntryWithAddend(FILE *file, struct RelocationEntryWithAddend *entry) {
    char buffer[RELOCATION_ENTRY_WITH_ADDEND_64_FILE_SIZE];
    if (fread(buffer, 1, RELOCATION_ENTRY_WITH_ADDEND_64_FILE_SIZE, file) < RELOCATION_ENTRY_WITH_ADDEND_64_FILE_SIZE) {
        fprintf(stderr, "Unexpected end of file\n");
        return 1;
    }

    entry->address = readWord64LittleEndian(buffer);
    entry->info = readWord64LittleEndian(buffer + 8);
    entry->addend = readWord64LittleEndian(buffer + 16);

    return 0;
}

int parseDynamicEntry(FILE *file, struct DynamicEntry *entry) {
    char buffer[DYNAMIC_TABLE_ENTRY_64_FILE_SIZE];
    if (fread(buffer, 1, DYNAMIC_TABLE_ENTRY_64_FILE_SIZE, file) < DYNAMIC_TABLE_ENTRY_64_FILE_SIZE) {
        fprintf(stderr, "Unexpected end of file\n");
        return 1;
    }

    entry->tag = readWord64LittleEndian(buffer);
    entry->value = readWord64LittleEndian(buffer + 8);

    return 0;
}

void dumpHeader(const struct Header *header) {
    printf("Header:\n  class=%u\n  data=%u\n  version=%u\n  osabi=%u\n  abiVersion=%u\n", (int) header->class, (int) header->data, (int) header->version, (int) header->osabi, (int) header->abiVersion);
}

void dumpHeaderX(const struct HeaderX *headerX) {
    printf("HeaderX:\n  type=%u\n  machine=%u\n  version=%u\n  entry=%lu\n  programHeaderTable=%lu\n  sectionHeaderTable=%lu\n  flags=%u\n  headerSize=%u\n  programHeaderTableEntrySize=%u\n  programHeaderTableEntryCount=%u\n  sectionHeaderTableEntrySize=%u\n  sectionHeaderTableEntryCount=%u\n  sectionHeaderTableStringTableIndex=%u\n", (int) headerX->type, (int) headerX->machine, (int) headerX->version, headerX->entry, headerX->programHeaderTable, headerX->sectionHeaderTable, (int) headerX->flags, (int) headerX->headerSize, (int) headerX->programHeaderTableEntrySize, (int) headerX->programHeaderTableEntryCount, (int) headerX->sectionHeaderTableEntrySize, (int) headerX->sectionHeaderTableEntryCount, (int) headerX->sectionHeaderTableStringTableIndex);
}

void dumpProgramEntry(const struct ProgramEntry *entry) {
    printf("ProgramEntry:\n  type=%u\n  flags=%u\n  offset=%lu\n  virtualAddress=%lu\n  physicalAddress=%lu\n  fileSize=%lu\n  memSize=%lu\n  alignment=%lu\n", entry->type, entry->flags, entry->offset, entry->virtualAddress, entry->physicalAddress, entry->fileSize, entry->memSize, entry->alignment);
}

void dumpSectionEntry(const struct SectionEntry *entry, const unsigned char *stringTable) {
    printf("SectionEntry:\n  name=%s\n  type=%u\n  flags=%lu\n  virtualAddress=%lu\n  offset=%lu\n  fileSize=%lu\n  link=%u\n  info=%u\n  alignment=%lu\n  entrySize=%lu\n", stringTable + entry->name, entry->type, entry->flags, entry->virtualAddress, entry->offset, entry->fileSize, entry->link, entry->info, entry->alignment, entry->entrySize);
}

#define SYMBOL_ENTRY_NUMBER_OF_TYPES 7

const char *symbolEntryTypeNames[SYMBOL_ENTRY_NUMBER_OF_TYPES] = {
    "No type",
    "Object",
    "Function",
    "Section",
    "File",
    "Common data object",
    "Thread-local data object"
};

#define SYMBOL_ENTRY_NUMBER_OF_BINDINGS 3

const char *symbolEntryBindNames[SYMBOL_ENTRY_NUMBER_OF_BINDINGS] = {
    "Local",
    "Global",
    "Weak"
};

void dumpSymbolEntry64(const struct SymbolEntry64 *entry, const unsigned char *stringTable) {
    printf("SymbolEntry64:\n  name=%s\n  info=%u", stringTable + entry->name, entry->info);
    const int type = entry->info & 0x0F;
    const int bind = entry->info >> 4;
    if (type < SYMBOL_ENTRY_NUMBER_OF_TYPES) {
        printf("\t\t# %s", symbolEntryTypeNames[type]);
        if (bind < SYMBOL_ENTRY_NUMBER_OF_BINDINGS) {
            printf(" (%s)", symbolEntryBindNames[bind]);
        }
    }
    else if (bind < SYMBOL_ENTRY_NUMBER_OF_BINDINGS) {
        printf("\t\t# ? (%s)", symbolEntryBindNames[bind]);
    }

    printf("\n  other=%u\n  value=%lu\n  size=%lu\n", entry->other, entry->value, entry->size);
}

void dumpRelocationEntryWithAddend(const struct RelocationEntryWithAddend *entry, const struct SectionEntry *sections, int sectionCount, const char *stringTable, const struct SymbolEntry64 *symbols, const int symbolCount, const char *symbolStringTable) {
    printf("RelocationEntryWithAddend:\n  address=%lu", entry->address);
    for (int sectionIndex = 0; sectionIndex < sectionCount; sectionIndex++) {
        const struct SectionEntry *section = sections + sectionIndex;
        const long sectionAddress = section->virtualAddress;
        if (entry->address >= sectionAddress && entry->address < (sectionAddress + section->fileSize)) {
            printf("\t\t#%s + 0x%lx", stringTable + section->name, entry->address - sectionAddress);
        }
    }

    printf("\n  info=0x%lx", entry->info);
    const int symbolIndex = entry->info >> 32;
    if (symbolIndex < symbolCount && symbols != NULL && symbolStringTable != NULL) {
        const char *symbolName = symbolStringTable + symbols[symbolIndex].name;
        if (symbolName[0] != '\0') {
            printf("\t\t# %s", symbolName);
        }
    }

    printf("\n  addend=%lu\n", entry->addend);
}

void dumpDynamicEntry(const struct DynamicEntry *entry) {
    printf("(%lu)", entry->tag);
    printf(": ");
    printf("(%lu)\n", entry->value);
}

int readProgramEntries(FILE *file, struct ProgramEntry *entries, int entryCount) {
    for (int entryIndex = 0; entryIndex < entryCount; entryIndex++) {
        if (parseProgramEntry(file, &entries[entryIndex])) {
            return 1;
        }

        printf("#%u ", entryIndex);
        dumpProgramEntry(entries + entryIndex);
    }

    return 0;
}

int readSectionEntries(FILE *file, struct SectionEntry *entries, int entryCount) {
    for (int entryIndex = 0; entryIndex < entryCount; entryIndex++) {
        if (parseSectionEntry(file, &entries[entryIndex])) {
            return 1;
        }
    }

    return 0;
}

int readStringTable(FILE *file, const struct SectionEntry *stringTableSection, unsigned char *stringTable) {
    if (fseek(file, stringTableSection->offset, SEEK_SET)) {
        fprintf(stderr, "Unable to set file position at %lu\n", stringTableSection->offset);
        return 1;
    }

    if (fread(stringTable, 1, stringTableSection->fileSize, file) < stringTableSection->fileSize) {
        fprintf(stderr, "Unexpected end of file\n");
        return 1;
    }

    return 0;
}

int isDynSymSectionEntry(const struct SectionEntry *entry, const char *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_DYNAMIC_SYMBOL_TABLE && strcmp(".dynsym", stringTable + entry->name) == 0;
}

int isDynStrSectionEntry(const struct SectionEntry *entry, const char *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_STRING_TABLE && strcmp(".dynstr", stringTable + entry->name) == 0;
}

int isSymTabSectionEntry(const struct SectionEntry *entry, const char *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_SYMBOL_TABLE && strcmp(".symtab", stringTable + entry->name) == 0;
}

int isStrTabSectionEntry(const struct SectionEntry *entry, const char *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_STRING_TABLE && strcmp(".strtab", stringTable + entry->name) == 0;
}

int isRelaDynSectionEntry(const struct SectionEntry *entry, const char *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_RELOCATION_TABLE_WITH_ADDENDS && strcmp(".rela.dyn", stringTable + entry->name) == 0;
}

int isDynamicSectionEntry(const struct SectionEntry *entry, const char *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_DYNAMIC_TABLE && strcmp(".dynamic", stringTable + entry->name) == 0;
}

int readDynamicSymbolEntries(FILE *file, long offset, struct SymbolEntry64 *entries, int entryCount) {
    if (fseek(file, offset, SEEK_SET)) {
        fprintf(stderr, "Unable to set file position at %lu\n", offset);
        return 1;
    }

    for (int entryIndex = 0; entryIndex < entryCount; entryIndex++) {
        if (parseDynamicSymbolEntry(file, &entries[entryIndex])) {
            return 1;
        }
    }

    return 0;
}

int readRelocationEntriesWithAddend(FILE *file, long offset, struct RelocationEntryWithAddend *entries, int entryCount) {
    if (fseek(file, offset, SEEK_SET)) {
        fprintf(stderr, "Unable to set file position at %lu\n", offset);
        return 1;
    }

    for (int entryIndex = 0; entryIndex < entryCount; entryIndex++) {
        if (parseRelocationEntryWithAddend(file, &entries[entryIndex])) {
            return 1;
        }
    }

    return 0;
}

int readDynamicEntries(FILE *file, long offset, struct DynamicEntry *entries, int entryCount) {
    if (fseek(file, offset, SEEK_SET)) {
        fprintf(stderr, "Unable to set file position at %lu\n", offset);
        return 1;
    }

    for (int entryIndex = 0; entryIndex < entryCount; entryIndex++) {
        if (parseDynamicEntry(file, &entries[entryIndex])) {
            return 1;
        }
    }

    return 0;
}

int readProgramAndSectionEntries(FILE *file, void *memoryAllocated, struct HeaderX *headerX) {
    struct ProgramEntry *programEntries = (struct ProgramEntry *) memoryAllocated;
    struct SectionEntry *sectionEntries = memoryAllocated + (sizeof(struct ProgramEntry) * headerX->programHeaderTableEntryCount);

    int result;
    if ((result = readProgramEntries(file, programEntries, headerX->programHeaderTableEntryCount))) {
        return result;
    }

    int expectedPosition;
    if (headerX->sectionHeaderTable != (expectedPosition = HEADER_FILE_SIZE + HEADERX_FILE_SIZE + PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE * headerX->programHeaderTableEntryCount) &&
            fseek(file, headerX->sectionHeaderTable, SEEK_SET)) {
        fprintf(stderr, "Unable to set file position at %lu\n", headerX->sectionHeaderTable);
        return 1;
    }

    if (result = readSectionEntries(file, sectionEntries, headerX->sectionHeaderTableEntryCount)) {
        return result;
    }

    const struct SectionEntry *stringTableSection;
    unsigned char *stringTable;
    stringTableSection = sectionEntries + headerX->sectionHeaderTableStringTableIndex;
    stringTable = malloc(stringTableSection->fileSize);
    if (!stringTable) {
        fprintf(stderr, "Unable to allocate %lu bytes\n", stringTableSection->fileSize);
        return 1;
    }

    if (!(result = readStringTable(file, stringTableSection, stringTable))) {
        for (int entryIndex = 0; entryIndex < headerX->sectionHeaderTableEntryCount; entryIndex++) {
            printf("#%u ", entryIndex);
            dumpSectionEntry(sectionEntries + entryIndex, stringTable);
        }
    }

    const struct SectionEntry *dynSymSection;
    long symbolCount = 0;
    struct SymbolEntry64 *symbolEntries = NULL;
    char *symbolStringTable = NULL;

    if (!result && (dynSymSection = findSectionEntry(sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, isDynSymSectionEntry))) {
        const struct SectionEntry *dynStrSection;
        if (!(dynStrSection = findSectionEntry(sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, isDynStrSectionEntry))) {
            fprintf(stderr, ".dynsym section found but .dynstr is missing\n");
            result = 1;
        }

        void *dynSymAllocatedMemory;
        if (!result) {
            symbolCount = dynSymSection->fileSize / SYMBOL_ENTRY_64_FILE_SIZE;
            const long memoryToAllocate = sizeof(struct SymbolEntry64) * symbolCount + dynStrSection->fileSize;
            if (!(dynSymAllocatedMemory = malloc(memoryToAllocate))) {
                fprintf(stderr, "Unable to allocate %lu bytes for the dynamic symbol table\n", memoryToAllocate);
                result = 1;
            }
        }

        if (!result) {
            symbolEntries = dynSymAllocatedMemory;
            symbolStringTable = dynSymAllocatedMemory + (sizeof(struct SymbolEntry64) * symbolCount);
            if (readDynamicSymbolEntries(file, dynSymSection->offset, symbolEntries, symbolCount) || readStringTable(file, dynStrSection, symbolStringTable)) {
                result = 1;
            }
            else {
                printf("\nDynamic symbol table (.dynsym):\n");
                for (int entryIndex = 0; entryIndex < symbolCount; entryIndex++) {
                    printf("#%u ", entryIndex);
                    dumpSymbolEntry64(symbolEntries + entryIndex, symbolStringTable);
                }
            }
        }
    }

    const struct SectionEntry *symTabSection;
    if (!result && (symTabSection = findSectionEntry(sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, isSymTabSectionEntry))) {
        const struct SectionEntry *strTabSection;
        if (!(strTabSection = findSectionEntry(sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, isStrTabSectionEntry))) {
            fprintf(stderr, ".symtab section found but .strtab is missing\n");
            result = 1;
        }

        long symbolCount;
        void *symTabAllocatedMemory;
        if (!result) {
            symbolCount = symTabSection->fileSize / SYMBOL_ENTRY_64_FILE_SIZE;
            const long memoryToAllocate = sizeof(struct SymbolEntry64) * symbolCount + strTabSection->fileSize;
            if (!(symTabAllocatedMemory = malloc(memoryToAllocate))) {
                fprintf(stderr, "Unable to allocate %lu bytes for the dynamic symbol table\n", memoryToAllocate);
                result = 1;
            }
        }

        if (!result) {
            struct SymbolEntry64 *symbolEntries = symTabAllocatedMemory;
            char *symbolStringTable = symTabAllocatedMemory + (sizeof(struct SymbolEntry64) * symbolCount);
            if (readDynamicSymbolEntries(file, symTabSection->offset, symbolEntries, symbolCount) || readStringTable(file, strTabSection, symbolStringTable)) {
                result = 1;
            }
            else {
                printf("\nDynamic symbol table (.symtab):\n");
                for (int entryIndex = 0; entryIndex < symbolCount; entryIndex++) {
                    printf("#%u ", entryIndex);
                    dumpSymbolEntry64(symbolEntries + entryIndex, symbolStringTable);
                }
            }

            free(symTabAllocatedMemory);
        }
    }

    const struct SectionEntry *relaDynSection;
    if (!result && (relaDynSection = findSectionEntry(sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, isRelaDynSectionEntry))) {
        long symbolCount = relaDynSection->fileSize / RELOCATION_ENTRY_WITH_ADDEND_64_FILE_SIZE;
        const long memoryToAllocate = sizeof(struct RelocationEntryWithAddend) * symbolCount;
        struct RelocationEntryWithAddend *relocationEntries;
        if (!(relocationEntries = malloc(memoryToAllocate))) {
            fprintf(stderr, "Unable to allocate %lu bytes for the relation table\n", memoryToAllocate);
            result = 1;
        }

        if (!result) {
            if (readRelocationEntriesWithAddend(file, relaDynSection->offset, relocationEntries, symbolCount)) {
                result = 1;
            }
            else {
                printf("\nRelocation table (.rela.dyn):\n");
                for (int entryIndex = 0; entryIndex < symbolCount; entryIndex++) {
                    printf("#%u ", entryIndex);
                    dumpRelocationEntryWithAddend(relocationEntries + entryIndex, sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, symbolEntries, symbolCount, symbolStringTable);
                }
            }

            free(relocationEntries);
        }
    }

    const struct SectionEntry *dynamicSection;
    if (!result && (dynamicSection = findSectionEntry(sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, isDynamicSectionEntry))) {
        long symbolCount = dynamicSection->fileSize / DYNAMIC_TABLE_ENTRY_64_FILE_SIZE;
        const long memoryToAllocate = sizeof(struct DynamicEntry) * symbolCount;
        struct DynamicEntry *dynamicEntries;
        if (!(dynamicEntries = malloc(memoryToAllocate))) {
            fprintf(stderr, "Unable to allocate %lu bytes for the dynamic table\n", memoryToAllocate);
            result = 1;
        }

        if (!result) {
            if (readDynamicEntries(file, dynamicSection->offset, dynamicEntries, symbolCount)) {
                result = 1;
            }
            else {
                printf("\nDynamic table (.dynamic):\n");
                for (int entryIndex = 0; entryIndex < symbolCount; entryIndex++) {
                    printf("#%u ", entryIndex);
                    dumpDynamicEntry(dynamicEntries + entryIndex);
                }
            }

            free(dynamicEntries);
        }
    }

    if (symbolEntries) {
        free(symbolEntries);
    }

    free(stringTable);
    return result;
}

int readFile(FILE *file) {
    struct Header header;
    if (parseHeader(file, &header)) {
        return 1;
    }

    dumpHeader(&header);

    // For now we only focus in 64-bit little endian files
    if (header.class != 2) {
        fprintf(stderr, "Unexpected ELF file. It was expected a 64-bit one\n");
        return 1;
    }

    if (header.data != 1) {
        fprintf(stderr, "Unexpected ELF file. It was expected a little endian one\n");
        return 1;
    }

    struct HeaderX headerX;
    if (parseHeaderX(file, &headerX)) {
        return 1;
    }

    dumpHeaderX(&headerX);

    if (headerX.programHeaderTable != HEADER_FILE_SIZE + HEADERX_FILE_SIZE) {
        fprintf(stderr, "Program header table was expected to be at position %u\n", HEADER_FILE_SIZE + HEADERX_FILE_SIZE);
        return 1;
    }

    if (headerX.programHeaderTableEntrySize != PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE) {
        fprintf(stderr, "Program header table entry size was expected to be %u. But it was %u\n", PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE, headerX.programHeaderTableEntrySize);
        return 1;
    }

    if (headerX.sectionHeaderTableStringTableIndex >= headerX.sectionHeaderTableEntryCount) {
        fprintf(stderr, "Wrong index for .shstrtab section. Found %u, but it should be lower than %u\n", headerX.sectionHeaderTableStringTableIndex, headerX.sectionHeaderTableEntryCount);
        return 1;
    }

    const int memoryAllocatedSize = sizeof(struct ProgramEntry) * headerX.programHeaderTableEntryCount +
            sizeof(struct SectionEntry) * headerX.sectionHeaderTableEntryCount;
    void *memoryAllocated = malloc(memoryAllocatedSize);

    if (memoryAllocated) {
        int result = readProgramAndSectionEntries(file, memoryAllocated, &headerX);
        free(memoryAllocated);
        return result;
    }
    else {
        fprintf(stderr, "Unable to allocate %u bytes\n", memoryAllocatedSize);
        return 1;
    }
}

int main(int argc, const char *argv[]) {
    FILE *file = fopen(argv[0], "r");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s\n", argv[0]);
        return 1;
    }

    const int result = readFile(file);
    fclose(file);
    return result;
}
