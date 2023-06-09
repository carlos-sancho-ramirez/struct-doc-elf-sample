#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sections.h"
#include "program.h"
#include "symbols.h"
#include "parsers.h"
#include "readers.h"

#define HEADER_FILE_SIZE 16
#define HEADERX_FILE_SIZE 48
#define PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE 56
#define SECTION_HEADER_TABLE_ENTRY_FILE_SIZE 64
#define SYMBOL_ENTRY_64_FILE_SIZE 24
#define RELOCATION_ENTRY_64_WITH_ADDEND_FILE_SIZE 24
#define DYNAMIC_TABLE_ENTRY_64_FILE_SIZE 16

#define PROGRAM_ENTRY_TYPE_DYNAMIC_LINKING_INFORMATION 2

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

typedef struct {
    struct Header header;
    struct HeaderX headerX;

    struct ProgramEntry *programEntries;
    struct SectionEntry *sectionEntries;

    char *stringTable;

    long symbolCount;
    struct SymbolEntry64 *symbolEntries;
    char *symbolStringTable;

    struct DynamicEntry *dynamicEntries;

    long symbolTabCount;
    struct SymbolEntry64 *symbolTabEntries;
    char *symbolTabStringTable;

    long relocationCount;
    struct RelocationEntry64WithAddend *relocationEntries;
} FileDetails;

#define HEADER_CLASS_32_BIT 1
#define HEADER_CLASS_64_BIT 2

#define HEADER_DATA_LITTLE_ENDIAN 1
#define HEADER_DATA_BIG_ENDIAN 2

const char *headerOsabiNames[] = {
    "System V",
    "HP-UX",
    "NetBSD",
    "Linux",
    "GNU Hurd",
    "?",
    "Solaris",
    "AIX (Monterey)",
    "IRIX",
    "FreeBSD",
    "Tru64",
    "Novell Modesto",
    "OpenBSD",
    "OpenVMS",
    "NonStop Kernel",
    "AROS",
    "FenixOS",
    "Nuxi CloudABI",
    "Stratus Technologies OpenVOS"
};

void dumpHeader(const struct Header *header) {
    printf("Header:\n  class=%u", (int) header->class);
    if (header->class == HEADER_CLASS_32_BIT) {
        printf("\t\t# 32 bits");
    }
    else if (header->class == HEADER_CLASS_64_BIT) {
        printf("\t\t# 64 bits");
    }

    printf("\n  data=%u", (int) header->data);
    if (header->data == HEADER_DATA_LITTLE_ENDIAN) {
        printf("\t\t# Little Endian");
    }
    else if (header->data == HEADER_DATA_BIG_ENDIAN) {
        printf("\t\t# Big Endian");
    }

    printf("\n  version=%u\n  osabi=%u", (int) header->version, (int) header->osabi);
    if (header->osabi < sizeof(headerOsabiNames) / sizeof(char *)) {
        printf("\t\t# %s", headerOsabiNames[header->osabi]);
    }

    printf("\n  abiVersion=%u\n", (int) header->abiVersion);
}

const char *headerXTypeNames[] = {
    "Relocatable file",
    "Executable file",
    "Shared object",
    "Core file"
};

const short headerXMachineKeys[] = {
0x01,
0x02,
0x03,
0x04,
0x05,
0x06,
0x07,
0x08,
0x09,
0x0A,
0x0E,
0x13,
0x14,
0x15,
0x16,
0x17,
0x24,
0x25,
0x26,
0x27,
0x28,
0x29,
0x2A,
0x2B,
0x2C,
0x2D,
0x2E,
0x2F,
0x30,
0x31,
0x32,
0x33,
0x34,
0x35,
0x36,
0x37,
0x38,
0x39,
0x3A,
0x3B,
0x3C,
0x3D,
0x3E,
0x3F,
0x40,
0x41,
0x42,
0x43,
0x44,
0x45,
0x46,
0x47,
0x48,
0x49,
0x4A,
0x4B,
0x4C,
0x4D,
0x4E,
0x4F,
0x8C,
0xAF,
0xB7,
0xDC,
0xF3,
0xF7,
0x101
};

const char *headerXMachineNames[] = {
    "AT&T WE 32100",
    "SPARC",
    "x86",
    "Motorola 68000 (M68k)",
    "Motorola 88000 (M88k)",
    "Intel MCU",
    "Intel 80860",
    "MIPS",
    "IBM System/370",
    "MIPS RS3000 Little-endian",
    "Hewlett-Packard PA-RISC",
    "Intel 80960",
    "PowerPC",
    "PowerPC (64-bit)",
    "S390, including S390x",
    "IBM SPU/SPC",
    "NEC V800",
    "Fujitsu FR20",
    "TRW RH-32",
    "Motorola RCE",
    "Arm (up to Armv7/AArch32)",
    "Digital Alpha",
    "SuperH",
    "SPARC Version 9",
    "Siemens TriCore embedded processor",
    "Argonaut RISC Core",
    "Hitachi H8/300",
    "Hitachi H8/300H",
    "Hitachi H8S",
    "Hitachi H8/500",
    "IA-64",
    "Stanford MIPS-X",
    "Motorola ColdFire",
    "Motorola M68HC12",
    "Fujitsu MMA Multimedia Accelerator",
    "Siemens PCP",
    "Sony nCPU embedded RISC processor",
    "Denso NDR1 microprocessor",
    "Motorola Star*Core processor",
    "Toyota ME16 processor",
    "STMicroelectronics ST100 processor",
    "Advanced Logic Corp. TinyJ embedded processor family",
    "AMD x86-64",
    "Sony DSP Processor",
    "Digital Equipment Corp. PDP-10",
    "Digital Equipment Corp. PDP-11",
    "Siemens FX66 microcontroller",
    "STMicroelectronics ST9+ 8/16 bit microcontroller",
    "STMicroelectronics ST7 8-bit microcontroller",
    "Motorola MC68HC16 Microcontroller",
    "Motorola MC68HC11 Microcontroller",
    "Motorola MC68HC08 Microcontroller",
    "Motorola MC68HC05 Microcontroller",
    "Silicon Graphics SVx",
    "STMicroelectronics ST19 8-bit microcontroller",
    "Digital VAX",
    "Axis Communications 32-bit embedded processor",
    "Infineon Technologies 32-bit embedded processor",
    "Element 14 64-bit DSP Processor",
    "LSI Logic 16-bit DSP Processor",
    "TMS320C6000 Family",
    "MCST Elbrus e2k",
    "Arm 64-bits (Armv8/AArch64)",
    "Zilog Z80",
    "RISC-V",
    "Berkeley Packet Filter",
    "WDC 65C816"
};

static const char *findValueForKey(const short *keys, const char **values, int size, short key) {
    while (size > 0) {
        int index = size / 2;
        const short thisKey = keys[index];
        if (key == thisKey) {
            return values[index];
        }
        else if (key < thisKey) {
            size /= 2;
        }
        else {
            keys += index + 1;
            values += index + 1;
            size = (size - 1) / 2;
        }
    }

    return NULL;
}

static int isAddressInSection(const struct SectionEntry *section, const void *entryAddress) {
    const long addr = *((const long *) entryAddress);
    return addr >= section->virtualAddress && addr < (section->virtualAddress + section->fileSize);
}

static int isMatchingFunctionSymbol(const struct SymbolEntry64 *symbol, const void *rawVirtualAddress) {
    const long addr = *((const long *) rawVirtualAddress);
    return (symbol->info & 0x0F) == 2 && symbol->value == addr;
}

void dumpHeaderX(const FileDetails *fileDetails) {
    const struct HeaderX *headerX = &fileDetails->headerX;
    const int type = headerX->type;
    printf("HeaderX:\n  type=%u", type);

    if (type > 0 && type <= 4) {
        printf("\t\t# %s", headerXTypeNames[type - 1]);
    }

    printf("\n  machine=%u", (int) headerX->machine);

    const char *machineName = findValueForKey(headerXMachineKeys, headerXMachineNames, sizeof(headerXMachineKeys) / sizeof(short), headerX->machine);
    if (machineName) {
        printf("\t\t# %s", machineName);
    }

    printf("\n  version=%u\n  entry=%lu", (int) headerX->version, headerX->entry);

    const short sectionCount = headerX->sectionHeaderTableEntryCount;
    const struct SectionEntry *section = findSectionEntry(fileDetails->sectionEntries, sectionCount, &headerX->entry, isAddressInSection);
    const struct SymbolEntry64 *entrySymbol = findSymbolEntry64(fileDetails->symbolTabEntries, fileDetails->symbolTabCount, &headerX->entry, isMatchingFunctionSymbol);
    if (section && entrySymbol) {
        printf("\t\t# %s at %s + 0x%lx", fileDetails->symbolTabStringTable + entrySymbol->name, fileDetails->stringTable + section->name, headerX->entry - section->virtualAddress);
    }
    else if (section) {
        printf("\t\t# %s + 0x%lx", fileDetails->stringTable + section->name, headerX->entry - section->virtualAddress);
    }
    else if (entrySymbol) {
        printf("\t\t# %s", fileDetails->symbolTabStringTable + entrySymbol->name);
    }

    printf("\n  programHeaderTable=%lu\n  sectionHeaderTable=%lu\n  flags=%u\n  headerSize=%u\n  programHeaderTableEntrySize=%u\n  programHeaderTableEntryCount=%u\n  sectionHeaderTableEntrySize=%u\n  sectionHeaderTableEntryCount=%u\n  sectionHeaderTableStringTableIndex=%u\n", headerX->programHeaderTable, headerX->sectionHeaderTable, (int) headerX->flags, (int) headerX->headerSize, (int) headerX->programHeaderTableEntrySize, (int) headerX->programHeaderTableEntryCount, (int) headerX->sectionHeaderTableEntrySize, (int) headerX->sectionHeaderTableEntryCount, (int) headerX->sectionHeaderTableStringTableIndex);
}

#define PROGRAM_ENTRY_NUMBER_OF_TYPES 8

const char *programEntryTypeNames[PROGRAM_ENTRY_NUMBER_OF_TYPES] = {
    "Unused",
    "Loadable segment",
    "Dynamic linking information",
    "Interpreter information",
    "Auxiliary information",
    "?",
    "Program header table",
    "Thread-local storage template"
};

void dumpProgramEntry(const struct ProgramEntry *entry) {
    const int type = entry->type;
    printf("ProgramEntry:\n  type=%u", type);

    if (type < PROGRAM_ENTRY_NUMBER_OF_TYPES) {
        printf("\t\t# %s", programEntryTypeNames[type]);
    }

    const int flags = entry->flags;
    printf("\n  flags=%u", flags);
    if (flags & 7) {
        printf("\t\t# ");
        if (flags & 4) {
            printf("Readable");
        }

        if (flags & 2) {
            if (flags & 4) {
                printf(" + Writable");
            }
            else {
                printf("Writable");
            }
        }

        if (flags & 1) {
            if (flags & 6) {
                printf(" + Executable");
            }
            else {
                printf("Executable");
            }
        }
    }

    printf("\n  offset=%lu\n  virtualAddress=%lu\n  physicalAddress=%lu\n  fileSize=%lu\n  memSize=%lu\n  alignment=%lu\n", entry->offset, entry->virtualAddress, entry->physicalAddress, entry->fileSize, entry->memSize, entry->alignment);
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

void dumpRelocationEntry64WithAddend(const FileDetails *fileDetails, long relocationIndex) {
    const struct RelocationEntry64WithAddend *entry = fileDetails->relocationEntries + relocationIndex;
    const long entryAddress = entry->address;
    printf("RelocationEntryWithAddend:\n  address=%lu", entryAddress);

    const short sectionCount = fileDetails->headerX.sectionHeaderTableEntryCount;
    const struct SectionEntry *section = findSectionEntry(fileDetails->sectionEntries, sectionCount, &entryAddress, isAddressInSection);
    if (section) {
        printf("\t\t# %s + 0x%lx", fileDetails->stringTable + section->name, entryAddress - section->virtualAddress);
    }

    printf("\n  info=0x%lx", entry->info);
    const int symbolIndex = entry->info >> 32;
    if (symbolIndex < fileDetails->symbolCount && fileDetails->symbolEntries && fileDetails->symbolStringTable) {
        const char *symbolName = fileDetails->symbolStringTable + fileDetails->symbolEntries[symbolIndex].name;
        if (symbolName[0] != '\0') {
            printf("\t\t# %s", symbolName);
        }
    }

    printf("\n  addend=%lu\n", entry->addend);
}

#define DYNAMIC_ENTRY_NUMBER_OF_TAG_NAMES 35
#define DYNAMIC_ENTRY_TAG_NEEDED 1
#define DYNAMIC_ENTRY_TAG_STRING_TABLE_ADDRESS 5
#define DYNAMIC_ENTRY_TAG_SYMBOL_TABLE_ADDRESS 6
#define DYNAMIC_ENTRY_TAG_RELADYN_TABLE_ADDRESS 7
#define DYNAMIC_ENTRY_TAG_STRING_TABLE_SIZE 10
#define DYNAMIC_ENTRY_TAG_SYMBOL_ENTRY_FILE_SIZE 11

const char *dynamicEntryTagNames[DYNAMIC_ENTRY_NUMBER_OF_TAG_NAMES] = {
    "?",
    "Required library",
    "Size in bytes of PLT relocations",
    "Processor defined value",
    "Hash: Address of symbol hash table",
    "Address of the string table",
    "Address of the symbol table",
    "Address of Relocations with addend",
    "Total size of the relocations with addends table",
    "Size of one relocation entry",
    "Size of string table",
    "Size of one symbol table entry",
    "Address of init function",
    "Address of termination function",
    "Name of shared object",
    "Library search path (deprecated)",
    "Start symbol search here",
    "Address of relocation without addend table",
    "Total size of relocation without addend table",
    "Size of one Relocation without addend entry",
    "Type of relocation in PLT",
    "For debugging; unspecified",
    "Relocation might modify .text",
    "Address of PLT relocations",
    "Process relocations of object",
    "Array with addresses of init fct",
    "Array with addresses of fini fct",
    "Size in bytes of the array with addresses of init fct",
    "Size in bytes of the array with addresses of fini fct",
    "Library search path",
    "Flags for the object being loaded",
    "?",
    "Array with addresses of preinit fct",
    "Size in bytes of the array with addresses of preinit fct",
    "Address of SYMTAB_SHNDX section",
};

#define DYNAMIC_ENTRY_TAG_GNU_STYLE_HASH_TABLE 0x6FFFFEF5

const char *dynamicEntryTagNamesFrom6FFFFEF5[] = {
    "Address of the GNU-style hash table",
    "TLSDESC_PLT",
    "TLSDESC_GOT",
    "GNU_CONFLICT",
    "GNU_LIBLIST",
    "Configuration information",
    "Dependency auditing",
    "Object auditing",
    "PLT padding",
    "Move table",
    "Syminfo table"
};

#define DYNAMIC_ENTRY_TAG_RELA_COUNT 0x6FFFFFF9

const char *dynamicEntryTagNamesFrom6FFFFFF9[7] = {
    "Number of Relocation entries with addend",
    "Number of Relocation entries without addend",
    "State flags",
    "Address of version definition table",
    "Number of version definitions",
    "Address of table with needed versions",
    "Number of needed versions"
};

void dumpDynamicEntry(const struct DynamicEntry *entry, const char *stringTable) {
    const char *tagName = (entry->tag >= 0 && entry->tag < DYNAMIC_ENTRY_NUMBER_OF_TAG_NAMES)? dynamicEntryTagNames[entry->tag] :
            (entry->tag >= DYNAMIC_ENTRY_TAG_GNU_STYLE_HASH_TABLE && entry-> tag <= 0x6FFFFEFF)? dynamicEntryTagNamesFrom6FFFFEF5[entry -> tag - DYNAMIC_ENTRY_TAG_GNU_STYLE_HASH_TABLE] :
            (entry->tag >= DYNAMIC_ENTRY_TAG_RELA_COUNT && entry-> tag <= 0x6FFFFFFF)? dynamicEntryTagNamesFrom6FFFFFF9[entry -> tag - DYNAMIC_ENTRY_TAG_RELA_COUNT] :
            "?";
    printf("%s (0x%lx): ", tagName, entry->tag);

    if (entry->tag == DYNAMIC_ENTRY_TAG_NEEDED) {
        printf("%s\n", stringTable + entry->value);
    }
    else if (entry->tag == DYNAMIC_ENTRY_TAG_STRING_TABLE_ADDRESS) {
        printf(".dynstr section (%lu)\n", entry->value);
    }
    else if (entry->tag == DYNAMIC_ENTRY_TAG_SYMBOL_TABLE_ADDRESS) {
        printf(".dynsym section (%lu)\n", entry->value);
    }
    else {
        printf("%lu\n", entry->value);
    }
}

int readProgramEntries(FILE *file, struct ProgramEntry *entries, int entryCount) {
    for (int entryIndex = 0; entryIndex < entryCount; entryIndex++) {
        if (parseProgramEntry(file, &entries[entryIndex])) {
            return 1;
        }
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

int isDynamicProgramEntry(const struct ProgramEntry *entry) {
    return entry->type == PROGRAM_ENTRY_TYPE_DYNAMIC_LINKING_INFORMATION;
}

int isDynSymSectionEntry(const struct SectionEntry *entry, const void *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_DYNAMIC_SYMBOL_TABLE && strcmp(".dynsym", stringTable + entry->name) == 0;
}

int isDynStrSectionEntry(const struct SectionEntry *entry, const void *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_STRING_TABLE && strcmp(".dynstr", stringTable + entry->name) == 0;
}

int isSymTabSectionEntry(const struct SectionEntry *entry, const void *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_SYMBOL_TABLE && strcmp(".symtab", stringTable + entry->name) == 0;
}

int isStrTabSectionEntry(const struct SectionEntry *entry, const void *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_STRING_TABLE && strcmp(".strtab", stringTable + entry->name) == 0;
}

int isRelaDynSectionEntry(const struct SectionEntry *entry, const void *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_RELOCATION_TABLE_WITH_ADDENDS && strcmp(".rela.dyn", stringTable + entry->name) == 0;
}

int isDynamicSectionEntry(const struct SectionEntry *entry, const void *stringTable) {
    return entry->type == SECTION_ENTRY_TYPE_DYNAMIC_TABLE && strcmp(".dynamic", stringTable + entry->name) == 0;
}

int readSymbolEntries64(FILE *file, long offset, struct SymbolEntry64 *entries, int entryCount) {
    if (fseek(file, offset, SEEK_SET)) {
        fprintf(stderr, "Unable to set file position at %lu\n", offset);
        return 1;
    }

    for (int entryIndex = 0; entryIndex < entryCount; entryIndex++) {
        if (parseSymbolEntry64(file, &entries[entryIndex])) {
            return 1;
        }
    }

    return 0;
}

int readRelocationEntries64WithAddend(FILE *file, long offset, struct RelocationEntry64WithAddend *entries, int entryCount) {
    if (fseek(file, offset, SEEK_SET)) {
        fprintf(stderr, "Unable to set file position at %lu\n", offset);
        return 1;
    }

    for (int entryIndex = 0; entryIndex < entryCount; entryIndex++) {
        if (parseRelocationEntry64WithAddend(file, &entries[entryIndex])) {
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

int readProgramAndSectionEntries(FILE *file, FileDetails *fileDetails) {
    struct HeaderX *headerX = &(fileDetails->headerX);
    const short programEntryCount = headerX->programHeaderTableEntryCount;
    const short sectionEntryCount = headerX->sectionHeaderTableEntryCount;

    const int memoryAllocatedSize = sizeof(struct ProgramEntry) * programEntryCount +
            sizeof(struct SectionEntry) * sectionEntryCount;
    void *memoryAllocated = malloc(memoryAllocatedSize);

    if (!memoryAllocated) {
        fprintf(stderr, "Unable to allocate %u bytes\n", memoryAllocatedSize);
        return 1;
    }

    struct ProgramEntry *programEntries = (struct ProgramEntry *) memoryAllocated;
    fileDetails->programEntries = programEntries;

    struct SectionEntry *sectionEntries = memoryAllocated + (sizeof(struct ProgramEntry) * programEntryCount);
    fileDetails->sectionEntries = sectionEntries;

    int result;
    if (result = readProgramEntries(file, programEntries, programEntryCount)) {
        return result;
    }

    int expectedPosition;
    if (headerX->sectionHeaderTable != (expectedPosition = HEADER_FILE_SIZE + HEADERX_FILE_SIZE + PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE * programEntryCount) &&
            fseek(file, headerX->sectionHeaderTable, SEEK_SET)) {
        fprintf(stderr, "Unable to set file position at %lu\n", headerX->sectionHeaderTable);
        return 1;
    }

    if (result = readSectionEntries(file, sectionEntries, sectionEntryCount)) {
        return result;
    }

    const struct SectionEntry *stringTableSection = sectionEntries + headerX->sectionHeaderTableStringTableIndex;
    char *stringTable = malloc(stringTableSection->fileSize);
    if (!stringTable) {
        fprintf(stderr, "Unable to allocate %lu bytes\n", stringTableSection->fileSize);
        return 1;
    }

    fileDetails->stringTable = stringTable;

    if (result = readStringTable(file, stringTableSection, stringTable)) {
        return result;
    }

    const struct SectionEntry *dynSymSection = NULL;
    const struct SectionEntry *dynStrSection = NULL;
    if ((dynSymSection = findSectionEntry(sectionEntries, sectionEntryCount, stringTable, isDynSymSectionEntry)) && !(dynStrSection = findSectionEntry(sectionEntries, sectionEntryCount, stringTable, isDynStrSectionEntry))) {
        fprintf(stderr, ".dynsym section found but .dynstr is missing\n");
        return 1;
    }

    const struct SectionEntry *relaDynSection = findSectionEntry(sectionEntries, sectionEntryCount, stringTable, isRelaDynSectionEntry);
    if (dynSymSection) {
        void *dynSymAllocatedMemory;
        long symbolCount = dynSymSection->fileSize / SYMBOL_ENTRY_64_FILE_SIZE;
        fileDetails->symbolCount = symbolCount;
        const long memoryToAllocate = sizeof(struct SymbolEntry64) * symbolCount + dynStrSection->fileSize;
        if (!(dynSymAllocatedMemory = malloc(memoryToAllocate))) {
            fprintf(stderr, "Unable to allocate %lu bytes for the dynamic symbol table\n", memoryToAllocate);
            return 1;
        }

        fileDetails->symbolEntries = dynSymAllocatedMemory;
        fileDetails->symbolStringTable = dynSymAllocatedMemory + (sizeof(struct SymbolEntry64) * symbolCount);
        if ((result = readSymbolEntries64(file, dynSymSection->offset, fileDetails->symbolEntries, symbolCount)) || (result = readStringTable(file, dynStrSection, fileDetails->symbolStringTable))) {
            return result;
        }
    }

    struct DynamicEntry *dynamicEntries;
    const struct SectionEntry *dynamicSection;
    if (dynamicSection = findSectionEntry(sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, isDynamicSectionEntry)) {
        const struct ProgramEntry *dynamicSegment = findProgramEntry(programEntries, headerX->programHeaderTableEntryCount, isDynamicProgramEntry);
        if (!dynamicSegment || dynamicSegment->offset != dynamicSection->offset || dynamicSegment->fileSize != dynamicSection->fileSize) {
            fprintf(stderr, ".dynamic section offset or size does not match the same info in the program header table\n");
            return 1;
        }

        const long entryCount = dynamicSection->fileSize / DYNAMIC_TABLE_ENTRY_64_FILE_SIZE;
        const long memoryToAllocate = sizeof(struct DynamicEntry) * entryCount;
        if (!(dynamicEntries = malloc(memoryToAllocate))) {
            fprintf(stderr, "Unable to allocate %lu bytes for the dynamic table\n", memoryToAllocate);
            return 1;
        }
        fileDetails->dynamicEntries = dynamicEntries;

        if (readDynamicEntries(file, dynamicSection->offset, dynamicEntries, entryCount)) {
            return 1;
        }

        for (int i = 0; i < entryCount; i++) {
            const long tag = dynamicEntries[i].tag;
            const long value = dynamicEntries[i].value;
            if (tag == DYNAMIC_ENTRY_TAG_STRING_TABLE_ADDRESS && (dynStrSection == NULL || dynStrSection->virtualAddress != value)) {
                fprintf(stderr, "The offset of the string table was expected to match the .dynstr section, but it was %lu\n", value);
                return 1;
            }
            else if (tag == DYNAMIC_ENTRY_TAG_SYMBOL_TABLE_ADDRESS && (dynSymSection == NULL || dynSymSection->virtualAddress != value)) {
                fprintf(stderr, "The offset of the symbol table was expected to match the .dynsym section, but it was %lu\n", value);
                return 1;
            }
            else if (tag == DYNAMIC_ENTRY_TAG_RELADYN_TABLE_ADDRESS && (relaDynSection == NULL || relaDynSection->virtualAddress != value)) {
                fprintf(stderr, "The offset of the relocations with addend table was expected to match the .rela.dyn section, but it was %lu\n", value);
                return 1;
            }
            else if (tag == DYNAMIC_ENTRY_TAG_STRING_TABLE_SIZE && (dynStrSection == NULL || dynStrSection->fileSize < value)) {
                fprintf(stderr, "The size of the string table was expected to match or be lower than the .dynsym section size, but it was %lu\n", value);
                return 1;
            }
            else if (tag == DYNAMIC_ENTRY_TAG_SYMBOL_ENTRY_FILE_SIZE && value != SYMBOL_ENTRY_64_FILE_SIZE) {
                fprintf(stderr, "The size of one symbol was expected to be %u, but it was %lu\n", SYMBOL_ENTRY_64_FILE_SIZE, value);
                return 1;
            }
        }
    }

    const struct SectionEntry *symTabSection;
    if (symTabSection = findSectionEntry(sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, isSymTabSectionEntry)) {
        const struct SectionEntry *strTabSection;
        if (!(strTabSection = findSectionEntry(sectionEntries, headerX->sectionHeaderTableEntryCount, stringTable, isStrTabSectionEntry))) {
            fprintf(stderr, ".symtab section found but .strtab is missing\n");
            return 1;
        }

        long symbolCount = symTabSection->fileSize / SYMBOL_ENTRY_64_FILE_SIZE;
        const long memoryToAllocate = sizeof(struct SymbolEntry64) * symbolCount + strTabSection->fileSize;
        void *symTabAllocatedMemory;
        if (!(symTabAllocatedMemory = malloc(memoryToAllocate))) {
            fprintf(stderr, "Unable to allocate %lu bytes for the dynamic symbol table\n", memoryToAllocate);
            return 1;
        }

        struct SymbolEntry64 *symbolEntries = symTabAllocatedMemory;
        char *symbolStringTable = symTabAllocatedMemory + (sizeof(struct SymbolEntry64) * symbolCount);
        fileDetails->symbolTabCount = symbolCount;
        fileDetails->symbolTabEntries = symbolEntries;
        fileDetails->symbolTabStringTable = symbolStringTable;

        if ((result = readSymbolEntries64(file, symTabSection->offset, symbolEntries, symbolCount)) || (result = readStringTable(file, strTabSection, symbolStringTable))) {
            return result;
        }
    }

    if (relaDynSection) {
        long symbolCount = relaDynSection->fileSize / RELOCATION_ENTRY_64_WITH_ADDEND_FILE_SIZE;
        const long memoryToAllocate = sizeof(struct RelocationEntry64WithAddend) * symbolCount;
        struct RelocationEntry64WithAddend *relocationEntries;
        if (!(relocationEntries = malloc(memoryToAllocate))) {
            fprintf(stderr, "Unable to allocate %lu bytes for the relation table\n", memoryToAllocate);
            return 1;
        }

        fileDetails->relocationCount = symbolCount;
        fileDetails->relocationEntries = relocationEntries;

        if (result = readRelocationEntries64WithAddend(file, relaDynSection->offset, relocationEntries, symbolCount)) {
            return result;
        }
    }

    return result;
}

int readFile(FILE *file, FileDetails *fileDetails) {
    struct Header *header = &(fileDetails->header);
    if (parseHeader(file, header)) {
        return 1;
    }

    // For now we only focus in 64-bit little endian files
    if (header->class != 2) {
        fprintf(stderr, "Unexpected ELF file. It was expected a 64-bit one\n");
        return 1;
    }

    if (header->data != 1) {
        fprintf(stderr, "Unexpected ELF file. It was expected a little endian one\n");
        return 1;
    }

    struct HeaderX *headerX = &(fileDetails->headerX);
    if (parseHeaderX(file, headerX)) {
        return 1;
    }

    if (headerX->programHeaderTable != HEADER_FILE_SIZE + HEADERX_FILE_SIZE) {
        fprintf(stderr, "Program header table was expected to be at position %u\n", HEADER_FILE_SIZE + HEADERX_FILE_SIZE);
        return 1;
    }

    if (headerX->programHeaderTableEntrySize != PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE) {
        fprintf(stderr, "Program header table entry size was expected to be %u. But it was %u\n", PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE, headerX->programHeaderTableEntrySize);
        return 1;
    }

    if (headerX->sectionHeaderTableStringTableIndex >= headerX->sectionHeaderTableEntryCount) {
        fprintf(stderr, "Wrong index for .shstrtab section. Found %u, but it should be lower than %u\n", headerX->sectionHeaderTableStringTableIndex, headerX->sectionHeaderTableEntryCount);
        return 1;
    }

    return readProgramAndSectionEntries(file, fileDetails);
}

int main(int argc, const char *argv[]) {
    FILE *file = fopen(argv[0], "r");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s\n", argv[0]);
        return 1;
    }

    FileDetails fileDetails;
    fileDetails.programEntries = NULL;
    fileDetails.sectionEntries = NULL;
    fileDetails.stringTable = NULL;

    fileDetails.symbolCount = 0;
    fileDetails.symbolEntries = NULL;
    fileDetails.symbolStringTable = NULL;

    fileDetails.dynamicEntries = NULL;

    fileDetails.symbolTabCount = 0;
    fileDetails.symbolTabEntries = NULL;

    fileDetails.relocationCount = 0;
    fileDetails.relocationEntries = NULL;

    const int result = readFile(file, &fileDetails);
    fclose(file);

    if (!result) {
        dumpHeader(&(fileDetails.header));

        printf("\n");
        dumpHeaderX(&fileDetails);

        printf("\nProgram table:\n");
        for (int entryIndex = 0; entryIndex < fileDetails.headerX.programHeaderTableEntryCount; entryIndex++) {
            printf("#%u ", entryIndex);
            dumpProgramEntry(fileDetails.programEntries + entryIndex);
        }

        printf("\nSection table:\n");
        for (int entryIndex = 0; entryIndex < fileDetails.headerX.sectionHeaderTableEntryCount; entryIndex++) {
            printf("#%u ", entryIndex);
            dumpSectionEntry(fileDetails.sectionEntries + entryIndex, fileDetails.stringTable);
        }

        if (fileDetails.dynamicEntries) {
            printf("\nDynamic table (.dynamic):\n");
            struct DynamicEntry *entry;
            for (int entryIndex = 0; (entry = fileDetails.dynamicEntries)[entryIndex].tag; entryIndex++) {
                printf("#%u ", entryIndex);
                dumpDynamicEntry(entry + entryIndex, fileDetails.symbolStringTable);
            }
        }

        if (fileDetails.symbolCount > 0) {
            printf("\nDynamic symbol table (.dynsym):\n");
            for (int entryIndex = 0; entryIndex < fileDetails.symbolCount; entryIndex++) {
                printf("#%u ", entryIndex);
                dumpSymbolEntry64(fileDetails.symbolEntries + entryIndex, fileDetails.symbolStringTable);
            }
        }

        if (fileDetails.symbolTabCount > 0) {
            printf("\nDynamic symbol table (.symtab):\n");
            for (int entryIndex = 0; entryIndex < fileDetails.symbolTabCount; entryIndex++) {
                printf("#%u ", entryIndex);
                dumpSymbolEntry64(fileDetails.symbolTabEntries + entryIndex, fileDetails.symbolTabStringTable);
            }
        }

        if (fileDetails.relocationCount > 0) {
            printf("\nRelocation table (.rela.dyn):\n");
            for (int entryIndex = 0; entryIndex < fileDetails.relocationCount; entryIndex++) {
                printf("#%u ", entryIndex);
                dumpRelocationEntry64WithAddend(&fileDetails, entryIndex);
            }
        }
    }

    if (fileDetails.relocationEntries) {
        free(fileDetails.relocationEntries);
    }

    if (fileDetails.symbolTabEntries) {
        free(fileDetails.symbolTabEntries);
    }

    if (fileDetails.dynamicEntries) {
        free(fileDetails.dynamicEntries);
    }

    if (fileDetails.symbolEntries) {
        free(fileDetails.symbolEntries);
    }

    if (fileDetails.stringTable) {
        free(fileDetails.stringTable);
    }

    if (fileDetails.programEntries) {
        free(fileDetails.programEntries);
    }

    return result;
}
