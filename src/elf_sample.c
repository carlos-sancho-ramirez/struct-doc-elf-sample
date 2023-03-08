#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "elf_structs.h"

#define HEADER_FILE_SIZE 16
#define HEADERX_FILE_SIZE 48
#define PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE 56
#define SECTION_HEADER_TABLE_ENTRY_FILE_SIZE 64

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

    if (!memoryAllocated) {
        fprintf(stderr, "Unable to allocate %u bytes\n", memoryAllocatedSize);
        return 1;
    }

    struct ProgramEntry *programEntries = (struct ProgramEntry *) memoryAllocated;
    struct SectionEntry *sectionEntries = memoryAllocated + (sizeof(struct ProgramEntry) * headerX.programHeaderTableEntryCount);

    int result = readProgramEntries(file, programEntries, headerX.programHeaderTableEntryCount);
    if (!result) {
        int expectedPosition;
        if (headerX.sectionHeaderTable != (expectedPosition = HEADER_FILE_SIZE + HEADERX_FILE_SIZE + PROGRAM_HEADER_TABLE_ENTRY_FILE_SIZE * headerX.programHeaderTableEntryCount) &&
                fseek(file, headerX.sectionHeaderTable, SEEK_SET)) {
            fprintf(stderr, "Unable to set file position at %lu\n", headerX.sectionHeaderTable);
            result = 1;
        }
    }

    if (!result) {
        result = readSectionEntries(file, sectionEntries, headerX.sectionHeaderTableEntryCount);
    }

    const struct SectionEntry *stringTableSection;
    unsigned char *stringTable;
    if (!result) {
        stringTableSection = sectionEntries + headerX.sectionHeaderTableStringTableIndex;
        stringTable = malloc(sectionEntries->fileSize);
        if (!stringTable) {
            fprintf(stderr, "Unable to allocate %lu bytes\n", sectionEntries->fileSize);
            result = 1;
        }
    }

    if (!result) {
        result = readStringTable(file, stringTableSection, stringTable);

        if (!result) {
            for (int entryIndex = 0; entryIndex < headerX.sectionHeaderTableEntryCount; entryIndex++) {
                printf("#%u ", entryIndex);
                dumpSectionEntry(sectionEntries + entryIndex, stringTable);
            }
        }

        free(stringTable);
    }

    free(memoryAllocated);
    return result;
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
