#include <stdio.h>
#include <stdint.h>
#include "elf_structs.h"

#define HEADER_FILE_SIZE 16
#define HEADERX_FILE_SIZE 48

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

void dumpHeader(const struct Header *header) {
    printf("Header:\n  class=%u\n  data=%u\n  version=%u\n  osabi=%u\n  abiVersion=%u\n", (int) header->class, (int) header->data, (int) header->version, (int) header->osabi, (int) header->abiVersion);
}

void dumpHeaderX(const struct HeaderX *headerX) {
    printf("HeaderX:\n  type=%u\n  machine=%u\n  version=%u\n  entry=%lu\n  programHeaderTable=%lu\n  sectionHeaderTable=%lu\n  flags=%u\n  headerSize=%u\n  programHeaderTableEntrySize=%u\n  programHeaderTableEntryCount=%u\n  sectionHeaderTableEntrySize=%u\n  sectionHeaderTableEntryCount=%u\n  sectionHeaderTableStringTableIndex=%u\n", (int) headerX->type, (int) headerX->machine, (int) headerX->version, headerX->entry, headerX->programHeaderTable, headerX->sectionHeaderTable, (int) headerX->flags, (int) headerX->headerSize, (int) headerX->programHeaderTableEntrySize, (int) headerX->programHeaderTableEntryCount, (int) headerX->sectionHeaderTableEntrySize, (int) headerX->sectionHeaderTableEntryCount, (int) headerX->sectionHeaderTableStringTableIndex);
}

int main(int argc, const char *argv[]) {
    FILE *file = fopen(argv[0], "r");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s\n", argv[0]);
        return 1;
    }

    struct Header header;
    if (parseHeader(file, &header)) {
        fclose(file);
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
        fclose(file);
        return 1;
    }

    dumpHeaderX(&headerX);
    fclose(file);
    return 0;
}
