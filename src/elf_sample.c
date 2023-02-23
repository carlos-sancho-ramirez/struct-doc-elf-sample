#include <stdio.h>
#include "elf_structs.h"

#define HEADER_FILE_SIZE 16

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

void dumpHeader(const struct Header *header) {
    printf("Header(class=%u, data=%u, version=%u, osabi=%u, abiVersion=%u)", (int) header->class, (int) header->data, (int) header->version, (int) header->osabi, (int) header->abiVersion);
}

int main(int argc, const char *argv[]) {
    FILE *file = fopen(argv[0], "r");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file %s\n", argv[0]);
        return 1;
    }

    struct Header header;
    const int result = parseHeader(file, &header);
    fclose(file);

    if (!result) {
        dumpHeader(&header);
        printf("\n");
    }

    return result;
}
