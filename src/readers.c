#include "readers.h"

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
