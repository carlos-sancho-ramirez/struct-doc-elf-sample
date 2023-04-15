#ifndef _READERS_H_
#define _READERS_H_

#include <stdint.h>

uint16_t readWord16LittleEndian(const void *addr);
uint32_t readWord32LittleEndian(const void *addr);
uint64_t readWord64LittleEndian(const void *addr);

#endif // _READERS_H_
