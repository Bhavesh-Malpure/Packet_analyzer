#ifndef PLATFORM_H
#define PLATFORM_H

// Platform-specific includes and definitions for cross-platform compatibility
// This header provides portable byte-order conversion functions

#include <cstdint>

// Portable byte order conversion
// Works on any platform without requiring system headers
namespace PortableNet {

inline uint16_t swapBytes16(uint16_t value) {
    return ((value & 0xFF00) >> 8) | ((value & 0x00FF) << 8);
}

inline uint32_t swapBytes32(uint32_t value) {
    return ((value & 0xFF000000) >> 24) |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x000000FF) << 24);
}

// Check system endianness at runtime
inline bool isLittleEndian() {
    uint16_t test = 0x0001;
    return *reinterpret_cast<uint8_t*>(&test) == 0x01;
}
