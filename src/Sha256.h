#pragma once

#include <cstdint>

struct SHA256_Hash
{
    union
    {
        uint8_t data[32];
        uint32_t data32[8];
    };

    bool operator==(const SHA256_Hash& other) const
    {
        return (data32[0] == other.data32[0]) && (data32[1] == other.data32[1]) && (data32[2] == other.data32[2]) &&
            (data32[3] == other.data32[3]) && (data32[4] == other.data32[4]) && (data32[5] == other.data32[5]) &&
            (data32[6] == other.data32[6]) && (data32[7] == other.data32[7]);
    }

    static SHA256_Hash Hash(const void* data, size_t length);
};