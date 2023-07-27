#pragma once

#include <cstdint>

namespace Adler32
{
    struct HashPart
    {
        uint16_t a;
        uint16_t b;
        uint16_t n;
    };

    HashPart Preprocess(const uint8_t* __restrict data, size_t length);

    void HashForward(const uint32_t* __restrict input, uint32_t* __restrict output, size_t count, HashPart suffix);

    void HashReverse(const uint32_t* __restrict input, uint32_t* __restrict output, size_t count,
        const uint8_t* __restrict suffix, size_t suffix_length);
}; // namespace Adler32
