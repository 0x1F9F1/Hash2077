#pragma once

#include <cstddef>
#include <cstdint>

#ifdef __AVX2__
#    include <immintrin.h>
#endif

struct SHA256_Hash
{
    union
    {
        uint8_t data[32];
        uint32_t data32[8];
    };

    bool operator==(const SHA256_Hash& other) const
    {
#ifdef __AVX2__
        __m256i value = _mm256_xor_si256(
            _mm256_loadu_si256((const __m256i*) data), _mm256_loadu_si256((const __m256i*) other.data));
        return _mm256_testz_si256(value, value) != 0;
#else
        return (data32[0] == other.data32[0]) && (data32[1] == other.data32[1]) && (data32[2] == other.data32[2]) &&
            (data32[3] == other.data32[3]) && (data32[4] == other.data32[4]) && (data32[5] == other.data32[5]) &&
            (data32[6] == other.data32[6]) && (data32[7] == other.data32[7]);
#endif
    }
};

SHA256_Hash Sha256(const void* data, size_t length);