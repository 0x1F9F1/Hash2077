#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

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

struct SHA256_CTX
{
    uint8_t data[64];
    size_t datalen = 0;
    uint64_t bitlen = 0;
    uint32_t state[8] {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    void Update(const uint8_t* input, size_t len)
    {
        while (len > 0)
        {
            size_t n = 64 - datalen;

            if (n > len)
                n = len;

            std::memcpy(&data[datalen], input, n);

            datalen += n;
            input += n;
            len -= n;

            if (datalen == 64)
            {
                Transform();
                bitlen += 512;
                datalen = 0;
            }
        }
    }

    void Transform();

    SHA256_Hash Digest();
};
