#include "Adler32.h"

#ifdef __AVX2__
#    include <immintrin.h>
#endif

Adler32::HashPart Adler32::Preprocess(const uint8_t* data, size_t length)
{
    uint32_t a = 0;
    uint32_t b = 0;

    for (size_t i = 0; i < length; ++i)
    {
        uint8_t v = data[i];
        a += v;
        b += v * static_cast<uint32_t>(length - i);
    }

    return {static_cast<uint16_t>(a % 65521), static_cast<uint16_t>(b % 65521), static_cast<uint16_t>(length)};
}

void Adler32::HashForward(const uint32_t* input, uint32_t* output, size_t count, HashPart suffix)
{
    size_t here = 0;

#ifdef __AVX2__
    const __m256i mask = _mm256_set1_epi32(0xFFFF);
    const __m256i modulo = _mm256_set1_epi32(65521);
    const __m256i maxval = _mm256_set1_epi32(65521 - 1);

    for (; (count - here) >= 8; here += 8)
    {
        __m256i hashes = _mm256_loadu_si256((const __m256i*) &input[here]);
        __m256i a = _mm256_and_si256(hashes, mask);
        __m256i b = _mm256_srli_epi32(hashes, 16);

        {
            __m256i n = _mm256_set1_epi32(suffix.n);
            __m256i t = _mm256_mulhi_epu16(a, n);
            b = _mm256_add_epi32(
                b, _mm256_add_epi32(_mm256_mullo_epi16(a, n), _mm256_sub_epi32(_mm256_slli_epi32(t, 4), t)));
        }

        b = _mm256_add_epi32(b, _mm256_set1_epi32(suffix.b));

        {
            __m256i t = _mm256_srli_epi32(b, 16);
            b = _mm256_add_epi32(_mm256_and_si256(b, mask), _mm256_sub_epi32(_mm256_slli_epi32(t, 4), t));
        }
        b = _mm256_sub_epi32(b, _mm256_and_si256(_mm256_cmpgt_epi32(b, maxval), modulo));

        a = _mm256_add_epi32(a, _mm256_set1_epi32(suffix.a));
        a = _mm256_sub_epi32(a, _mm256_and_si256(_mm256_cmpgt_epi32(a, maxval), modulo));

        hashes = _mm256_or_si256(a, _mm256_slli_epi32(b, 16));
        _mm256_storeu_si256((__m256i*) &output[here], hashes);
    }
#endif

    for (; here != count; ++here)
    {
        uint32_t hash = input[here];
        uint32_t a = hash & 0xFFFF;
        uint32_t b = hash >> 16;

        b += a * suffix.n;
        b += suffix.b;
        b %= 65521;

        a += suffix.a;
        a %= 65521;

        hash = (b << 16) | a;
        output[here] = hash;
    }
}

void Adler32::HashReverse(const uint32_t* input, uint32_t* output, size_t count, HashPart suffix)
{
    size_t here = 0;

#ifdef __AVX2__
    const __m256i mask = _mm256_set1_epi32(0xFFFF);
    const __m256i modulo = _mm256_set1_epi32(65521);
    const __m256i maxval = _mm256_set1_epi32(65521 - 1);

    for (; (count - here) >= 8; here += 8)
    {
        __m256i hashes = _mm256_loadu_si256((const __m256i*) &input[here]);
        __m256i a = _mm256_and_si256(hashes, mask);
        __m256i b = _mm256_srli_epi32(hashes, 16);

        a = _mm256_add_epi32(a, _mm256_set1_epi32(65521 - suffix.a));
        a = _mm256_sub_epi32(a, _mm256_and_si256(_mm256_cmpgt_epi32(a, maxval), modulo));

        b = _mm256_add_epi32(b, _mm256_set1_epi32(65521 - suffix.b));

        {
            __m256i n = _mm256_set1_epi32(65521 - suffix.n);
            __m256i t = _mm256_mulhi_epu16(a, n);
            b = _mm256_add_epi32(
                b, _mm256_add_epi32(_mm256_mullo_epi16(a, n), _mm256_sub_epi32(_mm256_slli_epi32(t, 4), t)));
        }

        {
            __m256i t = _mm256_srli_epi32(b, 16);
            b = _mm256_add_epi32(_mm256_and_si256(b, mask), _mm256_sub_epi32(_mm256_slli_epi32(t, 4), t));
        }
        b = _mm256_sub_epi32(b, _mm256_and_si256(_mm256_cmpgt_epi32(b, maxval), modulo));

        hashes = _mm256_or_si256(a, _mm256_slli_epi32(b, 16));
        _mm256_storeu_si256((__m256i*) &output[here], hashes);
    }
#endif

    for (; here != count; ++here)
    {
        uint32_t hash = input[here];
        uint32_t a = hash & 0xFFFF;
        uint32_t b = hash >> 16;

        a += 65521 - suffix.a;
        a %= 65521;

        b += 65521 - suffix.b;
        b += a * (65521 - suffix.n);
        b %= 65521;

        hash = (b << 16) | a;
        output[here] = hash;
    }
}
