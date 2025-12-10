#include "Collider.h"
#include "Adler32.h"
#include "Sha256.h"
#include "ThreadPool.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

struct StringBuffer
{
    char buffer[2048];
    size_t length = 0;

    void append(const char* data, size_t len)
    {
        if (length + len > std::size(buffer))
        {
            printf("TOO LONG!\n");
            throw std::runtime_error("AAAAA");
        }
        memcpy(&buffer[length], data, len);
        length += len;
    }

    std::string_view str() const
    {
        return {buffer, length};
    }
};

struct Collider
{
public:
    void AddHash(uint32_t adler, SHA256_Hash sha);
    void NextPart();
    void AddString(const char* data);

    void Compile(size_t batch_size, size_t lookup_size);
    void Collide(bool outer = true);

    uint64_t GetTotalTeraHashes() const
    {
        return TeraHashTotal;
    }

    ThreadPool* Pool {};
    std::unordered_set<std::string> FoundStrings;

private:
    void PushPrefix(std::span<const std::string> suffixes, std::span<const Adler32::HashPart> adlers);
    void PopPrefix();

    void PushSuffix(std::vector<uint32_t>& hashes, std::span<const std::string> prefixes);

    void GetPrefix(StringBuffer& buffer, size_t index) const;
    void _GetPrefix(StringBuffer& buffer, size_t index, size_t i, size_t prefix_count) const;
    size_t GetSuffix(StringBuffer& buffer, size_t index) const;

    void Match();
    void Match(size_t start, size_t count);
    void AddMatch(size_t index, uint32_t hash);

    void HashForward(const uint32_t* input, uint32_t* output, size_t count, Adler32::HashPart suffix) const;
    void HashReverse(
        const uint32_t* input, uint32_t* output, size_t count, const uint8_t* suffix, size_t suffix_length) const;

    std::vector<std::vector<std::string>> Parts {};
    std::vector<std::vector<Adler32::HashPart>> AdlerParts {};

    std::vector<uint32_t> AdlerHashes {};
    std::vector<SHA256_Hash> ShaHashes {};

    std::vector<std::vector<uint32_t>> Prefixes {};
    std::vector<std::span<const std::string>> CurrentParts {};

    size_t PrefixPos {};
    size_t SuffixPos {};

    using FilterWord = size_t;
    std::vector<FilterWord> SuffixFilter {};

    // Using 64-bit indices would increase the memory usage from 5n to 9n
    // For 2^32 values, this would increase usage from 20GB to 36GB
    // So unless you have a huge amount of RAM, stick with a max of 2^32
    using SuffixIndex = uint32_t;
    std::vector<SuffixIndex> SuffixIndices {};
    std::vector<SuffixIndex> SuffixBuckets {};
    std::vector<uint8_t> SuffixBucketEntries {};

    uint64_t TeraHashTotal = 0;
    uint64_t HashSubTotal = 0;

    std::mutex MatchLock;
};

template <typename T>
static inline T bit_test(const T* bits, size_t index)
{
    constexpr size_t Radix = sizeof(T) * CHAR_BIT;

#if defined(_MSC_VER) && !defined(__clang__) && (defined(_M_IX86) || defined(_M_X64))
    // `index % Radix` should be a no-op on x86, as it is masked off by shl/shr/bt
    // Yet MSVC still generates a horrible `movzx, and, movzx` sequence
    // Note also, _bittest{64} is not recommended due to its high latency
    return (bits[index / Radix] & (T(1) << (index /*% Radix*/)));
#else
    return (bits[index / Radix] & (T(1) << (index % Radix)));
#endif
}

template <typename T>
static inline void bit_set(T* bits, size_t index)
{
    constexpr size_t Radix = sizeof(T) * CHAR_BIT;

    bits[index / Radix] |= (T(1) << (index % Radix));
}

void Collider::PushPrefix(std::span<const std::string> suffixes, std::span<const Adler32::HashPart> adlers)
{
    size_t suffix_count = suffixes.size();

    std::span<const uint32_t> prefixes = Prefixes[PrefixPos];
    CurrentParts[PrefixPos] = suffixes;

    ++PrefixPos;
    std::vector<uint32_t>& hashes = Prefixes[PrefixPos];

    size_t prefix_count = prefixes.size();
    hashes.resize(prefix_count * suffix_count);

    for (size_t i = 0; i < suffix_count; ++i)
    {
        HashForward(prefixes.data(), &hashes[i * prefix_count], prefix_count, adlers[i]);
    }
}

void Collider::PopPrefix()
{
    --PrefixPos;
}

void Collider::PushSuffix(std::vector<uint32_t>& hashes, std::span<const std::string> prefixes)
{
    size_t prefix_count = prefixes.size();
    size_t suffix_count = hashes.size();
    hashes.resize(suffix_count * prefix_count);

    for (size_t i = prefix_count; i--;)
    {
        std::string_view prefix = prefixes[i];

        HashReverse(
            hashes.data(), &hashes[i * suffix_count], suffix_count, (const uint8_t*) prefix.data(), prefix.size());
    }

    --SuffixPos;
    CurrentParts[SuffixPos] = prefixes;
}

void Collider::_GetPrefix(StringBuffer& buffer, size_t index, size_t i, size_t prefix_count) const
{
    if (i == 0)
    {
        return;
    }

    --i;

    const auto suffixes = CurrentParts[i];
    prefix_count /= suffixes.size();

    std::string_view suffix = suffixes[index / prefix_count];
    index %= prefix_count;

    _GetPrefix(buffer, index, i, prefix_count);

    buffer.append(suffix.data(), suffix.size());
}

void Collider::GetPrefix(StringBuffer& buffer, size_t index) const
{
    size_t prefix_count = Prefixes[PrefixPos].size();

    _GetPrefix(buffer, index, PrefixPos, prefix_count);
}

size_t Collider::GetSuffix(StringBuffer& buffer, size_t index) const
{
    size_t suffix_count = SuffixBucketEntries.size();

    for (size_t i = SuffixPos; i != Parts.size(); ++i)
    {
        const auto prefixes = CurrentParts[i];
        suffix_count /= prefixes.size();

        std::string_view prefix = prefixes[index / suffix_count];
        index %= suffix_count;

        buffer.append(prefix.data(), prefix.size());
    }

    return index;
}

// This sorts two unsigned integer arrays, based on the values of the first array.
// It uses a hybrid sorting algorithm:
// * Large partitions use in-place parallel MSD radix sort
// * Small partitions use insertion sort
//
// This combination was chosen to:
// * Avoid memory allocations
// * Reduce cache misses
// * Enable parallel sorting
//
// The radix sort could be replaced with a different partitioning scheme,
// but this seems unnecessary given that the hashes are expected to be randomly distributed.
template <typename Index>
static void SortHashesWithIndices(
    ThreadPool& pool, uint32_t* hashes, Index* indices, size_t count, uint32_t bit = std::numeric_limits<Index>::digits)
{
    if ((bit == 0) || (count < 16))
    {
        for (size_t i = 1; i < count; ++i)
        {
            uint32_t hash = hashes[i];
            Index index = indices[i];

            size_t j = i;

            for (; (j != 0) && (hash < hashes[j - 1]); --j)
            {
                hashes[j] = hashes[j - 1];
                indices[j] = indices[j - 1];
            }

            hashes[j] = hash;
            indices[j] = index;
        }

        return;
    }

    bit -= 1;

    size_t pivot = count;
    uint32_t mask = uint32_t(1) << bit;

    for (size_t i = 0; i < pivot; ++i)
    {
        uint32_t hash = hashes[i];

        if (hash & mask)
        {
            Index index = indices[i];

            do
            {
                --pivot;

                if (i == pivot)
                    break;

                std::swap(hash, hashes[pivot]);
                std::swap(index, indices[pivot]);
            } while (hash & mask);

            hashes[i] = hash;
            indices[i] = index;
        }
    }

    const auto sort_lower = [=, &pool] { SortHashesWithIndices(pool, hashes, indices, pivot, bit); };
    const auto sort_upper = [=, &pool] {
        SortHashesWithIndices(pool, hashes + pivot, indices + pivot, count - pivot, bit);
    };

    if (pivot > 0x10000)
    {
        pool.run(sort_lower);
    }
    else
    {
        sort_lower();
    }

    sort_upper();
}

using Stopwatch = std::chrono::high_resolution_clock;

static double DeltaSeconds(Stopwatch::time_point t1, Stopwatch::time_point t2)
{
    return std::chrono::duration_cast<std::chrono::duration<double>>(t2 - t1).count();
}

void Collider::AddHash(uint32_t adler, SHA256_Hash sha)
{
    AdlerHashes.push_back(adler);
    ShaHashes.push_back(sha);
}

void Collider::NextPart()
{
    Parts.emplace_back();
}

void Collider::AddString(const char* data)
{
    Parts.back().emplace_back(data);
}

void Collider::Compile(size_t batch_size, size_t lookup_size)
{
    for (const auto& part : Parts)
    {
        AdlerParts.emplace_back();

        for (const auto& str : part)
            AdlerParts.back().push_back(Adler32::Preprocess((const uint8_t*) str.data(), str.size()));
    }

    uint32_t seed = 1;
    Prefixes.resize(Parts.size() + 1);
    Prefixes[0] = {seed};

    std::vector<uint32_t> suffixes = AdlerHashes;

    PrefixPos = 0;
    SuffixPos = Parts.size();

    CurrentParts.resize(Parts.size());

    while (PrefixPos != SuffixPos)
    {
        std::span<const std::string> next_prefix = Parts[PrefixPos];
        std::span<const std::string> next_suffix = Parts[SuffixPos - 1];

        size_t next_prefix_size = Prefixes[PrefixPos].size() * next_prefix.size();
        size_t next_suffix_size = suffixes.size() * next_suffix.size();

        bool more_prefixes = next_prefix_size < batch_size;
        bool more_suffixes = next_suffix_size < lookup_size;

        if (more_prefixes && more_suffixes)
        {
            more_prefixes = next_prefix_size < next_suffix_size;
            more_suffixes = !more_prefixes;
        }

        if (more_prefixes)
        {
            // printf("Expanding Prefixes %zu\n", PrefixPos);
            PushPrefix(next_prefix, AdlerParts[PrefixPos]);
        }
        else if (more_suffixes)
        {
            // printf("Expanding Suffixes %zu\n", SuffixPos - 1);
            PushSuffix(suffixes, next_suffix);
        }
        else
        {
            break;
        }
    }

    size_t prefix_count = Prefixes[PrefixPos].size();
    size_t suffix_count = suffixes.size();

    SuffixIndices.resize(suffix_count);

    for (size_t i = 0; i < suffix_count; ++i)
        SuffixIndices[i] = static_cast<SuffixIndex>(i);

    auto start = Stopwatch::now();

    // printf("Building suffix lookup...\n");
    SortHashesWithIndices(*Pool, suffixes.data(), SuffixIndices.data(), suffix_count);
    Pool->wait();

    // printf("Building suffix filter...\n");

    // Create using sorted hashes to improve cache hits
    constexpr size_t FilterRadix = sizeof(FilterWord) * CHAR_BIT;
    SuffixFilter.resize(1 + (UINT32_MAX / FilterRadix));

    for (size_t i = 0; i < suffix_count; ++i)
        bit_set(SuffixFilter.data(), suffixes[i]);

    // printf("Building suffix buckets...\n");

    constexpr size_t NumBuckets = 0x1000000;
    SuffixBuckets.resize(NumBuckets + 1);
    SuffixBucketEntries.resize(suffixes.size());

    size_t here = 0;

    for (size_t i = 0; i < NumBuckets; ++i)
    {
        for (; here < suffixes.size(); ++here)
        {
            uint32_t hash = suffixes[here];

            if ((hash >> 8) > i)
                break;

            SuffixBucketEntries[here] = hash & 0xFF;
        }

        SuffixBuckets[i + 1] = static_cast<SuffixIndex>(here);
    }

    auto delta = DeltaSeconds(start, Stopwatch::now());
    printf("Compiled: %zu/%zu/%zu (%zu/%zu) in %.2f seconds\n", PrefixPos, SuffixPos, Parts.size(), prefix_count,
        suffix_count, delta);
}

static std::atomic_bool g_Running = true;

void Collider::Match()
{
    if (!g_Running)
        return;

    Pool->partition(
        Prefixes[PrefixPos].size(), 0x10000, [this](size_t start, size_t count) { return Match(start, count); });
}

void Collider::Match(size_t start, size_t count)
{
    if (!g_Running)
        return;

    if (count == 0)
        return;

    const FilterWord* filter = SuffixFilter.data();
    const uint32_t* hashes = Prefixes[PrefixPos].data();

    size_t i = start;
    size_t end = start + count;

    // Prefetch the next hash/filter word to reduce memory latency
    uint32_t next_hash = hashes[i];
    FilterWord next_match = bit_test(filter, next_hash);

    while (i != end)
    {
        uint32_t hash = next_hash;
        FilterWord match = next_match;
        size_t next = i + 1;

        if (next != end) [[likely]]
        {
            next_hash = hashes[next];
            next_match = bit_test(filter, next_hash);
        }

        if (match) [[unlikely]]
            AddMatch(i, hash);

        i = next;
    }
}

void Collider::AddMatch(size_t index, uint32_t hash)
{
    size_t hash_bucket = hash >> 8;
    uint8_t sub_hash = hash & 0xFF;

    const uint8_t* subs = SuffixBucketEntries.data();
    const uint8_t* start = &subs[SuffixBuckets[hash_bucket]];
    const uint8_t* end = &subs[SuffixBuckets[hash_bucket + 1]];
    const uint8_t* find = std::find(start, end, sub_hash);

    for (; (find != end) && (*find == sub_hash); ++find)
    {
        StringBuffer match;
        GetPrefix(match, index);
        size_t target = GetSuffix(match, SuffixIndices[find - subs]);

        std::string_view value = match.str();
        SHA256_Hash sha = SHA256_Hash::Hash(value.data(), value.size());

        if (sha == ShaHashes[target])
        {
            std::lock_guard guard(MatchLock);

            if (auto [iter, added] = FoundStrings.emplace(value); added)
            {
                printf("> %.*s\n", (int) value.size(), value.data());
            }
        }
    }
}

void Collider::Collide(bool outer)
{
    if (!g_Running)
        return;

    // printf("Collide %zu/%zu\n", PrefixPos, SuffixPos);

    if (PrefixPos == SuffixPos)
    {
        Match();

        uint64_t checks =
            static_cast<uint64_t>(Prefixes[PrefixPos].size()) * static_cast<uint64_t>(SuffixBucketEntries.size());

        const uint64_t TeraHash = UINT64_C(1000000000000);
        uint64_t accumulator = HashSubTotal + checks;
        TeraHashTotal += accumulator / TeraHash;
        HashSubTotal = accumulator % TeraHash;
    }
    else
    {
        std::span<const std::string> parts = Parts[PrefixPos];
        std::span<const Adler32::HashPart> adler_parts = AdlerParts[PrefixPos];

        auto start = Stopwatch::now();
        auto total = TeraHashTotal;

        for (size_t i = 0; i < parts.size(); ++i)
        {
            if (!g_Running)
                return;

            if (outer)
            {
                auto now = Stopwatch::now();

                if (auto delta = DeltaSeconds(start, now); delta > 60.0f)
                {
                    printf("Searching... (%.2f%%, %.2f tH/s)\n", static_cast<double>(i) / static_cast<double>(parts.size()),
                        static_cast<double>(TeraHashTotal - total) / delta);
                    start = now;
                    total = TeraHashTotal;
                }
            }

            PushPrefix({&parts[i], 1}, {&adler_parts[i], 1});
            Collide(false);
            PopPrefix();
        }
    }
}

void Collider::HashForward(const uint32_t* input, uint32_t* output, size_t count, Adler32::HashPart suffix) const
{
    Pool->partition(count, 0x10000,
        [=](size_t start, size_t count) { Adler32::HashForward(input + start, output + start, count, suffix); });
}

void Collider::HashReverse(
    const uint32_t* input, uint32_t* output, size_t count, const uint8_t* suffix, size_t suffix_length) const
{
    Pool->partition(count, 0x10000, [=](size_t start, size_t count) {
        Adler32::HashReverse(input + start, output + start, count, suffix, suffix_length);
    });
}

static BOOL WINAPI CtrlHandler(DWORD fdwCtrlType)
{
    if (fdwCtrlType == CTRL_C_EVENT)
    {
        printf("Ctrl+C received, stopping.\n");
        if (g_Running)
        {
            g_Running = false;
            return TRUE;
        }
    }

    return FALSE;
}

Collider* Collider_Create()
{
    return new Collider();
}

void Collider_Destroy(Collider* collider)
{
    delete collider;
}

void Collider_AddHash(Collider* collider, uint32_t adler, const void* sha)
{
    SHA256_Hash sha256;
    memcpy(&sha256, sha, sizeof(sha256));
    collider->AddHash(adler, sha256);
}

void Collider_NextPart(Collider* collider)
{
    collider->NextPart();
}

void Collider_AddString(Collider* collider, const char* string)
{
    collider->AddString(string);
}

size_t Collider_Run(Collider* collider, size_t num_threads, size_t prefix_table_size, size_t suffix_table_size)
{
    g_Running = true;
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    auto start = Stopwatch::now();

    ThreadPool pool {true, num_threads};

    collider->Pool = &pool;
    // printf("Compiling...\n");
    collider->Compile(prefix_table_size, suffix_table_size);

    printf("Searching... (press Ctrl+C to stop)\n");
    collider->Collide();
    collider->Pool = nullptr;

    auto delta = DeltaSeconds(start, Stopwatch::now());

    size_t total = collider->FoundStrings.size();

    printf("Found %llu results in %.2f seconds, %llu tH @ %.2f tH/s\n", total, delta, collider->GetTotalTeraHashes(),
        static_cast<double>(collider->GetTotalTeraHashes()) / static_cast<double>(delta));

    SetConsoleCtrlHandler(CtrlHandler, FALSE);

    return total;
}

void Collider_GetResults(Collider* collider, const char** results)
{
    for (const auto& value : collider->FoundStrings)
        *results++ = value.c_str();
}
