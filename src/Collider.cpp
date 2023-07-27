#include "Collider.h"
#include "Adler32.h"
#include "Sha256.h"
#include "ThreadPool.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

using String = std::string;
using StringView = std::string_view;

template <typename T>
using Vec = std::vector<T>;

template <typename T, typename U>
using Pair = std::pair<T, U>;

using FilterWord = size_t;

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

    StringView str() const
    {
        return {buffer, length};
    }
};

struct Adler32AndSha256
{
    uint32_t adler;
    SHA256_Hash sha;
};

struct Collider
{
public:
    Collider();

    void AddHash(uint32_t adler, SHA256_Hash sha);
    void NextPart();
    void AddString(const char* data);

    void Compile(size_t prefix_table_size, size_t suffix_table_size);
    void Collide();

    uint64_t GetTotalTeraHashes() const
    {
        return TeraHashTotal;
    }

    ThreadPool* Pool {};
    std::unordered_set<String> FoundStrings;

private:
    void PushPrefix(const String* suffixes, const Adler32::HashPart* suffixes2, size_t suffix_count);
    void PopPrefix();

    void PushSuffix(const String* prefixes, size_t prefix_count);

    void GetPrefix(StringBuffer& buffer, size_t index) const;
    void _GetPrefix(StringBuffer& buffer, size_t index, size_t i, size_t prefix_count) const;
    size_t GetSuffix(StringBuffer& buffer, size_t index) const;

    void Match();
    void Match(size_t start, size_t count);
    void AddMatch(size_t index, uint32_t hash);

    void HashForward(const uint32_t* input, uint32_t* output, size_t count, Adler32::HashPart suffix) const;
    void HashReverse(
        const uint32_t* input, uint32_t* output, size_t count, const uint8_t* suffix, size_t suffix_length) const;

    Vec<Vec<String>> Parts {};
    Vec<Vec<Adler32::HashPart>> AdlerParts {};

    Vec<uint32_t> Suffixes {};
    Vec<SHA256_Hash> ShaHashes {};

    Vec<Vec<uint32_t>> Prefixes {};
    Vec<std::span<const String>> CurrentParts {};

    size_t PrefixPos {};
    size_t SuffixPos {};

    Vec<FilterWord> Filter {};

    Vec<uint32_t> HashIndices {};
    Vec<uint32_t> HashBuckets {};
    Vec<uint8_t> SubHashes {};

    uint64_t TeraHashTotal = 0;
    uint64_t HashSubTotal = 0;

    std::atomic<size_t> TotalEntries = 0;
    std::atomic<size_t> TotalChars = 0;
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

Collider::Collider()
{
    //Parts = std::move(parts);

    //for (auto& hash : hashes)
    //{
    //    Suffixes.push_back(hash.adler);
    //    ShaHashes.push_back(hash.sha);
    //}
}

void Collider::PushPrefix(const String* suffixes, const Adler32::HashPart* suffixes2, size_t suffix_count)
{
    const Vec<uint32_t>& prefixes = Prefixes[PrefixPos];
    CurrentParts[PrefixPos] = {suffixes, suffix_count};

    ++PrefixPos;
    Vec<uint32_t>& hashes = Prefixes[PrefixPos];

    size_t prefix_count = prefixes.size();
    hashes.resize(prefix_count * suffix_count);

    for (size_t i = 0; i < suffix_count; ++i)
    {
        HashForward(prefixes.data(), &hashes[i * prefix_count], prefix_count, suffixes2[i]);
    }
}

void Collider::PopPrefix()
{
    --PrefixPos;
}

void Collider::PushSuffix(const String* prefixes, size_t prefix_count)
{
    size_t suffix_count = Suffixes.size();

    Vec<uint32_t> suffixes;
    suffixes.resize(suffix_count * prefix_count);

    for (size_t i = 0; i < prefix_count; ++i)
    {
        StringView prefix = prefixes[i];

        HashReverse(
            Suffixes.data(), &suffixes[i * suffix_count], suffix_count, (const uint8_t*) prefix.data(), prefix.size());
    }

    Suffixes.swap(suffixes);

    --SuffixPos;
    CurrentParts[SuffixPos] = {prefixes, prefix_count};
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

    StringView suffix = suffixes[index / prefix_count];
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
    size_t suffix_count = SubHashes.size();

    for (size_t i = SuffixPos; i != Parts.size(); ++i)
    {
        const auto prefixes = CurrentParts[i];
        suffix_count /= prefixes.size();

        StringView prefix = prefixes[index / suffix_count];
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
static void SortHashesWithIndices(ThreadPool& pool, uint32_t* hashes, uint32_t* indices, size_t count, uint32_t bit)
{
    if ((bit == 0) || (count < 16))
    {
        for (size_t i = 1; i < count; ++i)
        {
            uint32_t hash = hashes[i];
            uint32_t index = indices[i];

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
            uint32_t index = indices[i];

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
    Suffixes.push_back(adler);
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

void Collider::Compile(size_t prefix_table_size, size_t suffix_table_size)
{
    for (const auto& part : Parts)
    {
        Vec<Adler32::HashPart> adler {};

        for (const auto& str : part)
            adler.push_back(Adler32::Preprocess((const uint8_t*) str.data(), str.size()));

        AdlerParts.push_back(adler);
    }

    uint32_t seed = 1;
    Prefixes.resize(Parts.size() + 1);
    Prefixes[0] = {seed};

    PrefixPos = 0;
    SuffixPos = Parts.size();

    CurrentParts.resize(Parts.size());

    while (PrefixPos != SuffixPos)
    {
        const Vec<String>& next_prefix = Parts[PrefixPos];
        const Vec<String>& next_suffix = Parts[SuffixPos - 1];

        size_t next_prefix_size = Prefixes[PrefixPos].size() * next_prefix.size();
        size_t next_suffix_size = Suffixes.size() * next_suffix.size();

        bool more_prefixes = next_prefix_size < prefix_table_size;
        bool more_suffixes = next_suffix_size < suffix_table_size;

        if (more_prefixes && more_suffixes)
        {
            more_prefixes = next_prefix_size < next_suffix_size;
            more_suffixes = !more_prefixes;
        }

        if (more_prefixes)
        {
            printf("Expanding Prefixes %zu\n", PrefixPos);
            PushPrefix(next_prefix.data(), AdlerParts[PrefixPos].data(), next_prefix.size());
        }
        else if (more_suffixes)
        {
            printf("Expanding Suffixes %zu\n", SuffixPos - 1);
            PushSuffix(next_suffix.data(), next_suffix.size());
        }
        else
        {
            break;
        }
    }

    size_t prefix_count = Prefixes[PrefixPos].size();
    size_t suffix_count = Suffixes.size();

    HashIndices.resize(suffix_count);

    for (size_t i = 0; i < suffix_count; ++i)
        HashIndices[i] = static_cast<uint32_t>(i);

    auto start = Stopwatch::now();

    printf("Building suffix lookup...\n");
    SortHashesWithIndices(*Pool, Suffixes.data(), HashIndices.data(), suffix_count, 32);
    Pool->wait();

    printf("Building suffix filter...\n");

    // Create using sorted hashes to improve cache hits
    constexpr size_t FilterRadix = sizeof(FilterWord) * CHAR_BIT;
    Filter.resize(1 + (UINT32_MAX / FilterRadix));

    for (size_t i = 0; i < suffix_count; ++i)
        bit_set(Filter.data(), Suffixes[i]);

    printf("Building suffix buckets...\n");

    constexpr size_t NumBuckets = 0x1000000;

    HashBuckets.resize(NumBuckets + 1);
    SubHashes.resize(Suffixes.size());

    size_t here = 0;

    for (size_t i = 0; i < NumBuckets; ++i)
    {
        for (; here < Suffixes.size(); ++here)
        {
            uint32_t hash = Suffixes[here];

            if ((hash >> 8) > i)
                break;

            SubHashes[here] = hash & 0xFF;
        }

        HashBuckets[i + 1] = static_cast<uint32_t>(here);
    }

    auto delta = DeltaSeconds(start, Stopwatch::now());

    printf("Built lookup in %.2f seconds\n", delta);

    Suffixes = {};

    printf("Compiled: %zu/%zu (%zu/%zu)\n", PrefixPos, SuffixPos, prefix_count, suffix_count);
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

    const FilterWord* filter = Filter.data();
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

    const uint8_t* subs = SubHashes.data();
    const uint8_t* start = &subs[HashBuckets[hash_bucket]];
    const uint8_t* end = &subs[HashBuckets[hash_bucket + 1]];
    const uint8_t* find = std::find(start, end, sub_hash);

    for (; (find != end) && (*find == sub_hash); ++find)
    {
        StringBuffer match;
        GetPrefix(match, index);
        size_t target = GetSuffix(match, HashIndices[find - subs]);

        StringView value = match.str();
        SHA256_Hash sha = SHA256_Hash::Hash(value.data(), value.size());

        if (sha == ShaHashes[target])
        {
            std::lock_guard guard(MatchLock);

            if (auto [iter, added] = FoundStrings.emplace(value); added)
            {
                printf("Found %.*s\n", (int) value.size(), value.data());
                ++TotalEntries;
                TotalChars += value.size();
            }
        }
    }
}

void Collider::Collide()
{
    if (!g_Running)
        return;

    // printf("Collide %zu/%zu\n", PrefixPos, SuffixPos);

    if (PrefixPos == SuffixPos)
    {
        [[maybe_unused]] size_t before = TotalEntries;
        Match();
        [[maybe_unused]] size_t after = TotalEntries;

        uint64_t checks = static_cast<uint64_t>(Prefixes[PrefixPos].size()) * static_cast<uint64_t>(SubHashes.size());

        const uint64_t TeraHash = UINT64_C(1000000000000);
        uint64_t accumulator = HashSubTotal + checks;
        TeraHashTotal += accumulator / TeraHash;
        HashSubTotal = accumulator % TeraHash;

        // printf("Matches %zu/%zu (%zu MB), %llu tH\n", after - before, after, found.TotalChars >> 20, TeraHashTotal);
    }
    else
    {
        for (size_t i = 0; i < Parts[PrefixPos].size(); ++i)
        {
            if (!g_Running)
                return;

            PushPrefix(&Parts[PrefixPos][i], &AdlerParts[PrefixPos][i], 1);
            Collide();
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
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    auto start = Stopwatch::now();

    ThreadPool pool {num_threads};

    collider->Pool = &pool;
    printf("Compiling...\n");
    collider->Compile(prefix_table_size, suffix_table_size);

    printf("Searching\n");
    collider->Collide();
    collider->Pool = nullptr;

    auto delta = DeltaSeconds(start, Stopwatch::now());

    printf("Done!\n");

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
