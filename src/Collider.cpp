#include "Collider.h"
#include "Adler32.h"
#include "Sha256.h"
#include "ThreadPool.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <Windows.h>
#endif

using Stopwatch = std::chrono::high_resolution_clock;

struct Collider
{
public:
    Collider(size_t num_threads, size_t batch_size, size_t lookup_size);

    void AddHash(uint32_t adler, SHA256_Hash sha);
    void NextPart();
    void AddString(const char* data);

    void Run();

    uint64_t GetTotalTeraHashes() const
    {
        return DoneCombinations[1];
    }

    std::unordered_set<std::string> FoundStrings;

private:
    // Using 64-bit indices would increase the memory usage from 5n to 9n
    // For 2^32 values, this would increase usage from 20GB to 36GB
    // So unless you have a huge amount of RAM, stick with a max of 2^32
    // 64-bit division is also slower than 32-bit
    using IndexType = uint32_t;

    void Preprocess();
    void CompileSuffixes();
    void CollideForwards();

    void ReportProgress();

    void PushPrefix(std::span<const std::string_view> suffixes, std::span<const Adler32::HashPart> adlers);
    void PopPrefix();
    void PopSuffix();

    void PushSuffix(std::span<const std::string_view> prefixes);

    template <typename Func>
    void GetPrefix(Func& func, IndexType index, size_t i, IndexType prefix_count) const;

    template <typename Func>
    size_t GetSuffix(Func& func, IndexType index) const;

    template <typename Func>
    size_t GetString(size_t prefix, size_t suffix, Func&& func);

    void Match();
    void Match(size_t start, size_t count);
    void AddMatch(size_t index, uint32_t hash);

    void HashForward(const uint32_t* input, uint32_t* output, size_t count, Adler32::HashPart suffix);
    void HashReverse(
        const uint32_t* input, uint32_t* output, size_t count, const uint8_t* suffix, size_t suffix_length);

    ThreadPool Pool;
    size_t BatchSize {};
    size_t LookupSize {};

    std::unordered_set<std::string> StringPool {};
    std::vector<std::vector<std::string_view>> StringParts {};
    std::vector<std::vector<Adler32::HashPart>> AdlerParts {};

    std::vector<uint32_t> AdlerHashes {};
    std::vector<SHA256_Hash> ShaHashes {};

    std::vector<std::vector<uint32_t>> Prefixes {};
    std::vector<std::vector<uint32_t>> Suffixes {};
    std::vector<std::span<const std::string_view>> CurrentParts {};

    size_t PrefixPos {};
    size_t SuffixPos {};

    using FilterWord = size_t;
    std::vector<FilterWord> SuffixFilter {};

    std::vector<IndexType> SuffixIndices {};
    std::vector<IndexType> SuffixBuckets {};
    std::vector<uint8_t> SuffixBucketEntries {};

    const uint64_t TeraHash = UINT64_C(1000000000000);

    uint64_t DoneCombinations[2] {};
    uint64_t TotalCombinations[2] {};

    Stopwatch::time_point StartTime;
    double NextUpdate = 0.0f;

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

void Collider::PushPrefix(std::span<const std::string_view> suffixes, std::span<const Adler32::HashPart> adlers)
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

void Collider::PopSuffix()
{
    ++SuffixPos;
}

void Collider::PushSuffix(std::span<const std::string_view> prefixes)
{
    std::span<const uint32_t> suffixes = Suffixes[SuffixPos];

    --SuffixPos;
    std::vector<uint32_t>& hashes = Suffixes[SuffixPos];
    CurrentParts[SuffixPos] = prefixes;

    size_t prefix_count = prefixes.size();
    size_t suffix_count = suffixes.size();
    hashes.resize(prefix_count * suffix_count);

    for (size_t i = 0; i < prefix_count; ++i)
    {
        std::string_view prefix = prefixes[i];

        HashReverse(
            suffixes.data(), &hashes[i * suffix_count], suffix_count, (const uint8_t*) prefix.data(), prefix.size());
    }
}

template <typename Func>
void Collider::GetPrefix(Func& func, IndexType index, size_t i, IndexType prefix_count) const
{
    if (i == 0)
    {
        return;
    }

    --i;

    const auto suffixes = CurrentParts[i];
    prefix_count /= (IndexType) suffixes.size();

    std::string_view suffix = suffixes[index / prefix_count];
    index %= prefix_count;

    GetPrefix(func, index, i, prefix_count);
    func(suffix);
}

template <typename Func>
size_t Collider::GetSuffix(Func& func, IndexType index) const
{
    size_t suffix_count = SuffixBucketEntries.size();

    for (size_t i = SuffixPos; i != StringParts.size(); ++i)
    {
        const auto prefixes = CurrentParts[i];
        suffix_count /= prefixes.size();

        std::string_view prefix = prefixes[index / suffix_count];
        index %= suffix_count;

        func(prefix);
    }

    return index;
}

template <typename Func>
size_t Collider::GetString(size_t prefix, size_t suffix, Func&& func)
{
    GetPrefix(func, (IndexType) prefix, PrefixPos, (IndexType) Prefixes[PrefixPos].size());
    return GetSuffix(func, (IndexType) suffix);
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
static void SortHashesWithIndices(uint32_t* hashes, Index* indices, size_t count, uint32_t bit = 32)
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

    SortHashesWithIndices(hashes, indices, pivot, bit);
    SortHashesWithIndices(hashes + pivot, indices + pivot, count - pivot, bit);
}

static double DeltaSeconds(Stopwatch::time_point t1, Stopwatch::time_point t2)
{
    return std::chrono::duration_cast<std::chrono::duration<double>>(t2 - t1).count();
}

Collider::Collider(size_t num_threads, size_t batch_size, size_t lookup_size)
    : Pool(true, num_threads)
    , BatchSize(batch_size)
    , LookupSize(lookup_size)
{
    constexpr size_t limit = (std::numeric_limits<IndexType>::max)();

    if (BatchSize > limit)
    {
        BatchSize = limit;
        printf("Clamped batch size to 0x%zX\n", BatchSize);
    }

    if (LookupSize > limit)
    {
        LookupSize = limit;
        printf("Clamped lookup size to 0x%zX\n", LookupSize);
    }
}

void Collider::AddHash(uint32_t adler, SHA256_Hash sha)
{
    AdlerHashes.push_back(adler);
    ShaHashes.push_back(sha);
}

void Collider::NextPart()
{
    StringParts.emplace_back();
}

void Collider::AddString(const char* data)
{
    StringParts.back().emplace_back(*StringPool.emplace(data).first);
}

void Collider::Preprocess()
{
    auto start = Stopwatch::now();

    for (const auto& part : StringParts)
    {
        AdlerParts.emplace_back();

        for (const auto& str : part)
            AdlerParts.back().push_back(Adler32::Preprocess((const uint8_t*) str.data(), str.size()));
    }

    uint32_t seed = 1;
    Prefixes.resize(StringParts.size() + 1);
    Prefixes[0] = {seed};

    Suffixes.resize(StringParts.size() + 1);
    Suffixes[StringParts.size()] = AdlerHashes;

    PrefixPos = 0;
    SuffixPos = StringParts.size();

    CurrentParts.resize(StringParts.size());

    while (PrefixPos != SuffixPos)
    {
        std::span<const std::string_view> next_prefix = StringParts[PrefixPos];
        std::span<const std::string_view> next_suffix = StringParts[SuffixPos - 1];

        size_t next_prefix_size = Prefixes[PrefixPos].size() * next_prefix.size();
        size_t next_suffix_size = Suffixes[SuffixPos].size() * next_suffix.size();

        bool more_prefixes = next_prefix_size < BatchSize;
        bool more_suffixes = next_suffix_size < LookupSize;

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
            PushSuffix(next_suffix);
        }
        else
        {
            break;
        }
    }

    printf("Preprocessed: %zu/%zu/%zu (%zu/%zu) in %.2f seconds\n", PrefixPos, SuffixPos, StringParts.size(),
        Prefixes[PrefixPos].size(), Suffixes[SuffixPos].size(), DeltaSeconds(start, Stopwatch::now()));

    TotalCombinations[0] = AdlerHashes.size();
    TotalCombinations[1] = 0;

    for (size_t i = 0; i < StringParts.size(); ++i)
    {
        uint64_t n = StringParts[i].size();
        TotalCombinations[0] *= n;
        TotalCombinations[1] *= n;
        TotalCombinations[1] += TotalCombinations[0] / TeraHash;
        TotalCombinations[0] = TotalCombinations[0] % TeraHash;
    }
}

void Collider::CompileSuffixes()
{
    std::span<const uint32_t> suffixes = Suffixes[SuffixPos];

    constexpr size_t NumBuckets = 0x1000000;
    SuffixBuckets.resize(NumBuckets + 1);
    SuffixBuckets[NumBuckets] = (IndexType) suffixes.size();
    SuffixIndices.resize(suffixes.size());
    SuffixBucketEntries.resize(suffixes.size());

    constexpr size_t FilterRadix = sizeof(FilterWord) * CHAR_BIT;
    SuffixFilter.clear();
    SuffixFilter.resize(1 + (UINT32_MAX / FilterRadix));

    std::atomic<IndexType> counts[256 + 1] {};
    counts[256] = (IndexType) suffixes.size();

    Pool.partition(suffixes.size(), 0x100000, [&](size_t start, size_t count) {
        IndexType sub_counts[256] {};

        for (size_t i = start, end = start + count; i < end; ++i)
            ++sub_counts[suffixes[i] >> 24];

        for (size_t i = 0; i < 256; ++i)
        {
            if (IndexType n = sub_counts[i])
                counts[i] += n;
        }
    });

    IndexType total = 0;

    for (size_t i = 0; i < 256; ++i)
        total += counts[i].fetch_add(total);

    Pool.partition(suffixes.size(), 0x100000, [&](size_t start, size_t count) {
        IndexType starts[256] {};

        for (size_t i = start, end = start + count; i < end; ++i)
            ++starts[suffixes[i] >> 24];

        for (size_t i = 0; i < 256; ++i)
        {
            if (IndexType n = starts[i])
                starts[i] = counts[i].fetch_sub(n);
        }

        for (size_t i = start, end = start + count; i < end; ++i)
            SuffixIndices[--starts[suffixes[i] >> 24]] = (IndexType) i;
    });

    Pool.for_n(256, [&](size_t n) {
        IndexType start = counts[n];
        IndexType end = counts[n + 1];

        size_t count = end - start;
        std::vector<uint32_t> sub_hashes(count);

        for (size_t i = 0; i < count; ++i)
            sub_hashes[i] = suffixes[SuffixIndices[start + i]];

        SortHashesWithIndices(sub_hashes.data(), &SuffixIndices[start], sub_hashes.size(), 24);

        IndexType here = 0;

        for (size_t i = 0; i < 65536; ++i)
        {
            size_t j = (n << 16) | i;
            SuffixBuckets[j] = start + here;

            for (; here < count; ++here)
            {
                uint32_t hash = sub_hashes[here];
                bit_set(SuffixFilter.data(), hash);
                SuffixBucketEntries[start + here] = hash & 0xFF;

                if ((hash >> 8) > j)
                    break;
            }
        }
    });
}

static std::atomic_bool g_Running = true;

void Collider::Match()
{
    if (!g_Running)
        return;

    Pool.partition(
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
        SHA256_CTX hasher;
        IndexType suffix = SuffixIndices[find - subs];

        size_t target = GetString(
            index, suffix, [&hasher](std::string_view str) { hasher.Update((const uint8_t*) str.data(), str.size()); });

        if (hasher.Digest() == ShaHashes[target])
        {
            std::string value;
            GetString(index, suffix, [&value](std::string_view str) { value += str; });

            std::lock_guard guard(MatchLock);

            if (auto [iter, added] = FoundStrings.emplace(value); added)
            {
                printf("> %.*s\n", (int) value.size(), value.data());
            }
        }
    }
}

void Collider::Run()
{
    Preprocess();

    printf("Searching... (press Ctrl+C to stop)\n");
    StartTime = Stopwatch::now();
    NextUpdate = 5.0f;

    // Expanding the suffix filter in this way won't reduce the search space.
    // So generally this won't provide a speed-up, unless the suffix filter is very small.
    if ((SuffixPos - PrefixPos) >= 2)
    {
        size_t step = LookupSize / Suffixes[SuffixPos].size();
        std::span<const std::string_view> parts = StringParts[SuffixPos - 1];

        if (step > 1024)
        {
            for (size_t i = 0; i < parts.size();)
            {
                if (!g_Running)
                    return;

                size_t n = (std::min)(step, parts.size() - i);
                PushSuffix({&parts[i], n});
                CompileSuffixes();
                CollideForwards();
                PopSuffix();
                i += n;
            }

            return;
        }
    }

    CompileSuffixes();
    CollideForwards();
}

void Collider::CollideForwards()
{
    if (!g_Running)
        return;

    ReportProgress();

    // printf("Collide %zu/%zu\n", PrefixPos, SuffixPos);

    if (PrefixPos == SuffixPos)
    {
        Match();

        uint64_t checks =
            static_cast<uint64_t>(Prefixes[PrefixPos].size()) * static_cast<uint64_t>(SuffixBucketEntries.size());

        uint64_t accumulator = DoneCombinations[0] + checks;
        DoneCombinations[1] += accumulator / TeraHash;
        DoneCombinations[0] = accumulator % TeraHash;
    }
    else
    {
        std::span<const std::string_view> parts = StringParts[PrefixPos];
        std::span<const Adler32::HashPart> adler_parts = AdlerParts[PrefixPos];

        size_t step = BatchSize / Prefixes[PrefixPos].size();

        for (size_t i = 0; i < parts.size();)
        {
            if (!g_Running)
                return;

            size_t n = (std::min)(step, parts.size() - i);
            PushPrefix({&parts[i], n}, {&adler_parts[i], n});
            CollideForwards();
            PopPrefix();
            i += n;
        }
    }
}

void Collider::ReportProgress()
{
    if (auto delta = DeltaSeconds(StartTime, Stopwatch::now()); delta >= NextUpdate)
    {
        auto done = static_cast<double>(DoneCombinations[1]) / static_cast<double>(TotalCombinations[1]);

        if (done > 0.0001)
        {
            auto remaining = (delta / done) - delta;
            printf("# %5.2f%%, %4.1f mins remaining @ %.2f tH/s\n", done * 100.0f, remaining / 60.0f,
                static_cast<double>(DoneCombinations[1]) / delta);
            NextUpdate = (std::max)(NextUpdate, delta) +
                (std::min)(10.0 + NextUpdate * 0.1, (std::clamp)(remaining * 0.5, 30.0, 300.0));
        }
    }
}

void Collider::HashForward(const uint32_t* input, uint32_t* output, size_t count, Adler32::HashPart suffix)
{
    Pool.partition(count, 0x10000,
        [=](size_t start, size_t count) { Adler32::HashForward(input + start, output + start, count, suffix); });
}

void Collider::HashReverse(
    const uint32_t* input, uint32_t* output, size_t count, const uint8_t* suffix, size_t suffix_length)
{
    Pool.partition(count, 0x10000, [=](size_t start, size_t count) {
        Adler32::HashReverse(input + start, output + start, count, suffix, suffix_length);
    });
}

#ifdef _WIN32
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
#endif

Collider* Collider_Create(size_t num_threads, size_t batch_size, size_t lookup_size)
{
    return new Collider(num_threads, batch_size, lookup_size);
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

size_t Collider_Run(Collider* collider)
{
    g_Running = true;

#ifdef _WIN32
    // Prevent idle timer sleep
    EXECUTION_STATE prev_exec_state = SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);

    // Handle Ctrl+C
    SetConsoleCtrlHandler(CtrlHandler, TRUE);
#endif

    auto start = Stopwatch::now();
    collider->Run();
    auto delta = DeltaSeconds(start, Stopwatch::now());

    size_t total = collider->FoundStrings.size();

    printf("Found %zu results in %.2f seconds, %" PRIu64 " tH @ %.2f tH/s\n", total, delta,
        collider->GetTotalTeraHashes(),
        static_cast<double>(collider->GetTotalTeraHashes()) / static_cast<double>(delta));

#ifdef _WIN32
    SetThreadExecutionState(prev_exec_state);
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
#endif

    return total;
}

void Collider_GetResults(Collider* collider, const char** results)
{
    for (const auto& value : collider->FoundStrings)
        *results++ = value.c_str();
}
