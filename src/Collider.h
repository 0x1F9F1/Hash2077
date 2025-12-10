#pragma once

#include <cstddef>
#include <cstdint>

#ifdef _WIN32
#    define COLLIDERAPI __declspec(dllexport)
#else
#    define COLLIDERAPI __attribute__((__visibility__("default")))
#endif

struct Collider;

extern "C"
{
    COLLIDERAPI Collider* Collider_Create();
    COLLIDERAPI void Collider_Destroy(Collider* collider);
    COLLIDERAPI void Collider_AddHash(Collider* collider, uint32_t adler, const void* sha);
    COLLIDERAPI void Collider_NextPart(Collider* collider);
    COLLIDERAPI void Collider_AddString(Collider* collider, const char* string);
    COLLIDERAPI size_t Collider_Run(
        Collider* collider, size_t num_threads, size_t prefix_table_size, size_t suffix_table_size);
    COLLIDERAPI void Collider_GetResults(Collider* collider, const char** results);
}
