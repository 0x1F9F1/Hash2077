#pragma once

#include <cstddef>
#include <cstdint>

#ifdef _WIN32
#    define COLLIDERAPI __declspec(dllexport)
#    define COLLIDERCC __cdecl
#else
#    define COLLIDERAPI __attribute__((__visibility__("default")))
#    define COLLIDERCC
#endif

struct Collider;

extern "C"
{
    COLLIDERAPI Collider* COLLIDERCC Collider_Create(size_t num_threads, size_t batch_size, size_t lookup_size);
    COLLIDERAPI void COLLIDERCC Collider_Destroy(Collider* collider);
    COLLIDERAPI void COLLIDERCC Collider_AddHash(Collider* collider, uint32_t adler, const void* sha);
    COLLIDERAPI void COLLIDERCC Collider_NextPart(Collider* collider);
    COLLIDERAPI void COLLIDERCC Collider_AddString(Collider* collider, const char* string);
    COLLIDERAPI size_t COLLIDERCC Collider_Run(Collider* collider);
    COLLIDERAPI void COLLIDERCC Collider_GetResults(Collider* collider, const char** results);
}
