cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

project(hash2077 CXX)

if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    add_compile_options(
        /W4
        /MP
        /permissive-
        /utf-8
        /Oi
        /arch:AVX2
        $<$<CONFIG:Debug>:/Ob1>
        $<$<CONFIG:MinSizeRel,Release>:/Ob2>
        $<$<CONFIG:MinSizeRel,Release>:/Ot>
        $<$<NOT:$<CONFIG:Debug>>:/Zi>
    )

    add_link_options(
        $<$<NOT:$<CONFIG:Debug>>:/DEBUG>
        $<$<NOT:$<CONFIG:Debug>>:/OPT:REF>
        $<$<NOT:$<CONFIG:Debug>>:/OPT:ICF>
    )
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(src)