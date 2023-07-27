cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

project(hash2077 CXX)

if (MSVC)
    add_compile_options(/W4 /MP /permissive- /Zc:throwingNew /utf-8 $<$<CONFIG:Debug>:/Ob1> $<$<CONFIG:MinSizeRel,Release>:/Ob2>)
    add_compile_options(/arch:AVX2)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(src)