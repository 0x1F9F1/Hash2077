add_library(hash2077 SHARED
    Collider.cpp
    Collider.h
    ThreadPool.cpp
    ThreadPool.h
    Adler32.cpp
    Adler32.h
    Sha256.cpp
    Sha256.h
)

add_custom_command(TARGET hash2077 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:hash2077>" "${CMAKE_SOURCE_DIR}/python"
)