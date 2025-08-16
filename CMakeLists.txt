cmake_minimum_required(VERSION 3.26)
project(MQALLOC C)

set(CMAKE_C_STANDARD 11)
add_compile_options(/MT /LD /W4 /WX)

add_library(MQALLOC SHARED mqalloc.c)
target_link_libraries(MQALLOC ntdll)
target_sources(MQALLOC PRIVATE mqalloc.manifest)
