cmake_minimum_required(VERSION 3.26)
project(MQALLOC C)

set(CMAKE_C_STANDARD 11)
add_compile_options(/MT /LD)

include_directories("C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.26100.0\\km")
link_directories("C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.26100.0\\um\\x64")

add_library(MQALLOC SHARED mqalloc.c)
target_link_libraries(MQALLOC ntdll)
target_sources(MQALLOC PRIVATE mqalloc.manifest)
