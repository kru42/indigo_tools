cmake_minimum_required(VERSION 3.29)
project(indigo_decompiler)

# Debug
set(CMAKE_VERBOSE_MAKEFILE ON)

# Development
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set C++ standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Add source files
file(GLOB_RECURSE SOURCES "src/*.c")

# Add header files
file(GLOB_RECURSE HEADERS "src/*.h")

# Create executable
add_executable(indigo_decompiler ${SOURCES} ${HEADERS})

