cmake_minimum_required(VERSION 3.13)

project(dns-server-starter-cpp)

set(CMAKE_CXX_STANDARD 23) # Enable the C++23 standard

# CONFIGURE_DEPENDS so that adding a module re-runs the glob instead of silently
# compiling a stale source list.
file(GLOB_RECURSE SOURCE_FILES CONFIGURE_DEPENDS src/*.cpp src/*.hpp)

add_executable(dns-server ${SOURCE_FILES})

# Modules include each other by role path ("types/message.hpp"), so src/ is the
# include root.
target_include_directories(dns-server PRIVATE src)
