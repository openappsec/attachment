cmake_minimum_required(VERSION 2.8.4)
project(ngen)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wno-terminate")

set(CMAKE_CXX_STANDARD 11)

list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
)

find_package(PkgConfig REQUIRED)
find_package(Brotli REQUIRED MODULE)

include_directories(external)
include_directories(core/include/attachments)

add_subdirectory(core)
add_subdirectory(attachments)
add_subdirectory(docker)
add_subdirectory(nodes)
