cmake_minimum_required (VERSION 2.8.4)
project (ngen)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

set (CMAKE_CXX_STANDARD 11)

include_directories(external)
include_directories(core/include/attachments)

add_subdirectory(core)
add_subdirectory(attachments)
