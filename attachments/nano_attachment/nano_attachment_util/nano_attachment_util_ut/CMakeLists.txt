include_directories(${Boost_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/attachments/nano_attachment/nano_attachment_util)

add_unit_test(
    nano_attachment_util_ut
    "nano_attachment_util_ut.cc"
    "nano_attachment_util"
)
