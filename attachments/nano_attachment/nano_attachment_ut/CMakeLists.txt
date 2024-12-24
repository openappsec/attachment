include_directories(${CMAKE_SOURCE_DIR}/attachments/nano_attachment)

add_unit_test(
    nano_attachment_ut
    "nano_attachment_ut.cc"
    "nano_attachment"
)

if( NOT "${PLATFORM_TYPE}" STREQUAL "alpine")
    add_unit_test(
        nano_attachment_io_ut
        "nano_attachment_io_ut.cc"
        "nano_attachment"
    )
endif()

add_unit_test(
    nano_attachment_sender_ut
    "nano_attachment_sender_ut.cc"
    "nano_attachment"
)

add_unit_test(
    nano_thread_ut
    "nano_thread_ut.cc"
    "nano_attachment"
)

add_unit_test(
    nano_sender_thread_ut
    "nano_sender_thread_ut.cc"
    "nano_attachment"
)

add_unit_test(
    nano_configuration_ut
    "nano_configuration_ut.cc"
    "nano_attachment"
)

add_unit_test(
    nano_initializer_ut
    "nano_initializer_ut.cc"
    "nano_attachment"
)

add_unit_test(
    nano_attachment_metrics_ut
    "nano_attachment_metrics_ut.cc"
    "nano_attachment"
)
