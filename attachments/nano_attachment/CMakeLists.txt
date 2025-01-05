add_subdirectory(nano_attachment_util)

include_directories(include)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -lpthread -Wall")

link_directories(${ng_module_osrc_zlib_path}/lib)
link_directories(${CMAKE_BINARY_DIR}/core)
link_directories(${CMAKE_BINARY_DIR}/core/shmem_ipc)
include_directories(${PROJECT_SOURCE_DIR}/core/include/attachments)


add_library(
    nano_attachment
    SHARED
    nano_attachment.c
    nano_configuration.c
    nano_initializer.c
    nano_utils.c
    nano_attachment_io.c
    nano_attachment_thread.c
    nano_attachment_sender.c
    nano_attachment_sender_thread.c
    nano_attachment_metric.c
    nano_compression.c
)

target_link_libraries(nano_attachment shmem_ipc_2 nano_attachment_util compression_utils)

# add_subdirectory(nano_attachment_ut)

install(TARGETS nano_attachment DESTINATION lib)
install(TARGETS nano_attachment DESTINATION http_transaction_handler_service/lib/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
