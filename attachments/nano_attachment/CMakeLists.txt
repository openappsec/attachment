add_subdirectory(nano_attachment_util)

include_directories(include)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE -lpthread -Wall")

link_directories(../../core)
link_directories(../../core/shmem_ipc)
include_directories(../../core/include/attachments)


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
)

target_link_libraries(nano_attachment shmem_ipc_2 nano_attachment_util)

# add_subdirectory(nano_attachment_ut)
# add_subdirectory(manual_testing)

install(TARGETS nano_attachment DESTINATION lib)
install(TARGETS nano_attachment DESTINATION http_transaction_handler_service/lib/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
