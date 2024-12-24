add_library(shmem_ipc_2 SHARED shmem_ipc.c shared_ring_queue.c)

target_link_libraries(shmem_ipc_2 -lrt)

install(TARGETS shmem_ipc_2 DESTINATION lib)
install(TARGETS shmem_ipc_2 DESTINATION http_transaction_handler_service/lib/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
