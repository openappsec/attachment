add_library(osrc_shmem_ipc SHARED shmem_ipc.c shared_ring_queue.c)

target_link_libraries(osrc_shmem_ipc -lrt)

install(TARGETS osrc_shmem_ipc DESTINATION lib)
install(TARGETS osrc_shmem_ipc DESTINATION nginx_attachment/lib)
