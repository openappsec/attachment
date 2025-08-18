if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" AND ATTACHMENT_TYPE STREQUAL "envoy")    
    set(ATTACHMENTS_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/core/include/attachments)
    set(NANO_ATTACHMENT_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/attachments/nano_attachment)
    set(SHMEM_LIBRARY_DIR ${CMAKE_BINARY_DIR}/core/shmem_ipc_2)
    set(NANO_ATTACHMENT_LIBRARY_DIR ${CMAKE_BINARY_DIR}/attachments/nano_attachment)
    set(NANO_ATTACHMENT_UTIL_LIBRARY_DIR ${CMAKE_BINARY_DIR}/attachments/nano_attachment/nano_attachment_util)
    set(LIBRARIES "-lnano_attachment -lnano_attachment_util -lshmem_ipc_2")
    set(ENVOY_ATTACHMENT_DIR ${CMAKE_CURRENT_SOURCE_DIR})

    get_filename_component(CURRENT_DIR ${CMAKE_CURRENT_SOURCE_DIR} NAME)

    # Configure the build.sh script from the template
    configure_file(
        ${PROJECT_SOURCE_DIR}/attachments/envoy/${CURRENT_DIR}/build_template
        ${CMAKE_BINARY_DIR}/attachments/envoy/${CURRENT_DIR}/build.sh
        @ONLY
    )

    # Define a custom command to run the bash script
    add_custom_target(
        envoy_attachment${CURRENT_DIR} ALL
        COMMAND chmod +x ${CMAKE_BINARY_DIR}/attachments/envoy/${CURRENT_DIR}/build.sh
        COMMAND ${CMAKE_BINARY_DIR}/attachments/envoy/${CURRENT_DIR}/build.sh
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/attachments/envoy
        COMMENT "Building envoy attachment ${CURRENT_DIR}"
    )

    add_dependencies(envoy_attachment${CURRENT_DIR} shmem_ipc_2 nano_attachment nano_attachment_util)

    install(FILES libenvoy_attachment.so DESTINATION ${CMAKE_BINARY_DIR}/attachments/envoy/${CURRENT_DIR} PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
    install(FILES libenvoy_attachment.so DESTINATION envoy/${CURRENT_DIR} PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)
endif()

