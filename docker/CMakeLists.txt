add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/nginx-docker.img
    COMMAND docker build -t nginx-docker ${CMAKE_INSTALL_PREFIX}
    COMMAND docker tag nginx-docker ${OUTPUT_DOCKER_IMAGE}
    COMMAND docker image save nginx-docker -o ${CMAKE_INSTALL_PREFIX}/nginx-docker.img
)

add_custom_target(docker DEPENDS ${CMAKE_INSTALL_PREFIX}/nginx-docker.img)

add_subdirectory(openappsec-envoy-attachments)
add_subdirectory(openappsec-waf-webhook)
add_subdirectory(openappsec-kong-plugin)
