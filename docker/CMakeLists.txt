add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/nginx-docker.img
    COMMAND docker build -t nginx-docker ${CMAKE_INSTALL_PREFIX}
    COMMAND docker tag nginx-docker ${OUTPUT_DOCKER_IMAGE}
    COMMAND docker image save nginx-docker -o ${CMAKE_INSTALL_PREFIX}/nginx-docker.img
)

add_custom_target(docker DEPENDS ${CMAKE_INSTALL_PREFIX}/nginx-docker.img)
