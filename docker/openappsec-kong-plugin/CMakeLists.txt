message(STATUS "OUTPUT_KONG_PLUGIN_DOCKER_IMAGE = ${OUTPUT_KONG_PLUGIN_DOCKER_IMAGE}")
add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/kong-plugin-docker.img
    COMMAND docker buildx build --load -t kong-plugin-docker -f ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile ${CMAKE_INSTALL_PREFIX}
    COMMAND docker tag kong-plugin-docker ${OUTPUT_KONG_PLUGIN_DOCKER_IMAGE}
    COMMAND docker image save kong-plugin-docker -o ${CMAKE_INSTALL_PREFIX}/kong-plugin-docker.img
)

add_custom_target(kong-plugin-docker DEPENDS ${CMAKE_INSTALL_PREFIX}/kong-plugin-docker.img)