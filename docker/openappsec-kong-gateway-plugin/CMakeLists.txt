message(STATUS "OUTPUT_KONG_PLUGIN_DOCKER_IMAGE = ${OUTPUT_KONG_PLUGIN_DOCKER_IMAGE}")
add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/kong-gateway-plugin-docker.img
    COMMAND docker build --load -t kong-gateway-plugin-docker --network host -f ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile ${CMAKE_INSTALL_PREFIX}
    COMMAND docker tag kong-gateway-plugin-docker ${OUTPUT_KONG_PLUGIN_DOCKER_IMAGE}
    COMMAND docker image save kong-gateway-plugin-docker -o ${CMAKE_INSTALL_PREFIX}/kong-gateway-plugin-docker.img
)

add_custom_target(kong-gateway-plugin-docker DEPENDS ${CMAKE_INSTALL_PREFIX}/kong-gateway-plugin-docker.img)