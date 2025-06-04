message(STATUS "OUTPUT_ENVOY_FILTERS_DOCKER_IMAGE = ${OUTPUT_ENVOY_FILTERS_DOCKER_IMAGE}")

add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/envoy-filters-docker.img
    COMMAND docker build -t envoy-filters-docker -f ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile ${CMAKE_INSTALL_PREFIX}
    COMMAND docker tag envoy-filters-docker ${OUTPUT_ENVOY_FILTERS_DOCKER_IMAGE}
    COMMAND docker image save envoy-filters-docker -o ${CMAKE_INSTALL_PREFIX}/envoy-filters-docker.img
)

add_custom_target(envoy-filters-docker DEPENDS ${CMAKE_INSTALL_PREFIX}/envoy-filters-docker.img)