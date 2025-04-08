add_custom_command(
    OUTPUT ${CMAKE_INSTALL_PREFIX}/waf-webhook-docker.img
    COMMAND docker build -t waf-webhook-docker -f ${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile ${CMAKE_INSTALL_PREFIX}
    COMMAND docker tag waf-webhook-docker ${OUTPUT_WEBHOOK_DOCKER_IMAGE}
    COMMAND docker image save waf-webhook-docker -o ${CMAKE_INSTALL_PREFIX}/waf-webhook-docker.img
)

add_custom_target(waf-webhook-docker DEPENDS ${CMAKE_INSTALL_PREFIX}/waf-webhook-docker.img)
