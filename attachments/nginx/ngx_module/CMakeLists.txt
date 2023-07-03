MACRO(CREATE_INCLUDE_LIST result)
    file(READ ${CMAKE_INSTALL_PREFIX}/nginx-src/include_paths.mk relative_includes)
    STRING(REGEX REPLACE "\n" ";" relative_includes "${relative_includes}")
    set(inclist "")
    FOREACH(include ${relative_includes})
        if(NOT include MATCHES "^/")
            set(inclist ${inclist} "${CMAKE_INSTALL_PREFIX}/nginx-src/${include}")
        else()
            set(inclist ${inclist} "${include}")
        endif()
    ENDFOREACH()
    set(${result} ${inclist})
ENDMACRO()

MACRO(READ_COMPILE_FLAGS result)
    file(READ ${CMAKE_INSTALL_PREFIX}/nginx-src/cc_flags.mk CC_FLAGS)
    string(REGEX REPLACE "\n" "" CC_FLAGS "${CC_FLAGS}")
    set(flag_list "")
    FOREACH(flag ${CC_FLAGS})
        if (flag MATCHES "-fstack-clash-protection" OR flag MATCHES "-fcf-protection" OR flag MATCHES "-Wno-cast-function-type")
            continue()
        endif()

        set(flag_list ${flag_list} "${flag}")
    ENDFOREACH()
    separate_arguments(flag_list)
    set(${result} ${flag_list})
ENDMACRO()

add_library(
	ngx_module
	SHARED
	ngx_http_cp_attachment_module.c ngx_cp_thread.c ngx_cp_hook_threads.c ngx_cp_hooks.c ngx_cp_utils.c
	ngx_cp_initializer.c ngx_cp_io.c ngx_cp_static_content.c ngx_cp_custom_response.c ngx_modules.c
	ngx_cp_compression.c ngx_cp_http_parser.c ngx_cp_failing_state.c ngx_cp_metric.c
)

add_dependencies(ngx_module osrc_shmem_ipc osrc_nginx_attachment_util osrc_compression_utils)

target_link_libraries(ngx_module osrc_shmem_ipc osrc_nginx_attachment_util osrc_compression_utils)

CREATE_INCLUDE_LIST(NGX_INCLUDES)
READ_COMPILE_FLAGS(CC_FLAG_LIST)

target_include_directories(ngx_module PRIVATE ${NGX_INCLUDES})
target_compile_options(ngx_module PRIVATE ${CC_FLAG_LIST})

install(TARGETS ngx_module DESTINATION lib)
install(TARGETS ngx_module DESTINATION nginx_attachment/lib)
