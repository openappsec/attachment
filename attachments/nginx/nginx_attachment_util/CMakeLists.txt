add_definitions(-DUSERSPACE)

add_library(osrc_nginx_attachment_util SHARED nginx_attachment_util.cc)

install(TARGETS osrc_nginx_attachment_util DESTINATION lib)
