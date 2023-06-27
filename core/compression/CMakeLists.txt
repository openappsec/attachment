add_definitions(-DZLIB_CONST)

add_library(osrc_compression_utils SHARED compression_utils.cc)

install(TARGETS osrc_compression_utils DESTINATION lib)
install(TARGETS osrc_compression_utils DESTINATION nginx_attachment/lib)
