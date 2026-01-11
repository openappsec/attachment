install(FILES install-nginx-attachment.sh DESTINATION nginx_attachment/ PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ)

execute_process (
        COMMAND sh -c "find /usr/lib* -name \"libbrotli*.so*\" | awk '{printf \$0\";\"}'"
        OUTPUT_VARIABLE brotli
)
install(FILES ${brotli} DESTINATION nginx_attachment/lib)

gen_package(
	install-cp-nano-nginx-attachment.sh
	nginx_attachment
	./install-nginx-attachment.sh
	Check Point Attachment Registration Manager Nano Service Version ${PACKAGE_VERSION} Install Package
)
