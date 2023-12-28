#!/bin/sh

#Attachment Detials
ATTACHMENT_NAME="NGINX Attachemnt"
ATTACHMENT_BIN_NAME="cp-nano-nginx-attachment"

#Const variables
FORCE_STDOUT=true
INSTALLATION_TIME=$(date)
CP_NANO_LOG_PATH="/var/log/nano_agent"
INSTALLATION_LOG_FILE=${CP_NANO_LOG_PATH}/${ATTACHMENT_BIN_NAME}-install.log

mkdir -p ${CP_NANO_LOG_PATH}

cp_print()
{
    var_text=$1
    var_std_out=$2
    touch $INSTALLATION_LOG_FILE
    if [ -n "$var_std_out" ]; then
        if [ "$var_std_out" = "true" ]; then
            printf "%b\n" "$var_text"
        fi
    fi
    printf "%b\n" "$var_text" >> $INSTALLATION_LOG_FILE
}

cp_exec()
{
    var_cmd=$1
    var_std_out=$2
    # Send exec output to RES
    RES=$($var_cmd 2>&1)
    if [ -n "$RES" ]; then
        cp_print "$RES" "$var_std_out"
    fi
}

run_installation()
{
    cp_print "Starting installation of Check Point ${NANO_SERVICE_NAME} Nano service [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    cp_exec "cp lib/libosrc_compression_utils.so /usr/lib/libosrc_compression_utils.so"
    cp_exec "cp lib/libosrc_compression_utils.so /usr/lib64/libosrc_compression_utils.so"
    cp_exec "cp lib/libosrc_nginx_attachment_util.so /usr/lib/libosrc_nginx_attachment_util.so"
    cp_exec "cp lib/libosrc_nginx_attachment_util.so /usr/lib64/libosrc_nginx_attachment_util.so"
    cp_exec "cp lib/libosrc_shmem_ipc.so /usr/lib/libosrc_shmem_ipc.so"
    cp_exec "cp lib/libosrc_shmem_ipc.so /usr/lib64/libosrc_shmem_ipc.so"
    cp_exec "mkdir -p /usr/lib/nginx/modules"
    cp_exec "mkdir -p /usr/lib64/nginx/modules"
    cp_exec "cp lib/libngx_module.so /usr/lib/nginx/modules/ngx_cp_attachment_module.so"
    cp_exec "cp lib/libngx_module.so /usr/lib64/nginx/modules/ngx_cp_attachment_module.so"

    [ -f /etc/nginx/nginx.conf ] && sed -i -e '/load_module.*ngx_cp_attachment_module.so;/d' /etc/nginx/nginx.conf || echo
    [ -f /etc/nginx/template/nginx.tmpl ] && sed -i -e '/load_module.*ngx_cp_attachment_module.so;/d' /etc/nginx/template/nginx.tmpl || echo
    [ -f /usr/local/share/lua/5.1/kong/templates/nginx.lua ] && sed -i -e '/load_module.*ngx_cp_attachment_module.so;/d' /usr/local/share/lua/5.1/kong/templates/nginx.lua || echo
    [ -f /usr/local/share/lua/5.1/kong/templates/nginx.lua ] && sed -i -e '/cp_worker_processes/d' /usr/local/share/lua/5.1/kong/templates/nginx.lua || echo
    [ -f /usr/local/apisix/apisix/cli/ngx_tpl.lua ] && sed -i -e '/load_module.*ngx_cp_attachment_module.so;/d' /usr/local/apisix/apisix/cli/ngx_tpl.lua || echo

    [ -f /etc/nginx/nginx.conf ] && sed -i 1i'load_module /usr/lib/nginx/modules/ngx_cp_attachment_module.so;' /etc/nginx/nginx.conf || echo
    [ -f /etc/nginx/template/nginx.tmpl ] && sed -i 1i'load_module /usr/lib/nginx/modules/ngx_cp_attachment_module.so;' /etc/nginx/template/nginx.tmpl || echo
    [ -f /usr/local/share/lua/5.1/kong/templates/nginx.lua ] && sed -i 's|return \[\[|return \[\[\nload_module /usr/lib/nginx/modules/ngx_cp_attachment_module.so;|g' /usr/local/share/lua/5.1/kong/templates/nginx.lua || echo
    [ -f /usr/local/share/lua/5.1/kong/templates/nginx.lua ] && sed -i 's|http {|http {\ncp_worker_processes ${{nginx_worker_processes}};|g' /usr/local/share/lua/5.1/kong/templates/nginx.lua || echo
    [ -f /usr/local/apisix/apisix/cli/ngx_tpl.lua ] && sed -i 's|return \[\=\[|return \[\=\[\nload_module /usr/lib/nginx/modules/ngx_cp_attachment_module.so;|' /usr/local/apisix/apisix/cli/ngx_tpl.lua || echo

    command -v nginx > /dev/null && nginx -s reload
    command -v kong > /dev/null && kong restart
    command -v apisix > /dev/null && apisix reload

    cp_print "Installation completed successfully." $FORCE_STDOUT
}

usage()
{
    echo "Check Point: available flags are"
    echo "--install           : install ${NANO_SERVICE_NAME} Nano Service"
    echo "--uninstall         : remove ${NANO_SERVICE_NAME} Nano Service"
    echo "--pre_install_test  : run Pre-installation test for ${NANO_SERVICE_NAME} Nano Service install package"
    echo "--post_install_test : run Post-installation test for ${NANO_SERVICE_NAME} Nano Service install package"
    exit 255
}

run_uninstall()
{
    cp_print "Starting uninstallation of Check Point ${NANO_SERVICE_NAME} Nano service [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    cp_print "Uninstallation completed successfully." $FORCE_STDOUT
}

run_pre_install_test()
{
    cp_print "Starting Pre-installation test of Check Point ${ATTACHMENT_NAME} installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    cp_print "Successfully finished pre-installation test for Check Point ${ATTACHMENT_NAME} installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    exit 0
}

run_post_install_test()
{
    cp_print "Starting Post-installation test of Check Point ${ATTACHMENT_NAME} Nano service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT

    cp_print "Successfully finished post-installation test for Check Point ${ATTACHMENT_NAME} Nano service installation package [$INSTALLATION_TIME]\n" $FORCE_STDOUT
    exit 0
}

run()
{
    if [ '--install' = "$1" ]; then
        run_installation "${@}"
    elif [ '--uninstall' = "$1" ]; then
        run_uninstall
    elif [ '--pre_install_test' = "$1" ]; then
        run_pre_install_test
    elif [ '--post_install_test' = "$1" ]; then
        run_post_install_test
    else
        usage
        exit 1
    fi
}

if [ "$(id -u)" != "0" ]; then
    echo "Administrative privileges required for this Package (use su or sudo)"
    exit 1
fi

shift
run "${@}"

exit 0
