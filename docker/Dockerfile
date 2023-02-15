FROM <DOCKER BASE IMAGE>

USER root

RUN apk update
RUN apk add --no-cache -u busybox
RUN apk add --no-cache -u zlib
RUN apk add --no-cache libstdc++
RUN mkdir -p /usr/lib/nginx/modules/
RUN mkdir -p /usr/lib64/nginx/modules/

USER <DOCKER USER>

COPY lib/libosrc_compression_utils.so /usr/lib/libosrc_compression_utils.so
COPY lib/libosrc_compression_utils.so /usr/lib64/libosrc_compression_utils.so
COPY lib/libosrc_nginx_attachment_util.so /usr/lib/libosrc_nginx_attachment_util.so
COPY lib/libosrc_nginx_attachment_util.so /usr/lib64/libosrc_nginx_attachment_util.so
COPY lib/libosrc_shmem_ipc.so /usr/lib/libosrc_shmem_ipc.so
COPY lib/libosrc_shmem_ipc.so /usr/lib64/libosrc_shmem_ipc.so
COPY lib/libngx_module.so /usr/lib/nginx/modules/ngx_cp_attachment_module.so
COPY lib/libngx_module.so /usr/lib64/nginx/modules/ngx_cp_attachment_module.so

USER root

RUN [ -f /etc/nginx/nginx.conf ] && sed -i 1i"load_module /usr/lib/nginx/modules/ngx_cp_attachment_module.so;" /etc/nginx/nginx.conf || echo ""
RUN [ -f /etc/nginx/template/nginx.tmpl ] && sed -i 1i"load_module /usr/lib/nginx/modules/ngx_cp_attachment_module.so;" /etc/nginx/template/nginx.tmpl || echo ""
RUN [ -f /usr/local/share/lua/5.1/kong/templates/nginx.lua ] && sed -i "s|return \[\[|return \[\[\nload_module /usr/lib64/nginx/modules/ngx_cp_attachment_module.so;|g" /usr/local/share/lua/5.1/kong/templates/nginx.lua || echo ""
RUN [ -f /usr/local/share/lua/5.1/kong/templates/nginx.lua ] && sed -i "s|http {|http {\ncp_worker_processes \$\{\{nginx_worker_processes\}\};|g" /usr/local/share/lua/5.1/kong/templates/nginx.lua || echo ""

USER <DOCKER USER>
