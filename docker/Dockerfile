FROM <DOCKER BASE IMAGE>

USER root

RUN apk update
RUN apk add --no-cache -u busybox
RUN apk add --no-cache -u zlib
RUN apk add --no-cache libstdc++

USER <DOCKER USER>

COPY lib/libosrc_compression_utils.so /usr/lib/libosrc_compression_utils.so
COPY lib/libosrc_nginx_attachment_util.so /usr/lib/libosrc_nginx_attachment_util.so
COPY lib/libosrc_shmem_ipc.so /usr/lib/libosrc_shmem_ipc.so
RUN mkdir -p /usr/lib/nginx/modules/
COPY lib/libngx_module.so /usr/lib/nginx/modules/ngx_cp_attachment_module.so

RUN echo "load_module /usr/lib/nginx/modules/ngx_cp_attachment_module.so;"|cat - /etc/nginx/nginx.conf> /tmp/out && mv /tmp/out /etc/nginx/nginx.conf
RUN [ -f /etc/nginx/template/nginx.tmpl ] && echo "load_module /usr/lib/nginx/modules/ngx_cp_attachment_module.so;"|cat - /etc/nginx/template/nginx.tmpl> /tmp/out.tmpl && mv /tmp/out.tmpl /etc/nginx/template/nginx.tmpl || echo ""
RUN [ -f /usr/local/share/lua/5.1/kong/templates/nginx.lua ] && /bin/sh -c sed -i "s|return \[\[|return \[\[\nload_module /usr/lib64/nginx/modules/ngx_cp_attachment_module.so;|g" /usr/local/share/lua/5.1/kong/templates/nginx.lua
RUN [ -f /usr/local/share/lua/5.1/kong/templates/nginx.lua ] && /bin/sh -c sed -i "s|http {|http {\ncp_worker_processes \$\{\{nginx_worker_processes\}\};|g" /usr/local/share/lua/5.1/kong/templates/nginx.lua

