FROM kong

USER root

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libpcre3-dev \
        libxml2-dev \
        zlib1g-dev \
        libssl-dev \
        libgeoip-dev \
        linux-libc-dev \
        python3 \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

ENV LUAROCKS_VER=3.11.0
RUN curl -fSL https://luarocks.org/releases/luarocks-${LUAROCKS_VER}.tar.gz -o luarocks-${LUAROCKS_VER}.tar.gz && \
    tar xzf luarocks-${LUAROCKS_VER}.tar.gz && \
    cd luarocks-${LUAROCKS_VER} && \
    ./configure \
        --with-lua=/usr/local/openresty/luajit \
        --with-lua-include=/usr/local/openresty/luajit/include/luajit-2.1 && \
    make && make install && \
    cd .. && rm -rf luarocks-${LUAROCKS_VER}*

# Install the plugin via LuaRocks
RUN luarocks install https://raw.githubusercontent.com/openappsec/attachment/main/attachments/kong/open-appsec-waf-kong-plugin-1.0.0-1.rockspec --deps-mode=all

USER kong

# Enable the plugin
ENV KONG_PLUGINS=bundled,open-appsec-waf-kong-plugin
