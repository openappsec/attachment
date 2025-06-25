FROM kong:$VERSION

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl zlib1g-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN curl -sL https://github.com/USCiLab/cereal/archive/refs/tags/v1.3.2.tar.gz | tar xz && \
    mkdir -p /usr/local/include/cereal && \
    cp -r cereal-1.3.2/include/cereal /usr/local/include/ && \
    rm -rf cereal-1.3.2

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
