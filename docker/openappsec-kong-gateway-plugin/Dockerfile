FROM kong/kong-gateway

USER root

RUN touch /etc/dual_docker
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git curl zlib1g-dev libbrotli-dev ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

RUN curl -sL https://github.com/USCiLab/cereal/archive/refs/tags/v1.3.2.tar.gz | tar xz && \
    mkdir -p /usr/local/include/cereal && \
    cp -r cereal-1.3.2/include/cereal /usr/local/include/ && \
    rm -rf cereal-1.3.2

# Create attachment-metadata file
RUN echo "EFFECTIVE_SHM_SEGMENT_SIZE=4096" > /etc/attachment-metadata

# Install the plugin via LuaRocks
RUN luarocks install https://raw.githubusercontent.com/openappsec/attachment/main/attachments/kong/plugins/open-appsec-waf-kong-plugin/open-appsec-waf-kong-plugin-1.0.0-1.rockspec

USER kong

# Enable the plugin
ENV KONG_PLUGINS=bundled,open-appsec-waf-kong-plugin
