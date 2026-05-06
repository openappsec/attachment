FROM debian:bookworm-slim

RUN apt-get update \
	&& apt-get install -y --no-install-recommends bash ca-certificates libbrotli-dev \
	&& rm -rf /var/lib/apt/lists/*

COPY envoy /envoy/attachment/versions
COPY lib/libnano_attachment.so /envoy/attachment/libnano_attachment.so
COPY lib/libshmem_ipc_2.so /envoy/attachment/libshmem_ipc_2.so
COPY lib/libnano_attachment_util.so /envoy/attachment/libnano_attachment_util.so
COPY lib/libosrc_compression_utils.so /envoy/attachment/libosrc_compression_utils.so
RUN cp -av /usr/lib/x86_64-linux-gnu/libbrotli*.so* /envoy/attachment/

COPY prepare_attachment.sh /prepare_attachment.sh
RUN chmod +x /prepare_attachment.sh

