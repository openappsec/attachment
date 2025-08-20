FROM alpine

RUN apk add --no-cache bash

# Copy your versioned envoy directory
COPY envoy /envoy/attachment/versions

# Copy required shared libraries
COPY lib/libnano_attachment.so /envoy/attachment/libnano_attachment.so
COPY lib/libshmem_ipc_2.so /envoy/attachment/libshmem_ipc_2.so
COPY lib/libnano_attachment_util.so /envoy/attachment/libnano_attachment_util.so
COPY lib/libosrc_compression_utils.so /envoy/attachment/libosrc_compression_utils.so

# Copy prepare script into container
COPY prepare_attachment.sh /prepare_attachment.sh
RUN chmod +x /prepare_attachment.sh
