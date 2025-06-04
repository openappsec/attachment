FROM alpine

RUN apk add --no-cache bash

COPY envoy /envoy/attachment/versions
COPY lib/libnano_attachment.so /envoy/attachment/libnano_attachment.so
COPY lib/libshmem_ipc_2.so /envoy/attachment/libshmem_ipc_2.so
COPY lib/libnano_attachment_util.so /envoy/attachment/libnano_attachment_util.so
COPY lib/libosrc_compression_utils.so /envoy/attachment/libosrc_compression_utils.so
