#!/bin/bash

# Set environment variables
SHMEM_LIBRARY_DIR="/u/wiaamm/Views/kong-github-dockerfile/core/shmem_ipc_2"
NANO_ATTACHMENT_LIBRARY_DIR="/u/wiaamm/Views/kong-github-dockerfile/attachments/nano_attachment"
NANO_ATTACHMENT_UTIL_LIBRARY_DIR="/u/wiaamm/Views/kong-github-dockerfile/attachments/nano_attachment/nano_attachment_util"
LIBRARIES="-lnano_attachment -lnano_attachment_util -lshmem_ipc_2"
ENVOY_ATTACHMENT_DIR="/u/wiaamm/Views/kong-github-dockerfile/attachments/envoy/1.32"

cd $ENVOY_ATTACHMENT_DIR

# Run the go build command
CGO_CFLAGS="-I/u/wiaamm/Views/kong-github-dockerfile/core/include/attachments -I/u/wiaamm/Views/kong-github-dockerfile/attachments/nano_attachment" go build -o ${ENVOY_ATTACHMENT_DIR}/libenvoy_attachment.so -buildmode=c-shared -ldflags="-extldflags '-L${SHMEM_LIBRARY_DIR} -L${NANO_ATTACHMENT_LIBRARY_DIR} -L${NANO_ATTACHMENT_UTIL_LIBRARY_DIR} ${LIBRARIES}'"
