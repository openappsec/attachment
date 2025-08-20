FROM alpine

# Bash for scripting & verbose utils
RUN apk add --no-cache bash

# Where we stage attachment files
ENV ENVOY_ATTACHMENT_ROOT=/envoy/attachment

# Versioned Envoy libs directory
COPY envoy ${ENVOY_ATTACHMENT_ROOT}/versions
# Base libs
COPY lib/libnano_attachment.so           ${ENVOY_ATTACHMENT_ROOT}/libnano_attachment.so
COPY lib/libshmem_ipc_2.so               ${ENVOY_ATTACHMENT_ROOT}/libshmem_ipc_2.so
COPY lib/libnano_attachment_util.so      ${ENVOY_ATTACHMENT_ROOT}/libnano_attachment_util.so
COPY lib/libosrc_compression_utils.so    ${ENVOY_ATTACHMENT_ROOT}/libosrc_compression_utils.so

# Create the script inline; no external file needed
RUN cat >/usr/local/bin/prepare_attachment.sh <<'EOF' && chmod +x /usr/local/bin/prepare_attachment.sh
#!/usr/bin/env bash
set -euo pipefail

log() { echo "[prepare-attachment] $(date -Iseconds) $*"; }

# Require ENVOY_VERSION at runtime (fail fast with a clear message)
: "${ENVOY_VERSION:?ENVOY_VERSION env var is required (e.g., 1.27)}"

log "Starting preparation for ENVOY_VERSION=${ENVOY_VERSION}"

# Create destination and copy shared libs
mkdir -p "${ENVOY_ATTACHMENT_ROOT}/shared"

log "Copying base libs from ${ENVOY_ATTACHMENT_ROOT} to ${ENVOY_ATTACHMENT_ROOT}/shared"
cp -rv "${ENVOY_ATTACHMENT_ROOT}/lib"* "${ENVOY_ATTACHMENT_ROOT}/shared"

log "Copying versioned libs from ${ENVOY_ATTACHMENT_ROOT}/versions/${ENVOY_VERSION}"
cp -v "${ENVOY_ATTACHMENT_ROOT}/versions/${ENVOY_VERSION}/lib"* "${ENVOY_ATTACHMENT_ROOT}/shared"

log "Preparation complete. Final contents of shared:"
ls -l "${ENVOY_ATTACHMENT_ROOT}/shared" || true

log "All done."
EOF

# Run the script when the container starts (great for initContainers)
ENTRYPOINT ["/usr/local/bin/prepare_attachment.sh"]
