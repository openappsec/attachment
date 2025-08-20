#!/bin/bash

set -x

echo "Preparing shared Envoy attachment files..."
mkdir -p /envoy/attachment/shared && \
cp -r /envoy/attachment/lib* /envoy/attachment/shared && \
cp /envoy/attachment/versions/$ENVOY_VERSION/lib* /envoy/attachment/shared
