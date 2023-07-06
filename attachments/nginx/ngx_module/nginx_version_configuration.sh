#!/bin/bash

NGINX_VERSION_CONF_INPUT_PATH=/tmp/nginx.sourcefile.ver
if [ "${1}" == "--docker" ]; then
    docker run -it ${2} nginx -V > ${NGINX_VERSION_CONF_INPUT_PATH}
elif [ "${1}" == "--conf" ]; then
    cp ${2} ${NGINX_VERSION_CONF_INPUT_PATH}
else
    echo "Usage: ${0} [--conf <input nginx compilation flags file> | --docker <input docker name>] <compilation artifacts directory>"
    exit 1
fi
NGINX_VERSION_CONF_OUTPUT_PATH=/tmp/nginx.sourcefile.conf
dos2unix ${NGINX_VERSION_CONF_INPUT_PATH}
$(dirname $0)/nginx_version_extractor.sh -i ${NGINX_VERSION_CONF_INPUT_PATH} -o ${NGINX_VERSION_CONF_OUTPUT_PATH}
BUILD_OUTPUT_DIR=${3}

if [[ ${BUILD_OUTPUT_DIR} != /* ]]; then
    BUILD_OUTPUT_DIR=$(pwd)/${BUILD_OUTPUT_DIR}
fi

source ${NGINX_VERSION_CONF_OUTPUT_PATH}

CURRENT_PWD=$(pwd)

mkdir -p ${BUILD_OUTPUT_DIR}
cd ${BUILD_OUTPUT_DIR}

wget --no-check-certificate https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
if [[ $? != 0 ]]; then
    echo "Failed to download NGINX source code. Path used: 'https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz'"
    exit 1
fi

tar -xzvf nginx-${NGINX_VERSION}.tar.gz
if [[ $? != 0 ]]; then
    echo "Failed to untar NGINX source code. Tar file: 'nginx-${NGINX_VERSION}.tar.gz'"
    exit 1
fi

rm -f nginx-${NGINX_VERSION}.tar.gz

mv nginx-${NGINX_VERSION} nginx-src
cd nginx-src

if test ! -f configured.ok; then
    echo "Configuring nginx compiler: ./configure ${CONFIGURE_OPT} --with-cc-opt=\"${EXTRA_CC_OPT} ${LOCAL_CC_OPT}\" && touch configured.ok"
    ./configure ${CONFIGURE_OPT} --with-cc-opt="${EXTRA_CC_OPT} ${LOCAL_CC_OPT}" && touch configured.ok
else 
    echo "Nginx compiler already Configured...\n"
fi

if test ! -f configured.ok; then
    echo "Failed to configure NGINX source code"
    exit 1
fi

make && echo "${EXTRA_CC_OPT}" > cc_flags.mk
if [[ $? != 0 ]]; then
    echo "Failed to build NGINX source code"
    exit 1
fi

OUTPUT_FILE_NAME=include_paths.mk

ALL_INCS=$(cat objs/Makefile|grep -v \$\(ALL_INCS\) | awk '/ALL_INCS/' RS="\n\n" ORS="\n\n" | tr '\\' ' ')
ALL_INCS=${ALL_INCS/ALL_INCS =/}
ALL_INCS=$(sed "s/-I//g" <<< "${ALL_INCS}")

echo > include_paths.mk
for include in ${ALL_INCS}; do
    echo $include >> include_paths.mk
done

cd ${CURRENT_PWD}

if [ "${1}" == "--docker" ]; then
    cp -f $(dirname $0)/../../../docker/Dockerfile ${BUILD_OUTPUT_DIR}/Dockerfile
    sed -i "s|<DOCKER BASE IMAGE>|${2}|g" ${BUILD_OUTPUT_DIR}/Dockerfile
    docker run -it ${2} whoami > /tmp/usertouse
    USER_NAME="$(cat /tmp/usertouse)"
    rm /tmp/usertouse
    sed -i "s|<DOCKER USER>|${USER_NAME}|g" ${BUILD_OUTPUT_DIR}/Dockerfile
fi
