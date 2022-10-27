<div align=center>
<img src="https://i2-s3-ui-static-content-prod-10.s3.eu-west-1.amazonaws.com/elpis/tree-no-bg-256.png" width="100" height="100"> 
<h1>openappsec/attachement</h1>
</div>

## About

open-appsec is a machine learning security engine that preemptively and automatically prevent threats against Web Application & APIs.

<strong>open-appsec Attachments</strong> connect between processes that provide HTTP data and the <strong>open-appsec Agent</strong> security logic.

An attachment gets HTTP data (URL, Header, Body, Response) from a hosting process and delivers it to an open-appsec process known as HTTP Transaction handler.

To deal with potential issues where the HTTP Transaction handler process is not responding, the Attachment implements a retry mechanism and configurable fail-open/fail-close mechanism.

This repository will host Attachment for different platforms. The first one is the open-appsec attachment for NGINX, implemented as a standard NGINX dynamically loadable module (plugin).


## open-appsec NGINX attachment compilation instructions

The attchment can be compiled to support an existing alpine based nginx server or an nginx/ingress-nginx alpine based docker.

Your compilation environment must be alpine based and contain git, docker, cmake and g++.

Before compiling, ensure the latest development versions of the following libraries:

* PCRE
* libxml2
* zlib
* OpenSSL
* Geoip

```bash
 $ apk update
 $ apk add pcre-dev libxml2-dev zlib-dev openssl-dev geoip-dev
```

### Compiling the attachment code for an existing nginx server

On your existing nginx server:
1. Run command to extract nginx compilation flags to a file

```bash
 $ nginx -V &> /tmp/nginx.ver
```

On your compilation environment:
1. Clone this repository
2. Copy the file created on your nginx server (the previous section) to your compilation environment to the path /tmp/nginx.ver
3. Run Configuration script
4. Run CMake command
5. Run make command

```bash
 $ git clone https://github.com/openappsec/attachment.git
 $ ./attachments/nginx/ngx_module/nginx_version_configuration.sh --conf /tmp/nginx.ver build_out
 $ cmake -DCMAKE_INSTALL_PREFIX=build_out .
 $ make install
```

#### NGINX plugin associated libraries
The NGINX plugin uses these libraries: shmem_ipc, compression_utils, and nginx_attachment_util.

They can be found under the `lib` directory in the `<output path>` given to the CMake.

#### Deploying the attachment on an existing alpine nginx server

1. Copy the associated libraries to /usr/lib on your existing nginx server
2. Copy the nginx attachment file lib/libngx_module.so to the following path on your existing nginx server: /usr/lib/nginx/modules/
3. Load the attachment on your nginx by adding the following command to the main nginx.conf file: 
   `load_module /usr/lib/nginx/modules/libngx_module.so;`
4. Restart your nginx server.

### Compiling the attachment code and create a docker image for an existing nginx/ingres-nginx alpine docker

This step requires Docker to be installed on your comilation environment

1. Clone this repository
3. Run Configuration script with the required docker image name and tag
4. Run CMake command
5. Run make command

```bash
 $ git clone https://github.com/openappsec/attachment.git
 $ ./attachments/nginx/ngx_module/nginx_version_configuration.sh --docker <input docker image> build_out
 $ cmake -DCMAKE_INSTALL_PREFIX=build_out -DOUTPUT_DOCKER_IMAGE=<output docker image> .
 $ make install
 $ make docker
```

Later on, you can push the image to your own registry and use it as needed.

## License    

open-appsec/attachment is open source and available under the Apache 2.0 license.
