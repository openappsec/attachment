<div align=center>
<img src="https://i2-s3-ui-static-content-prod-10.s3.eu-west-1.amazonaws.com/elpis/tree-no-bg-256.png" width="100" height="100"> 
<h1>openappsec/attachment</h1>
</div>

## About

open-appsec is a machine learning security engine that preemptively and automatically prevent threats against Web Application & APIs.

<strong>open-appsec Attachments</strong> connect between processes that provide HTTP data and the <strong>open-appsec Agent</strong> security logic.

An attachment gets HTTP data (URL, Header, Body, Response) from a hosting process and delivers it to an open-appsec process known as HTTP Transaction handler.

To deal with potential issues where the HTTP Transaction handler process is not responding, the Attachment implements a retry mechanism and configurable fail-open/fail-close mechanism.

This repository will host Attachment for different platforms. The first one is the open-appsec attachment for NGINX, implemented as a standard NGINX dynamically loadable module (plugin).


## open-appsec NGINX attachment compilation instructions

### Compiling the attachment code
1. Clone this repository
2. Run CMake command
3. Run make install command

```bash
 $ git clone https://github.com/openappsec/attachment.git
 $ cd attachment/
 $ cmake -DCMAKE_INSTALL_PREFIX=build_out .
 $ make install
```

### NGINX plugin

NGINX Plugins are built per specific version.
1. Get nginx source code from [nginx.org](http://nginx.org/), e.g. version 1.23.0 (see [nginx compatibility](http://nginx.org/en/docs/njs/compatibility.html))
2. Run make modules

```bash
 $ module_path=/<absolute-path>/attachment

 $ wget 'https://nginx.org/download/nginx-1.23.0.tar.gz'
 $ sha256sum nginx-1.23.0.tar.gz
 820acaa35b9272be9e9e72f6defa4a5f2921824709f8aa4772c78ab31ed94cd1  nginx-1.23.0.tar.gz

 $ tar -xzvf nginx-1.23.0.tar.gz
 $ cd nginx-1.23.0/

 $ ./configure  --add-dynamic-module=$module_path --with-cc-opt="-I $module_path/core/include/attachments"

 $ make modules
```

#### NGINX plugin associated libraries
The NGINX plugin uses these libraries: shmem_ipc, compression_utils, and nginx_attachment_util.

They can be found under the `lib` directory in the `<output path>` given to the CMake.

## License    

open-appsec/attachment is open source and available under the Apache 2.0 license.
