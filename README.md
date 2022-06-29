# attachment

## NGINX attachment compilation instructions

### Compiling this repository
1. Clone this repository
2. Run CMake command (we recommand something like `cmake -DCMAKE_INSTALL_PREFIX=<output path> <repository path>`).
3. From the repositoy directory run `make install`

For example:
```bash
 $ git clone https://github.com/openappsec/attachment.git
 $ cd attachment/
 $ cmake  -DCMAKE_INSTALL_PREFIX=build_out .
 $ make install
```

### For the NGINX plugin
Grab the nginx source code from [nginx.org](http://nginx.org/), for example,
the version 1.23.0 (see [nginx compatibility](http://nginx.org/en/docs/njs/compatibility.html)), and then build the source with this module:

```bash
 $ module_path=/absolute/path/to/attachment

 $ wget 'http://nginx.org/download/nginx-1.23.0.tar.gz'
 $ tar -xzvf nginx-1.23.0.tar.gz
 $ cd nginx-1.23.0/

 $ ./configure  --add-dynamic-module=$module_path --with-cc-opt="-I $module_path/core/include/attachments"

 $ make modules
```

#### NGINX plugin associated libraries
The NGINX plugin uses these libraries: shmem_ipc, compression_utils, and nginx_attachment_util.

They can be found under the `lib` directory in the `<output path>` given to the CMake.
