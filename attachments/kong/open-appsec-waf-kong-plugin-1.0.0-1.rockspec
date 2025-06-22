package = "open-appsec-waf-kong-plugin"
version = "1.0.0-1"

source = {
  url = "git://github.com/openappsec/attachment.git",
  tag = "add-kong-plugin"  -- Change to main/tag if needed
}

description = {
  summary = "Kong plugin for scanning headers",
  detailed = [[
    A Kong plugin that scans HTTP request headers using Nano Attachment.
  ]],
  homepage = "https://github.com/openappsec/attachment",
  license = "Apache"
}

dependencies = {
  "lua >= 2.1"
}

build = {
  type = "builtin",

  modules = {
    ["kong.plugins.open-appsec-waf-kong-plugin.handler"] = "attachment/attachments/kong/handler.lua",
    ["kong.plugins.open-appsec-waf-kong-plugin.nano_ffi"] = "attachment/attachments/kong/nano_ffi.lua",
    ["kong.plugins.open-appsec-waf-kong-plugin.schema"] = "attachment/attachments/kong/schema.lua",
    ["lua_attachment_wrapper"] = {
      sources = {
        "attachment/attachments/kong/lua_attachment_wrapper.c",
        "attachment/attachments/nano_attachment/nano_attachment.c",
        "attachment/attachments/nano_attachment/nano_attachment_io.c",
        "attachment/attachments/nano_attachment/nano_attachment_metric.c",
        "attachment/attachments/nano_attachment/nano_attachment_sender.c",
        "attachment/attachments/nano_attachment/nano_attachment_sender_thread.c",
        "attachment/attachments/nano_attachment/nano_attachment_thread.c",
        "attachment/attachments/nano_attachment/nano_compression.c",
        "attachment/attachments/nano_attachment/nano_configuration.c",
        "attachment/attachments/nano_attachment/nano_initializer.c",
        "attachment/attachments/nano_attachment/nano_utils.c",
        "attachment/attachments/nano_attachment/nano_attachment_util/nano_attachment_util.cc",
        "attachment/core/attachments/http_configuration/http_configuration.cc",
        "attachment/core/compression/compression_utils.cc",
        "attachment/core/shmem_ipc_2/shared_ring_queue.c",
        "attachment/core/shmem_ipc_2/shmem_ipc.c"
      },
      incdirs = {
        "attachment/core/include/attachments/",
        "attachment/attachments/nano_attachment/"
      },
      defines = { "_GNU_SOURCE", "ZLIB_CONST" },
      libraries = { "pthread", "z", "rt", "stdc++" },
      ldflags = { "-static-libstdc++", "-static-libgcc" }
    }
  }
}
