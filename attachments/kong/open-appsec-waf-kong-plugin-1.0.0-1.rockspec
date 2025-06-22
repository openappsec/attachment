package = "open-appsec-waf-kong-plugin"
version = "1.0.0-1"

source = {
  url = "git://github.com/openappsec/attachment.git",
  tag = "add-kong-plugin"  -- Update this to your correct tag/branch if needed
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
    ["kong.plugins.open-appsec-waf-kong-plugin.handler"] = "attachments/kong/handler.lua",
    ["kong.plugins.open-appsec-waf-kong-plugin.nano_ffi"] = "attachments/kong/nano_ffi.lua",
    ["kong.plugins.open-appsec-waf-kong-plugin.schema"] = "attachments/kong/schema.lua",
    ["lua_attachment_wrapper"] = {
      sources = {
        "attachments/kong/lua_attachment_wrapper.c",
        "attachments/nano_attachment/nano_attachment.c",
        "attachments/nano_attachment/nano_attachment_io.c",
        "attachments/nano_attachment/nano_attachment_metric.c",
        "attachments/nano_attachment/nano_attachment_sender.c",
        "attachments/nano_attachment/nano_attachment_sender_thread.c",
        "attachments/nano_attachment/nano_attachment_thread.c",
        "attachments/nano_attachment/nano_compression.c",
        "attachments/nano_attachment/nano_configuration.c",
        "attachments/nano_attachment/nano_initializer.c",
        "attachments/nano_attachment/nano_utils.c",
        "attachments/nano_attachment/nano_attachment_util/nano_attachment_util.cc",
        "core/attachments/http_configuration/http_configuration.cc",
        "core/compression/compression_utils.cc",
        "core/shmem_ipc_2/shared_ring_queue.c",
        "core/shmem_ipc_2/shmem_ipc.c"
      },
      incdirs = {
        "core/include/attachments/",
        "attachments/nano_attachment/"
      },
      defines = { "_GNU_SOURCE", "ZLIB_CONST" },
      libraries = { "pthread", "z", "rt", "stdc++" },
      ldflags = { "-static-libstdc++", "-static-libgcc" }
    }
  }
}
