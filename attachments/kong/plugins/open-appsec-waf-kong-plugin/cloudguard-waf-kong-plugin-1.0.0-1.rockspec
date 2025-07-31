package = "cloudguard-waf-kong-plugin"
version = "1.0.0-1"

source = {
  url = "https://github.com/openappsec/attachment",
  tag = "main"
}

description = {
  summary = "CloudGuard WAF Kong plugin (based on open-appsec)",
  detailed = [[
    This is the CloudGuard WAF plugin for Kong API gateway, built using the open-appsec engine.
    It integrates advanced security features into Kong using CloudGuard branding while utilizing the open-appsec core.
  ]],
  homepage = "https://github.com/openappsec/open-appsec",
  license = "Apache 2.0"
}

dependencies = {
  "lua >= 5.1",
  "lua-cjson",
  "luasocket",
  "luafilesystem",
  "uuid",
  "lbase64",
  "luasec",
  "luacrypto",
  "bit32"
}


build = {
  type = "builtin",

  modules = {
    ["kong.plugins.open-appsec-waf-kong-plugin.handler"] = "attachments/kong/plugins/open-appsec-waf-kong-plugin/handler.lua",
    ["kong.plugins.open-appsec-waf-kong-plugin.nano_ffi"] = "attachments/kong/plugins/open-appsec-waf-kong-plugin/nano_ffi.lua",
    ["kong.plugins.open-appsec-waf-kong-plugin.schema"] = "attachments/kong/plugins/open-appsec-waf-kong-plugin/schema.lua",
    ["lua_attachment_wrapper"] = {
      sources = {
        "attachments/kong/plugins/open-appsec-waf-kong-plugin/lua_attachment_wrapper.c",
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
        "attachments/nano_attachment/",
        "external/"
      },
      defines = { "_GNU_SOURCE", "ZLIB_CONST" },
      libraries = { "pthread", "z", "rt", "stdc++" },
      ldflags = { "-static-libstdc++", "-static-libgcc" }
    }
  }
}
