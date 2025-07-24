local typedefs = require "kong.db.schema.typedefs"

return {
  name = "open-appsec-waf-kong-plugin",
  fields = {
    { consumer = typedefs.no_consumer }, -- required for Konnect compatibility
    {
      protocols = {
        type = "set",
        elements = { type = "string", one_of = { "http", "https" } },
        default = { "http", "https" },
      },
    },
    {
      config = {
        type = "record",
        fields = {
          { debug = { type = "boolean", default = false } },
        },
      },
    },
  },
}
