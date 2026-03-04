local typedefs = require "kong.db.schema.typedefs"

return {
  name = "cloudguard-waf-kong-plugin",
  fields = {
    { consumer = typedefs.no_consumer },                -- required for Konnect compatibility
    { protocols = typedefs.protocols_http },            -- required so Konnect knows when to allow this plugin
    { config = {
        type = "record",
        fields = {
          { debug  = { type = "boolean", default = false } },
        },
      },
    },
  },
}
