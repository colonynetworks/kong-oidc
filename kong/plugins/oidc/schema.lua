local typedefs = require "kong.db.schema.typedefs"

local function validate_flows(config)
  return true
end

local DEFAULT_REALM_CONFIGS = {
  {
    realm = "kong",
    client_id = "konglocal",
    client_secret = "kongapigateway"
  },
}

return {
  name = "oidc",
  fields = {
    { consumer = typedefs.no_consumer },
    { config = {
        type = "record",
        fields = {
          {anonymous = { type = "string", uuid = true, legacy = true }},
          {base_url = { type = "string", required = true, default = "https://cas.example.org:8453/cas/" }},
          {discovery_suffix = { type = "string", required = true, default = "/.well-known/openid-configuration" }},
          {introspection_suffix = { type = "string", required = false, default = "/protocol/openid-connect/token/introspect" }},
          {timeout = { type = "number", required = false }},
          {introspection_endpoint_auth_method = { type = "string", required = false }},
          {bearer_only = { type = "string", required = true, default = "no" }},
          {realm_configs = {
              type = "array",
              default = DEFAULT_REALM_CONFIGS,
              elements = {
                type = "record",
                custom_validator = validate_flows,
                fields = {
                  {realm = { type = "string", default= "kong" }},
                  {client_id = { type = "string", default = "konglocal" }},
                  {client_secret = { type = "string", default = "kongapigateway" }},
                }
              }
            }
          },
          {redirect_uri_path = { type = "string" }},
          {scope = { type = "string", required = true, default = "openid" }},
          {response_type = { type = "string", required = true, default = "code" }},
          {ssl_verify = { type = "string", required = true, default = "no" }},
          {token_endpoint_auth_method = { type = "string", required = true, default = "client_secret_post" }},
          {session_secret = { type = "string", required = false }},
          {recovery_page_path = { type = "string" }},
          {logout_path = { type = "string", required = false, default = '/logout' }},
          {redirect_after_logout_uri = { type = "string", required = false, default = '/' }},
          {filters = { type = "string" }}
        },
        custom_validator = validate_flows,
      },
    },
  },
}
