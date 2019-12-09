local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require "kong.plugins.oidc.utils"
local filter = require "kong.plugins.oidc.filter"
local session = require "kong.plugins.oidc.session"

local constants = require "kong.constants"

local kong = kong

OidcHandler.PRIORITY = 1004

local function internal_server_error(err)
  kong.log.err(err)
  return kong.response.exit(500, { message = "An unexpected error occurred" })
end

local function set_consumer(consumer, anonymous)
  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  if consumer and consumer.id then
    set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  else
    clear_header(constants.HEADERS.CONSUMER_ID)
  end

  if consumer and consumer.custom_id then
    set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else
    clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
  end

  if consumer and consumer.username then
    set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else
    clear_header(constants.HEADERS.CONSUMER_USERNAME)
  end

  kong.client.authenticate(consumer, nil)

  if anonymous then
    set_header(constants.HEADERS.ANONYMOUS, true)
  else
    clear_header(constants.HEADERS.ANONYMOUS)
  end
  clear_header("x-authenticated-scope")
  clear_header("x-authenticated-userid")
end

function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  if config.anonymous and kong.client.get_credential()then
    -- we're already authenticated, not as anonymous, and we're configured for
    -- using anonymous, hence we're in a logical OR between auth methods and
    -- we're already done.
    return
  end

  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local response
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    response = introspect(oidcConfig)
    if response then
      local user = response
      user.id = user.sub
      user.username = user.preferred_username
      set_consumer(user, false)
      utils.injectUser(user)
    end
  else
    response = make_oidc(oidcConfig)
    if response then
      if (response.user) then
        local tmp_user = response.user
        tmp_user.id = response.user.sub
        tmp_user.username = response.user.preferred_username
        set_consumer(tmp_user, false)
        utils.injectUser(response.user)
      end
      if (response.access_token) then
        utils.injectAccessToken(response.access_token)
      end
      if (response.id_token) then
        utils.injectIDToken(response.id_token)
      end
    end
  end
end

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  for realm in oidcConfig.realms do
    oidcConfig.discovery = oidcConfig.base_url .. realm .. oidcConfig.discovery_suffix
    local res, err = require("resty.openidc").authenticate(oidcConfig)
    if err then
      if oidcConfig.anonymous then
        -- get anonymous user
        local consumer_cache_key = kong.db.consumers:cache_key(oidcConfig.anonymous)
        local consumer, err      = kong.cache:get(consumer_cache_key, nil,
                                                  kong.client.load_consumer,
                                                  oidcConfig.anonymous, true)
        if err then
          kong.log.err("failed to load anonymous consumer:", err)
          return internal_server_error(err)
        end

        set_consumer(consumer, true)
      end
    else
      return res
    end
  end
  if oidcConfig.recovery_page_path then
    ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
    ngx.redirect(oidcConfig.recovery_page_path)
  end
  if not oidcConfig.anonymous then
    return utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
  end
end

function introspect(oidcConfig)
  for realm in oidcConfig.realms do
    oidcConfig.introspection_endpoint = oidcConfig.base_url .. realm .. oidcConfig.introspection_suffix
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      if oidcConfig.bearer_only == "yes" then
        if oidcConfig.anonymous then
          -- get anonymous user
          local consumer_cache_key = kong.db.consumers:cache_key(oidcConfig.anonymous)
          local consumer, err      = kong.cache:get(consumer_cache_key, nil,
                                                    kong.client.load_consumer,
                                                    oidcConfig.anonymous, true)
          if err then
            kong.log.err("failed to load anonymous consumer:", err)
            return internal_server_error(err)
          end

          set_consumer(consumer, true)

        else
          ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        end
      end
    else
      ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
      return res
    end
  end
  if not oidcConfig.anonymous then
    return utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
  end
end

return OidcHandler
