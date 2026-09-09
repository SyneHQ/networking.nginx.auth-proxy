local cjson = require "cjson"

local function get_env(name, default)
    return os.getenv(name) or default
end

local JWT_SECRET = get_env("JWT_SECRET", "")
local JWT_SALT = get_env("JWT_SALT", "authjs.session-token")
local TOKEN_ISSUER = get_env("TOKEN_ISSUER", "")
local TOKEN_AUDIENCE = get_env("TOKEN_AUDIENCE", "")
local ENABLE_DB_CHECK = get_env("ENABLE_DB_CHECK", "false")
local ALLOW_LOCAL_BYPASS = get_env("ALLOW_LOCAL_BYPASS", "false")
local LOCAL_BYPASS_HEADER = get_env("LOCAL_BYPASS_HEADER", "X-Local-Auth-Bypass")
local LOCAL_BYPASS_VALUE = get_env("LOCAL_BYPASS_VALUE", "")

local function parse_cookies(cookie_string)
    local cookies = {}
    if not cookie_string then
        return cookies
    end

    for cookie in string.gmatch(cookie_string, "([^;]+)") do
        local key, value = string.match(cookie:gsub("^%s+", ""), "([^=]+)=(.+)")
        if key and value then
            cookies[key] = value
        end
    end

    return cookies
end

local function clear_untrusted_headers()
    local headers = {
        "X-Api-Key",
        "X-User-Id",
        "X-User-Email",
        "X-Remote-User",
        "X-Remote-Email",
        "X-Auth-User",
        "X-Team-Id",
        "X-Organization-Id",
        "X-Forwarded-User",
        "X-Forwarded-Email",
        "X-Forwarded-Id",
        "X-Forwarded-Access-Token",
        "X-Auth-Request-User",
        "X-Auth-Request-Email",
        "X-Auth-Request-Access-Token",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Real-IP",
        "X-Bypass-Auth",
        LOCAL_BYPASS_HEADER,
    }

    for _, header in ipairs(headers) do
        ngx.req.clear_header(header)
    end
end

local function audience_matches(audience, expected)
    if type(audience) == "string" then
        return audience == expected
    end

    if type(audience) == "table" then
        for _, value in ipairs(audience) do
            if value == expected then
                return true
            end
        end
    end

    return false
end

local function validate_claims(payload)
    if type(payload) ~= "table" or type(payload.sub) ~= "string" or payload.sub == "" then
        return false, "token is missing a subject"
    end

    -- Expiration is mandatory. Auth.js JWE tokens must carry a numeric exp claim.
    if type(payload.exp) ~= "number" or payload.exp <= ngx.time() then
        return false, "token is expired or missing expiration"
    end

    if TOKEN_ISSUER ~= "" and payload.iss ~= TOKEN_ISSUER then
        return false, "token issuer does not match"
    end

    if TOKEN_AUDIENCE ~= "" and not audience_matches(payload.aud, TOKEN_AUDIENCE) then
        return false, "token audience does not match"
    end

    return true
end

local function validate_jwe(token)
    if JWT_SECRET == "" then
        ngx.log(ngx.ERR, "Authentication is not configured: JWT_SECRET is empty")
        return nil, "unavailable"
    end

    local body = cjson.encode({
        token = token,
        secret = JWT_SECRET,
        salt = JWT_SALT,
    })

    local captured, res = pcall(ngx.location.capture, "/verify-jwe", {
        method = ngx.HTTP_POST,
        body = body,
        headers = { ["Content-Type"] = "application/json" },
    })

    if not captured or not res then
        ngx.log(ngx.ERR, "JWE verification subrequest failed")
        return nil, "unavailable"
    end

    if res.status >= 500 or res.status == ngx.HTTP_REQUEST_TIMEOUT then
        ngx.log(ngx.ERR, "JWE verification service unavailable, status=", res.status)
        return nil, "unavailable"
    end

    if res.status ~= ngx.HTTP_OK or not res.body or res.body == "" then
        return nil, "invalid"
    end

    local decoded, response = pcall(cjson.decode, res.body)
    if not decoded or type(response) ~= "table" or response.success ~= true then
        return nil, "invalid"
    end

    local valid, reason = validate_claims(response.payload)
    if not valid then
        ngx.log(ngx.WARN, "JWE claim validation failed: ", reason)
        return nil, "invalid"
    end

    return response.payload
end

local function authenticate()
    local request_headers = ngx.req.get_headers()
    local local_bypass_value = request_headers[LOCAL_BYPASS_HEADER]
    clear_untrusted_headers()

    -- Slack verifies its own signature downstream. This is intentionally limited to
    -- the exact callback endpoint, not a path prefix, and receives no caller identity.
    if ngx.var.uri == "/slack/events" then
        return
    end

    -- Local bypass is opt-in, requires a non-empty secret value, and only accepts
    -- direct loopback traffic. It cannot be enabled for remotely sourced requests.
    if ALLOW_LOCAL_BYPASS == "true"
        and LOCAL_BYPASS_VALUE ~= ""
        and local_bypass_value == LOCAL_BYPASS_VALUE
        and (ngx.var.remote_addr == "127.0.0.1" or ngx.var.remote_addr == "::1") then
        ngx.log(ngx.WARN, "Local authentication bypass accepted")
        return
    end

    local token = parse_cookies(ngx.var.http_cookie)[JWT_SALT]
    if not token then
        ngx.log(ngx.WARN, "Authentication rejected: session token is missing")
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local payload, state = validate_jwe(token)
    if not payload then
        if state == "unavailable" then
            return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
        end
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.req.set_header("X-User-Id", payload.sub)

    if ENABLE_DB_CHECK == "true" then
        ngx.log(ngx.ERR, "ENABLE_DB_CHECK is not supported without a configured verifier")
        return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    end
end

local ok, err = pcall(authenticate)
if not ok then
    ngx.log(ngx.ERR, "Authentication boundary failed closed: ", err)
    return ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
end
