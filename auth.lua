local cjson = require "cjson"

local function get_env(name, default)
    return os.getenv(name) or default
end

local JWT_SALT = get_env("JWT_SALT", "authjs.session-token")
local TOKEN_ISSUER = get_env("TOKEN_ISSUER", "")
local TOKEN_AUDIENCE = get_env("TOKEN_AUDIENCE", "")
local ENABLE_DB_CHECK = get_env("ENABLE_DB_CHECK", "false")
local ALLOW_LOCAL_BYPASS = get_env("ALLOW_LOCAL_BYPASS", "false")
local LOCAL_BYPASS_HEADER = get_env("LOCAL_BYPASS_HEADER", "X-Local-Auth-Bypass")
local LOCAL_BYPASS_VALUE = get_env("LOCAL_BYPASS_VALUE", "")

-- Auth.js splits large cookies into name.0, name.1, and subsequent chunks.
-- Reject duplicate names, gaps, mixed formats, and excessive input.
local function session_cookie(cookie_string, name)
    if not cookie_string or #cookie_string > 65536 then return nil end
    local plain, chunks, count, seen = nil, {}, 0, {}
    for cookie in string.gmatch(cookie_string, "([^;]+)") do
        local key, value = string.match(cookie:gsub("^%s+", ""), "([^=]+)=(.*)")
        if key == name or (key and key:sub(1, #name + 1) == name .. ".") then
            if seen[key] or value == "" then return nil end
            seen[key] = true
            if key == name then
                plain = value
            else
                local suffix = key:sub(#name + 2)
                local index = tonumber(suffix)
                if not index or index < 0 or index >= 32 or tostring(index) ~= suffix then return nil end
                chunks[index] = value
                count = count + 1
            end
        end
    end
    if plain then
        if count ~= 0 then return nil end
        return plain
    end
    local parts = {}
    for index = 0, count - 1 do
        if not chunks[index] then return nil end
        parts[#parts + 1] = chunks[index]
    end
    if count == 0 then return nil end
    return table.concat(parts)
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
    local body = cjson.encode({ token = token })

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
    require("headers").clear(LOCAL_BYPASS_HEADER)

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

    local token = session_cookie(ngx.var.http_cookie, JWT_SALT)
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
