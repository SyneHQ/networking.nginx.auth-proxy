local jwt = require "resty.jwt"
local cjson = require "cjson"
-- local redis = require "resty.redis"
-- local pgmoon = require "pgmoon"

-- Get environment variables with defaults
local function get_env(name, default)
    return os.getenv(name) or default
end

-- Environment configuration
local JWT_SECRET = get_env("JWT_SECRET", "your_secret")
local JWT_SALT = get_env("JWT_SALT", "authjs.session-token")
local ALLOW_BYPASS = get_env("ALLOW_BYPASS", "false")
local BYPASS_HEADER = get_env("BYPASS_HEADER", "X-Bypass-Auth")
local BYPASS_HEADER_VALUE = get_env("BYPASS_HEADER_VALUE", "true")
-- local REDIS_HOST = get_env("REDIS_HOST", "redis")
-- local REDIS_PORT = tonumber(get_env("REDIS_PORT", "6379"))
-- local REDIS_TIMEOUT = tonumber(get_env("REDIS_TIMEOUT", "1000"))
-- local REDIS_CACHE_TTL = tonumber(get_env("REDIS_CACHE_TTL", "600"))
-- local REDIS_PASSWORD = get_env("REDIS_PASSWORD", "")
-- local REDIS_KEY_PREFIX = get_env("REDIS_KEY_PREFIX", "auth:")

-- local POSTGRES_HOST = get_env("POSTGRES_HOST", "postgres")
-- local POSTGRES_PORT = get_env("POSTGRES_PORT", "5432")
-- local POSTGRES_DB = get_env("POSTGRES_DB", "your_db")
-- local POSTGRES_USER = get_env("POSTGRES_USER", "your_user")
-- local POSTGRES_PASSWORD = get_env("POSTGRES_PASSWORD", "your_password")

-- local USER_TABLE = get_env("USER_TABLE", "users")
-- local USER_ID_FIELD = get_env("USER_ID_FIELD", "id")

local ENABLE_DB_CHECK = get_env("ENABLE_DB_CHECK", "false")
-- Validate JWT (Auth.js JWE token)
local function validate_jwt(token)
    ngx.log(ngx.ERR, "🔐 [Line 30] validate_jwt: Starting JWT validation for token")
    
    -- Prepare request body for the decrypt service
    local request_body = cjson.encode({
        token = token,
        secret = JWT_SECRET,
        salt = JWT_SALT
    })
    -- Use nginx internal location to verify JWE token on port 3000
    local res = ngx.location.capture("/verify-jwe", {
        method = ngx.HTTP_POST,
        body = request_body,
        headers = {
            ["Content-Type"] = "application/json"
        }
    })
    
    if not res then
        ngx.log(ngx.ERR, "❌ [Line 47] validate_jwt: Failed to capture internal location /verify-jwe")
        return false
    end
    
    if res.status ~= 200 then
        ngx.log(ngx.ERR, "❌ [Line 52] validate_jwt: /verify-jwe returned status " .. res.status)
        return false
    end
    
    if not res.body or res.body == "" then
        ngx.log(ngx.ERR, "❌ [Line 57] validate_jwt: Empty response body from /verify-jwe")
        return false
    end
    
    local ok, response = pcall(cjson.decode, res.body)
    if not ok or not response then
        ngx.log(ngx.ERR, "❌ [Line 63] validate_jwt: Failed to decode JSON response from /verify-jwe")
        return false
    end
    
    if not response.success or not response.payload then
        ngx.log(ngx.ERR, "❌ [Line 68] validate_jwt: Decrypt service returned error: " .. (response.error or "unknown"))
        return false
    end
    
    local decoded = response.payload
    
    -- Check if token is expired
    if decoded.exp and decoded.exp < ngx.time() then
        ngx.log(ngx.ERR, "⏰ [Line 76] validate_jwt: Token expired, exp=" .. decoded.exp .. " current=" .. ngx.time())
        return false
    end
    
    ngx.log(ngx.INFO, "✅ [Line 80] validate_jwt: JWT validation successful")
    return { payload = decoded }
end

-- Check user in Redis and Postgres
local function check_user(user_id)
    local red = redis:new()
    red:set_timeout(REDIS_TIMEOUT)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        return false
    end
    
    local cache_key = REDIS_KEY_PREFIX .. user_id
    
    local res, err = red:get(cache_key)
    if res == ngx.null then
        local pg = pgmoon.new({
            host = POSTGRES_HOST,
            port = POSTGRES_PORT,
            database = POSTGRES_DB,
            user = POSTGRES_USER,
            password = POSTGRES_PASSWORD
        })
        
        local connected, err = pg:connect()
        if not connected then
            return false
        end
        
        local query = "SELECT exists (SELECT 1 FROM " .. USER_TABLE .. " WHERE " .. USER_ID_FIELD .. " = " .. pg:escape_literal(user_id) .. ")"
        
        local result, err = pg:query(query)
        if not result then
            return false
        end
        
        if result[1].exists ~= true then
            return false
        end
        
        red:setex(cache_key, REDIS_CACHE_TTL, "true")
    end
    
    return true
end

-- Parse cookies manually from ngx.var.http_cookie
local function parse_cookies(cookie_string)
    if not cookie_string then
        return {}
    end
    
    local cookies = {}
    for cookie in string.gmatch(cookie_string, "([^;]+)") do
        local key, value = string.match(cookie:gsub("^%s+", ""), "([^=]+)=(.+)")
        if key and value then
            cookies[key] = value
        end
    end
    return cookies
end

-- Allow OPTIONS requests to pass through without authentication for CORS preflight
if ngx.var.request_method == "OPTIONS" then
    ngx.log(ngx.INFO, "🚀 Line 105 - auth.lua:main() - Allowing OPTIONS preflight request: ", ngx.var.request_uri)
    return ngx.exit(ngx.HTTP_OK)
end

-- get request headers
local headers = ngx.req.get_headers()
local bypass_header_value = headers[BYPASS_HEADER]

if ALLOW_BYPASS == "true" and bypass_header_value and bypass_header_value == BYPASS_HEADER_VALUE then
    ngx.log(ngx.INFO, "🔓 Line 112 - auth.lua:main() - Bypassing auth for request: ", ngx.var.request_uri)
    return ngx.exit(ngx.HTTP_OK)
end

local cookies = parse_cookies(ngx.var.http_cookie)
local token = cookies[JWT_SALT]

if not token then
    ngx.log(ngx.ERR, "❌ Line 119 - auth.lua:main() - No JWT token found in cookies for request: ", ngx.var.request_uri)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local jwt_obj = validate_jwt(token)
if not jwt_obj then
    ngx.log(ngx.ERR, "❌ Line 125 - auth.lua:validate_jwt() - Invalid JWT token for request: ", ngx.var.request_uri)
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local user_id = jwt_obj.payload.sub

-- we need to set user_id in the request headers
ngx.req.set_header("X-User-Id", user_id)
ngx.log(ngx.INFO, "✅ Line 132 - auth.lua:main() - Authentication successful for user: ", user_id, " request: ", ngx.var.request_uri)

if ENABLE_DB_CHECK == "true" then
    if not check_user(user_id) then
        ngx.log(ngx.ERR, "❌ Line 136 - auth.lua:check_user() - User not found in database: ", user_id, " request: ", ngx.var.request_uri)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    ngx.log(ngx.INFO, "✅ Line 139 - auth.lua:check_user() - Database check passed for user: ", user_id)
end
