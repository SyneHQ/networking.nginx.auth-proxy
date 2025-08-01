local jwt = require "resty.jwt"
local cjson = require "cjson"
local redis = require "resty.redis"
local pgmoon = require "pgmoon"

-- Get environment variables with defaults
local function get_env(name, default)
    return os.getenv(name) or default
end

-- Environment configuration
local JWT_SECRET = get_env("JWT_SECRET", "your_secret")
local JWT_SALT = get_env("JWT_SALT", "authjs.session-token")
local REDIS_HOST = get_env("REDIS_HOST", "redis")
local REDIS_PORT = tonumber(get_env("REDIS_PORT", "6379"))
local REDIS_TIMEOUT = tonumber(get_env("REDIS_TIMEOUT", "1000"))
local REDIS_CACHE_TTL = tonumber(get_env("REDIS_CACHE_TTL", "600"))
local REDIS_PASSWORD = get_env("REDIS_PASSWORD", "")
local REDIS_KEY_PREFIX = get_env("REDIS_KEY_PREFIX", "auth:")

local POSTGRES_HOST = get_env("POSTGRES_HOST", "postgres")
local POSTGRES_PORT = get_env("POSTGRES_PORT", "5432")
local POSTGRES_DB = get_env("POSTGRES_DB", "your_db")
local POSTGRES_USER = get_env("POSTGRES_USER", "your_user")
local POSTGRES_PASSWORD = get_env("POSTGRES_PASSWORD", "your_password")

local USER_TABLE = get_env("USER_TABLE", "users")
local USER_ID_FIELD = get_env("USER_ID_FIELD", "id")

local ENABLE_DB_CHECK = get_env("ENABLE_DB_CHECK", "false")

-- Validate JWT (Auth.js JWE token)
local function validate_jwt(token)
    -- Use the TypeScript decoder to decrypt the JWE token
    local cmd = string.format("/usr/local/bin/decrypt '%s' '%s' '%s'", token, JWT_SECRET, JWT_SALT)
    
    local handle = io.popen(cmd)
    local result = handle:read("*a")
    handle:close()
    
    if not result or result == "" then
        return false
    end
    
    local ok, decoded = pcall(cjson.decode, result)
    if not ok or not decoded then
        return false
    end
    
    -- Check if token is expired
    if decoded.exp and decoded.exp < ngx.time() then
        return false
    end
    
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

local cookies = parse_cookies(ngx.var.http_cookie)
local token = cookies[JWT_SALT]

if not token then
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local jwt_obj = validate_jwt(token)
if not jwt_obj then
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local user_id = jwt_obj.payload.sub

if ENABLE_DB_CHECK == "true" then
    if not check_user(user_id) then
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end
