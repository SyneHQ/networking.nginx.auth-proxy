local M = {}

function M.clear(local_bypass_header)
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
        local_bypass_header or "X-Local-Auth-Bypass",
    }

    for _, header in ipairs(headers) do
        ngx.req.clear_header(header)
    end
end


return M
