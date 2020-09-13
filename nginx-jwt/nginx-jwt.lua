local jwt = require "resty.jwt"
local hmac = require "resty.hmac"

local cjson = require "cjson"
local basexx = require "basexx"

local secrets = os.getenv("JWT_SECRETS")

assert(secretS ~= nil, "Environment variable JWT_SECRETS not set")

if os.getenv("JWT_SECRETS_IS_BASE64_ENCODED") == 'true' then
    -- convert from URL-safe Base64 to Base64
    local r = #secrets % 4
    if r == 2 then
        secrets = secrets .. "=="
    elseif r == 3 then
        secrets = secrets .. "="
    end
    secrets = string.gsub(secrets, "-", "+")
    secrets = string.gsub(secrets, "_", "/")

    -- convert from Base64 to UTF-8 string
    secrets = basexx.from_base64(secret)
    ngx.log(ngx.INFO, "Decoded Secret: " .. secrets)
end

-- Going now to JSON Decode the fun
local secrets = json.decode(secrets)


local M = {}

function M.auth(claim_specs)
    -- require Authorization request header
    local auth_header = ngx.var.http_Authorization

    if auth_header == nil then
        ngx.log(ngx.WARN, "No Authorization header")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.log(ngx.INFO, "Authorization: " .. auth_header)

    -- require Bearer token
    local _, _, token = string.find(auth_header, "Bearer%s+(.+)")

    if token == nil then
        ngx.log(ngx.WARN, "Missing token")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.log(ngx.INFO, "Token: " .. token)

    local jwt_obj = jwt:load_jwt(token)
    if not jwt_obj.valid then
        return ngx.exit(403)
    end

    local kid = jwt_obj.payload.kid
    if not kid then
        return ngx.exit(403)
    end

    if secrets[kid] == nil then
      return ngx.exit(403)
    end

    secret = secrets[kid]

    -- require valid JWT
    local jwt_obj = jwt:verify_jwt_obj(secret, jwt_obj)
    if jwt_obj.verified == false then
        ngx.log(ngx.WARN, "Invalid token: ".. jwt_obj.reason)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    ngx.log(ngx.INFO, "JWT: " .. cjson.encode(jwt_obj))

    -- optionally require specific claims
    if claim_specs ~= nil then
        --TODO: test
        -- make sure they passed a Table
        if type(claim_specs) ~= 'table' then
            ngx.log(ngx.STDERR, "Configuration error: claim_specs arg must be a table")
            ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        -- process each claim
        local blocking_claim = ""
        for claim, spec in pairs(claim_specs) do
            -- make sure token actually contains the claim
            local claim_value = jwt_obj.payload[claim]
            if claim_value == nil then
                blocking_claim = claim .. " (missing)"
                break
            end

            local spec_actions = {
                -- claim spec is a string (pattern)
                ["string"] = function (pattern, val)
                    return string.match(val, pattern) ~= nil
                end,

                -- claim spec is a predicate function
                ["function"] = function (func, val)
                    -- convert truthy to true/false
                    if func(val) then
                        return true
                    else
                        return false
                    end
                end
            }

            local spec_action = spec_actions[type(spec)]

            -- make sure claim spec is a supported type
            -- TODO: test
            if spec_action == nil then
                ngx.log(ngx.STDERR, "Configuration error: claim_specs arg claim '" .. claim .. "' must be a string or a table")
                ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
            end

            -- make sure token claim value satisfies the claim spec
            if not spec_action(spec, claim_value) then
                blocking_claim = claim
                break
            end
        end

        if blocking_claim ~= "" then
            ngx.log(ngx.WARN, "User did not satisfy claim: ".. blocking_claim)
            ngx.exit(ngx.HTTP_UNAUTHORIZED)
        end
    end

    -- write the X-Auth-UserId header
    ngx.header["X-Auth-UserId"] = jwt_obj.payload.sub
end

function M.table_contains(table, item)
    for _, value in pairs(table) do
        if value == item then return true end
    end
    return false
end

return M
