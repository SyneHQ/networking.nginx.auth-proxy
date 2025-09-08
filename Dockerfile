FROM oven/bun:alpine as builder

WORKDIR /app

COPY package.json .
COPY bun.lock .

RUN bun install

COPY decrypt_jwe.ts .
COPY tsconfig.json .

RUN bun run compile

FROM openresty/openresty:alpine as runner

RUN apk add --no-cache \
    luarocks
RUN luarocks install lua-resty-jwt
RUN luarocks install luaossl

COPY --from=builder /app/dist/decrypt /usr/local/bin/decrypt
RUN chmod +x /usr/local/bin/decrypt
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY auth.lua /etc/nginx/lua/auth.lua
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
