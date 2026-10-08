FROM openresty/openresty:alpine-fat as runner

RUN apk add --no-cache \
    luarocks
RUN luarocks install lua-resty-jwt

COPY nginx.conf /app/nginx.conf.template
COPY auth.lua headers.lua /etc/nginx/lua/
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

USER 65532:65532

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
