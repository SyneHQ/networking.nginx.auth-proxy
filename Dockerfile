FROM openresty/openresty:alpine-fat as runner

RUN apk add --no-cache \
    luarocks
RUN luarocks install lua-resty-jwt

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY auth.lua /etc/nginx/lua/auth.lua
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/app/entrypoint.sh"]

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
