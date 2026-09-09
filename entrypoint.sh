#!/bin/sh
set -eu
mkdir -p /var/log/nginx /usr/local/openresty/nginx/logs
chmod 755 /var/log/nginx /usr/local/openresty/nginx/logs
# Authwall verifies sessions; no separate decryption listener is needed.
exec /usr/local/openresty/bin/openresty -g "daemon off; error_log /dev/stderr warn;"
