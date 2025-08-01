#!/bin/bash
# Create log directory and ensure proper permissions
mkdir -p /var/log/nginx
mkdir -p /usr/local/openresty/nginx/logs
chmod 755 /var/log/nginx
chmod 755 /usr/local/openresty/nginx/logs

# Start nginx with proper logging configuration
exec /usr/local/openresty/bin/openresty -g "daemon off; error_log /dev/stderr info;"