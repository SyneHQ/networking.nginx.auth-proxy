#!/bin/bash

# Add host entries for local development
echo "127.0.0.1 kole" >> /etc/hosts
echo "127.0.0.1 paywall" >> /etc/hosts
echo "127.0.0.1 db_api" >> /etc/hosts

printenv

# Create log directory and ensure proper permissions
mkdir -p /var/log/nginx
mkdir -p /usr/local/openresty/nginx/logs
chmod 755 /var/log/nginx
chmod 755 /usr/local/openresty/nginx/logs

# Start nginx with proper logging configuration
exec /usr/local/openresty/bin/openresty -g "daemon off; error_log /dev/stderr info;"