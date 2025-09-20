#!/bin/bash
# Create log directory and ensure proper permissions
mkdir -p /var/log/nginx
mkdir -p /usr/local/openresty/nginx/logs
chmod 755 /var/log/nginx
chmod 755 /usr/local/openresty/nginx/logs

# 🚀 [Line 8] main: Starting decrypt server in background
echo "🔧 [Line 9] main: Starting JWT decrypt service..."
/usr/local/bin/decrypt &
DECRYPT_PID=$!
echo "✅ [Line 12] main: Decrypt server started with PID: $DECRYPT_PID"

# 🕐 [Line 14] main: Waiting for decrypt service to be ready
sleep 2

# 📡 [Line 17] main: Setting up signal handling for graceful shutdown
cleanup() {
    echo "🛑 [Line 19] cleanup: Received shutdown signal, cleaning up..."
    if kill -0 $DECRYPT_PID 2>/dev/null; then
        echo "🔄 [Line 21] cleanup: Stopping decrypt server (PID: $DECRYPT_PID)"
        kill $DECRYPT_PID
    fi
    echo "💀 [Line 24] cleanup: Cleanup completed"
    exit 0
}

trap cleanup SIGTERM SIGINT

# 🌐 [Line 29] main: Starting OpenResty with proper logging
echo "🚀 [Line 30] main: Starting OpenResty nginx server..."
exec /usr/local/openresty/bin/openresty -g "daemon off; error_log /dev/stderr info;"