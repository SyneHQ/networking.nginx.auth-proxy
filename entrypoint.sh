#!/bin/sh
set -eu
mkdir -p /tmp/auth-proxy/client-body /tmp/auth-proxy/proxy /tmp/auth-proxy/fastcgi /tmp/auth-proxy/uwsgi /tmp/auth-proxy/scgi

# Nginx does not use the resolver search suffix. Set complete service names on Kubernetes.
DNS_RESOLVER="${DNS_RESOLVER:-$(awk '/^nameserver / {print $2; exit}' /etc/resolv.conf)}"
case "$DNS_RESOLVER" in
    ''|*[!0-9a-fA-F.:\[\]]*) echo 'DNS_RESOLVER must contain one DNS server address.' >&2; exit 1 ;;
esac
# Brackets are required for an IPv6 address in an Nginx resolver directive.
case "$DNS_RESOLVER" in
    \[*\]) ;;
    *:*) DNS_RESOLVER="[$DNS_RESOLVER]" ;;
esac

KOLE_UPSTREAM="${KOLE_UPSTREAM:-kole:8080}"
PAYWALL_UPSTREAM="${PAYWALL_UPSTREAM:-paywall:8080}"
DB_API_UPSTREAM="${DB_API_UPSTREAM:-db-api:8080}"
APP_UPSTREAM="${APP_UPSTREAM:-app:3001}"
KMS_UPSTREAM="${KMS_UPSTREAM:-kms:50051}"
AUTHWALL_UPSTREAM="${AUTHWALL_UPSTREAM:-authwall:80}"
for endpoint in "$KOLE_UPSTREAM" "$PAYWALL_UPSTREAM" "$DB_API_UPSTREAM" "$APP_UPSTREAM" "$KMS_UPSTREAM" "$AUTHWALL_UPSTREAM"; do
    case "$endpoint" in
        ''|*[!a-zA-Z0-9.:-]*) echo 'Each upstream must contain a hostname and port.' >&2; exit 1 ;;
    esac
done
sed -e "s/__DNS_RESOLVER__/$DNS_RESOLVER/g" \
    -e "s/__KOLE_UPSTREAM__/$KOLE_UPSTREAM/g" \
    -e "s/__PAYWALL_UPSTREAM__/$PAYWALL_UPSTREAM/g" \
    -e "s/__DB_API_UPSTREAM__/$DB_API_UPSTREAM/g" \
    -e "s/__APP_UPSTREAM__/$APP_UPSTREAM/g" \
    -e "s/__KMS_UPSTREAM__/$KMS_UPSTREAM/g" \
    -e "s/__AUTHWALL_UPSTREAM__/$AUTHWALL_UPSTREAM/g" \
    /app/nginx.conf.template > /tmp/auth-proxy/nginx.conf
exec /usr/local/openresty/bin/openresty -c /tmp/auth-proxy/nginx.conf -g "daemon off;" "$@"
