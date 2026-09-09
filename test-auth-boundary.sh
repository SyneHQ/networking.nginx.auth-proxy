#!/bin/sh
set -eu

IMAGE="auth-proxy-boundary-test:local"
NETWORK="auth-proxy-boundary-test-$$"
TMPDIR="$(mktemp -d)"

cleanup() {
    docker rm -f auth-proxy-test authwall-test kole-test paywall-test db_api-test app-test kms-test >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

cat >"$TMPDIR/authwall.conf" <<'EOF'
server {
    listen 80;
    location = /decrypt {
        default_type application/json;
        return 200 '{"success":true,"payload":{"sub":"trusted-user","exp":4102444800}}';
    }
}
EOF

cat >"$TMPDIR/kole.conf" <<'EOF'
server {
    listen 8080;
    location / {
        default_type text/plain;
        return 200 "user=$http_x_user_id api=$http_x_api_key team=$http_x_team_id forwarded=$http_x_forwarded_user for=$http_x_forwarded_for";
    }
}
EOF

cat >"$TMPDIR/authwall-expired.conf" <<'EOF'
server {
    listen 80;
    location = /decrypt {
        default_type application/json;
        return 200 '{"success":true,"payload":{"sub":"trusted-user","exp":1}}';
    }
}
EOF

docker build -t "$IMAGE" .
docker network create "$NETWORK" >/dev/null
docker run -d --name authwall-test --network "$NETWORK" --network-alias authwall -v "$TMPDIR/authwall.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine >/dev/null
docker run -d --name kole-test --network "$NETWORK" --network-alias kole -v "$TMPDIR/kole.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine >/dev/null
for service in paywall db_api app kms; do
    docker run -d --name "${service}-test" --network "$NETWORK" --network-alias "$service" nginx:alpine >/dev/null
done
docker run --rm --network "$NETWORK" --entrypoint /usr/local/openresty/bin/openresty "$IMAGE" -t
docker run -d --name auth-proxy-test --network "$NETWORK" -e JWT_SECRET=test-secret --entrypoint /usr/local/openresty/bin/openresty "$IMAGE" -g 'daemon off;' >/dev/null

for _ in 1 2 3 4 5; do
    if docker exec auth-proxy-test wget -qO- --header='Host: kole.synehq.com' http://127.0.0.1/verify-jwe >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

status() {
    docker exec auth-proxy-test wget -S -O /dev/null "$@" 2>&1 | awk '/HTTP\// { code=$2 } END { print code }'
}

test "$(status --header='Host: kole.synehq.com' http://127.0.0.1/verify-jwe)" = "404"
test "$(status --header='Host: kole.synehq.com' --header='X-Api-Key: attacker' http://127.0.0.1/)" = "401"
test "$(status --header='Host: kole.synehq.com' --header='X-Local-Auth-Bypass: local-secret' http://127.0.0.1/)" = "401"
test "$(status --header='Host: kole.synehq.com' http://127.0.0.1/slack/events)" = "200"
test "$(status --header='Host: kole.synehq.com' http://127.0.0.1/slack/events/)" = "401"

body="$(docker exec auth-proxy-test wget -qO- --header='Host: kole.synehq.com' --header='Cookie: authjs.session-token=valid-token' --header='X-User-Id: attacker' --header='X-Api-Key: attacker-key' --header='X-Team-Id: attacker-team' --header='X-Forwarded-User: attacker' --header='X-Forwarded-For: 198.51.100.7' http://127.0.0.1/)"
test "$body" = "user=trusted-user api= team= forwarded= for=127.0.0.1"

docker rm -f authwall-test >/dev/null
docker run -d --name authwall-test --network "$NETWORK" --network-alias authwall -v "$TMPDIR/authwall-expired.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine >/dev/null
sleep 1
test "$(status --header='Host: kole.synehq.com' --header='Cookie: authjs.session-token=expired-token' http://127.0.0.1/)" = "401"

docker rm -f authwall-test >/dev/null
test "$(status --header='Host: kole.synehq.com' --header='Cookie: authjs.session-token=valid-token' http://127.0.0.1/)" = "503"

printf '%s\n' 'auth boundary validation passed'
