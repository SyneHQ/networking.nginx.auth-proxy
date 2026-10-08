#!/bin/sh
set -eu

TEST_SUFFIX="${TEST_SUFFIX:-$$}"
IMAGE="auth-proxy-boundary-test:$TEST_SUFFIX"
NETWORK="auth-proxy-boundary-test-$$"
TMPDIR="$(mktemp -d)"

cleanup() {
    docker rm -f auth-proxy-boundary-$TEST_SUFFIX authwall-boundary-$TEST_SUFFIX kole-boundary-$TEST_SUFFIX paywall-boundary-$TEST_SUFFIX db-api-boundary-$TEST_SUFFIX app-boundary-$TEST_SUFFIX kms-boundary-$TEST_SUFFIX >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    docker image rm "$IMAGE" >/dev/null 2>&1 || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

cat >"$TMPDIR/authwall.conf" <<'EOF'
server {
    listen 80;
    location = /verify {
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
    location = /verify {
        default_type application/json;
        return 200 '{"success":true,"payload":{"sub":"trusted-user","exp":1}}';
    }
}
EOF

DOCKER_BUILDKIT=0 docker build --memory 512m --cpu-quota 100000 -t "$IMAGE" .
docker network create "$NETWORK" >/dev/null
docker run -d --cpus 0.2 --memory 96m --pids-limit 128 --name authwall-boundary-$TEST_SUFFIX --network "$NETWORK" --network-alias authwall -v "$TMPDIR/authwall.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine >/dev/null
docker run -d --cpus 0.2 --memory 96m --pids-limit 128 --name kole-boundary-$TEST_SUFFIX --network "$NETWORK" --network-alias kole -v "$TMPDIR/kole.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine >/dev/null
docker run --rm --cpus 0.2 --memory 96m --pids-limit 128 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --network "$NETWORK" "$IMAGE" -t
docker run -d --cpus 0.2 --memory 96m --pids-limit 128 --name auth-proxy-boundary-$TEST_SUFFIX --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m --network "$NETWORK" "$IMAGE" >/dev/null

for _ in 1 2 3 4 5; do
    if docker exec auth-proxy-boundary-$TEST_SUFFIX wget -qO- --header='Host: kole.synehq.com' http://127.0.0.1:8080/verify-jwe >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

status() {
    docker exec auth-proxy-boundary-$TEST_SUFFIX wget -S -O /dev/null "$@" 2>&1 | awk '/HTTP\// { code=$2 } END { print code }'
}

test "$(status --header='Host: kole.synehq.com' http://127.0.0.1:8080/verify-jwe)" = "404"
test "$(status --header='Host: kole.synehq.com' --header='X-Api-Key: attacker' http://127.0.0.1:8080/)" = "401"
test "$(status --header='Host: kole.synehq.com' --header='X-Local-Auth-Bypass: local-secret' http://127.0.0.1:8080/)" = "401"
test "$(status --header='Host: kole.synehq.com' http://127.0.0.1:8080/slack/events)" = "200"
test "$(status --header='Host: kole.synehq.com' http://127.0.0.1:8080/slack/events/)" = "401"

body="$(docker exec auth-proxy-boundary-$TEST_SUFFIX wget -qO- --header='Host: kole.synehq.com' --header='Cookie: authjs.session-token=valid-token' --header='X-User-Id: attacker' --header='X-Api-Key: attacker-key' --header='X-Team-Id: attacker-team' --header='X-Forwarded-User: attacker' --header='X-Forwarded-For: 198.51.100.7' http://127.0.0.1:8080/)"
test "$body" = "user=trusted-user api= team= forwarded= for=127.0.0.1"
# A valid chunked cookie reaches the same verification boundary.
test "$(status --header='Host: kole.synehq.com' --header='Cookie: authjs.session-token.1=token; authjs.session-token.0=valid-' http://127.0.0.1:8080/)" = "200"
for cookie in 'authjs.session-token.1=token' 'authjs.session-token.0=a; authjs.session-token.2=b' 'authjs.session-token=a; authjs.session-token.0=b' 'authjs.session-token=a; authjs.session-token=b' 'authjs.session-token.00=a'; do
    test "$(status --header='Host: kole.synehq.com' --header="Cookie: $cookie" http://127.0.0.1:8080/)" = "401"
done

docker rm -f authwall-boundary-$TEST_SUFFIX >/dev/null
docker run -d --cpus 0.2 --memory 96m --pids-limit 128 --name authwall-boundary-$TEST_SUFFIX --network "$NETWORK" --network-alias authwall -v "$TMPDIR/authwall-expired.conf:/etc/nginx/conf.d/default.conf:ro" nginx:alpine >/dev/null
sleep 1
test "$(status --header='Host: kole.synehq.com' --header='Cookie: authjs.session-token=expired-token' http://127.0.0.1:8080/)" = "401"

docker rm -f authwall-boundary-$TEST_SUFFIX >/dev/null
test "$(status --header='Host: kole.synehq.com' --header='Cookie: authjs.session-token=valid-token' http://127.0.0.1:8080/)" = "503"

printf '%s\n' 'auth boundary validation passed'
