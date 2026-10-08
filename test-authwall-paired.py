#!/usr/bin/env python3
"""Test the real proxy and Authwall with disposable keys and no published ports.

Usage: python3 test-authwall-paired.py /path/to/authwall.go
Requires Docker, Python cryptography, and access to the Go dependency registries.
"""
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def run(*args, check=True):
    return subprocess.run(args, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def token(secret, salt, enc, claims):
    size = 64 if enc == "A256CBC-HS512" else 32
    key = HKDF(algorithm=hashes.SHA256(), length=size, salt=salt.encode(),
               info=f"Auth.js Generated Encryption Key ({salt})".encode()).derive(secret.encode())
    jwk = json.dumps({"k": b64(key), "kty": "oct"}, separators=(",", ":")).encode()
    kid = b64((hashlib.sha512 if size == 64 else hashlib.sha256)(jwk).digest())
    header = b64(json.dumps({"alg": "dir", "enc": enc, "kid": kid}, separators=(",", ":")).encode())
    plaintext = json.dumps(claims).encode()
    if size == 32:
        iv = secrets.token_bytes(12)
        encrypted = AESGCM(key).encrypt(iv, plaintext, header.encode())
        ciphertext, tag = encrypted[:-16], encrypted[-16:]
    else:
        iv = secrets.token_bytes(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key[32:]), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        auth_data = header.encode() + iv + ciphertext + struct.pack(">Q", len(header) * 8)
        tag = hmac.new(key[:32], auth_data, hashlib.sha512).digest()[:32]
    return ".".join([header, "", b64(iv), b64(ciphertext), b64(tag)])


def main():
    source = Path(sys.argv[1]).resolve()
    proxy_source = Path(__file__).resolve().parent
    prefix = "authpair-" + secrets.token_hex(4)
    image = prefix + ":test"
    names = [prefix + "-authwall", prefix + "-kole", prefix + "-proxy", prefix + "-app"]
    salt, secret = "__Secure-authjs.session-token", secrets.token_hex(32)
    with tempfile.TemporaryDirectory(prefix=prefix) as folder:
        os.chmod(folder, 0o755)
        temp = Path(folder)
        try:
            run("docker", "run", "--rm", "--cpus", "2", "--memory", "1g", "-e", "GOMAXPROCS=2",
                "-v", f"{source}:/src:ro", "-v", f"{temp}:/out", "-v", os.getenv("AUTHWALL_GO_CACHE", "authwall-paired-go-cache") + ":/root/.cache/go-build",
                "-v", os.getenv("AUTHWALL_GO_MOD", "authwall-paired-go-mod") + ":/go/pkg/mod", "-w", "/src", "golang:1.26.8",
                "sh", "-c", "CGO_ENABLED=0 go build -p 2 -o /out/authwall .")
            env = dict(os.environ, DOCKER_BUILDKIT="0")
            subprocess.run(["docker", "build", "--memory", "512m", "--cpu-quota", "100000", "-t", image, str(proxy_source)],
                           env=env, check=True, stdout=subprocess.DEVNULL)
            run("docker", "network", "create", prefix)
            (temp / "kole.conf").write_text('server { listen 8080; location / { return 200 "user=$http_x_user_id"; } }')
            limits = ["--cpus", "0.25", "--memory", "128m", "--pids-limit", "128", "--network", prefix]
            run("docker", "run", "-d", *limits, "--name", names[0], "--network-alias", "authwall.fixture.test",
                "--read-only", "--user", "65532:65532", "-v", f"{temp}/authwall:/authwall:ro",
                "-e", "ADDR=:8080", "-e", f"AUTH_SECRETS={secret}", "-e", f"AUTH_SALT={salt}",
                "-e", f"AUTH_COOKIE_NAME={salt}", "--entrypoint", "/authwall", "golang:1.26.8")
            run("docker", "run", "-d", *limits, "--name", names[1], "--network-alias", "kole.fixture.test",
                "-v", f"{temp}/kole.conf:/etc/nginx/conf.d/default.conf:ro", "nginx:alpine")
            (temp / "app.conf").write_text('server { listen 3001; location / { return 200 "path=$uri user=$http_x_user_id proto=$http_x_forwarded_proto"; } }')
            run("docker", "run", "-d", *limits, "--name", names[3], "--network-alias", "app.fixture.test",
                "-v", f"{temp}/app.conf:/etc/nginx/conf.d/default.conf:ro", "nginx:alpine")
            run("docker", "run", "-d", *limits, "--name", names[2], "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                "-e", f"JWT_SALT={salt}", "-e", "AUTHWALL_UPSTREAM=authwall.fixture.test:8080",
                "-e", "KOLE_UPSTREAM=kole.fixture.test:8080", "-e", "APP_UPSTREAM=app.fixture.test:3001", image)
            for _ in range(30):
                if run("docker", "exec", names[2], "wget", "-qO-", "http://authwall.fixture.test:8080/health", check=False).returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError("Authwall did not become healthy.")

            def request(cookie, path="/", host="kole.synehq.com"):
                result = run("docker", "exec", names[2], "wget", "-S", "-O", "-", "--header=Host: " + host,
                             "--header=X-User-Id: attacker", "--header=X-Forwarded-Proto: attacker", "--header=Cookie: " + cookie,
                             "http://127.0.0.1:8080" + path, check=False)
                statuses = [line.split()[1] for line in result.stderr.splitlines() if "HTTP/" in line]
                return (statuses[-1] if statuses else "missing"), result.stdout

            for enc in ["A256GCM", "A256CBC-HS512"]:
                claims = {"sub": "verified-member", "exp": int(time.time()) + 600}
                good = token(secret, salt, enc, claims)
                assert request(salt + "=" + good) == ("200", "user=verified-member"), enc
                cut = len(good) // 2
                chunked = salt + ".1=" + good[cut:] + "; " + salt + ".0=" + good[:cut]
                assert request(chunked) == ("200", "user=verified-member"), enc
                wrong = token("wrong-key", salt, enc, claims)
                assert request(salt + "=" + wrong)[0] == "401", enc
                expired = token(secret, salt, enc, {"sub": "verified-member", "exp": 1})
                assert request(salt + "=" + expired)[0] == "401", enc
                assert request(salt + ".1=" + good)[0] == "401", enc
                assert request(salt + "=" + good, "/verify-jwe")[0] == "404", enc
            for path in ["/", "/api/auth/providers", "/api/auth/signin", "/_next/static/test.js"]:
                assert request("", path, "data.synehq.com") == ("200", "path=" + path + " user= proto=https"), path
            for host in ["kole.synehq.com", "cosmos.synehq.com", "paywall.synehq.com"]:
                assert request("", "/api/auth/providers", host)[0] == "401", host
            for host in ["cosmos.synehq.com", "paywall.synehq.com"]:
                assert request("", "/slack/events", host)[0] == "401", host
            assert request("", "/healthz", "127.0.0.1") == ("200", "ok\n")
            assert run("docker", "exec", names[2], "id", "-u").stdout.strip() == "65532"
            print("PASS: real Authwall/proxy, both Auth.js encryption modes, configured keys, expiry, chunks, header identity, private verifier, app login/assets, protected data hosts, readiness, nonroot read-only runtime.")
        finally:
            run("docker", "rm", "-f", *names, check=False)
            run("docker", "network", "rm", prefix, check=False)
            run("docker", "image", "rm", image, check=False)


if __name__ == "__main__":
    main()
