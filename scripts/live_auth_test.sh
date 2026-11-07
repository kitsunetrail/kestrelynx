#!/usr/bin/env bash
# Runs the live registry login tests with the real Trivy against a registry that
# asks for a login: the registry image with htpasswd authentication, served over
# TLS with a certificate made here, holding kx/app:1.2.3 and kx/app:1.2.4. Needs
# Docker, Go, openssl, curl and trivy. The registry and every file are removed at
# the end. Run it from the repository root.
#
# The scanners as main assembles them are tested on a private address, the case of
# a registry on the user's own network. The plan's tests allow only a loopback
# address, so they get that one. A test that skips counts as a failure here: a
# run in which nothing was tested must not look like a pass.
set -euo pipefail

port="${KX_LIVE_PORT:-5443}"
name="kx-live-registry-$$"
user=klive
work="$(mktemp -d)"
chmod 700 "$work"

cleanup() {
  docker rm -fv "$name" >/dev/null 2>&1 || true
  docker rmi -f "127.0.0.1:$port/kx/app:1.2.3" "127.0.0.1:$port/kx/app:1.2.4" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

private_ip="$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
case "$private_ip" in
  10.* | 192.168.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].*) ;;
  *)
    echo "this host's address ${private_ip:-(none)} is not private, so the test would not cover a private registry" >&2
    exit 1
    ;;
esac

mkdir "$work/auth" "$work/certs" "$work/docker"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=kx-live" \
  -keyout "$work/certs/key.pem" -out "$work/certs/cert.pem" \
  -addext "subjectAltName=IP:$private_ip,IP:127.0.0.1" 2>/dev/null
# The registry container reads the key as another user.
chmod 755 "$work"
chmod 644 "$work/certs/key.pem"
openssl rand -hex 16 | tr -d '\n' >"$work/password"
docker run --rm httpd:2-alpine htpasswd -Bbn "$user" "$(cat "$work/password")" >"$work/auth/htpasswd"

docker run -d --name "$name" -p "$port:5443" \
  -v "$work/auth:/auth:ro" -v "$work/certs:/certs:ro" \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:5443 \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/cert.pem \
  -e REGISTRY_HTTP_TLS_KEY=/certs/key.pem \
  -e REGISTRY_AUTH=htpasswd \
  -e REGISTRY_AUTH_HTPASSWD_REALM=kx \
  -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
  registry:2 >/dev/null

base="https://$private_ip:$port"
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$work/certs/cert.pem" "$base/v2/" || true)"
  [ "$code" = 401 ] && break
  sleep 1
done
if [ "$code" != 401 ]; then
  echo "the registry did not come up asking for a login (last answer: $code)" >&2
  exit 1
fi

# Docker accepts the certificate only for a loopback address, which it treats as
# an insecure registry.
docker --config "$work/docker" login "127.0.0.1:$port" -u "$user" --password-stdin <"$work/password" >/dev/null 2>&1
for pair in 3.19:1.2.3 3.20:1.2.4; do
  from="alpine:${pair%%:*}"
  to="127.0.0.1:$port/kx/app:${pair##*:}"
  docker pull -q --platform linux/amd64 "$from" >/dev/null
  docker tag "$from" "$to"
  docker --config "$work/docker" push -q "$to" >/dev/null
done

digest="$(curl -fsSI --cacert "$work/certs/cert.pem" -u "$user:$(cat "$work/password")" \
  -H 'Accept: application/vnd.oci.image.index.v1+json' \
  -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
  -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
  -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
  "$base/v2/kx/app/manifests/1.2.3" | tr -d '\r' | sed -n 's/^[Dd]ocker-[Cc]ontent-[Dd]igest: //p')"
if [ -z "$digest" ]; then
  echo "could not read the digest of kx/app:1.2.3" >&2
  exit 1
fi

run_tests() { # registry address, package
  local log="$work/test.log"
  KX_LIVE_AUTH_ADDR="$1" KX_LIVE_AUTH_USER="$user" KX_LIVE_AUTH_PWFILE="$work/password" \
    KX_LIVE_AUTH_CA="$work/certs/cert.pem" KX_LIVE_AUTH_DIGEST="$digest" \
    go test -tags live -run TestLiveAuth -count=1 -v -timeout 15m "$2" | tee "$log"
  if grep -q -- '--- SKIP' "$log"; then
    echo "a live test skipped in $2" >&2
    exit 1
  fi
  if ! grep -q -- '--- PASS' "$log"; then
    echo "no live test ran in $2" >&2
    exit 1
  fi
}

run_tests "$private_ip:$port" ./cmd/kestrelynx
run_tests "127.0.0.1:$port" ./internal/remediation
