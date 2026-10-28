#!/usr/bin/env bash
# Disposable staging proof for the unpushed 4ADO build. Never use live volumes.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"
compose="$root/integration/local_auth_staging/compose.yaml"
project=headscale-local-auth-t4
network=headscale-t4-isolated
host=stage.headscale.test

if docker ps -aq --filter "label=com.docker.compose.project=$project" | grep -q . ||
   docker network inspect "$network" >/dev/null 2>&1; then
  echo 'staging resources already exist; refusing to touch them' >&2
  exit 1
fi
export STAGING_DIR
STAGING_DIR=$(mktemp -d "$root/.local-auth-t4.XXXXXXXX")
started=0
cleanup() {
  status=$?
  trap - EXIT
  if (( started )); then
    if (( status != 0 )); then
      echo 'staging failed; collecting only this project status and bounded logs' >&2
      docker compose -p "$project" -f "$compose" ps --all >&2 || true
      docker compose -p "$project" -f "$compose" logs --no-color --tail=50 >&2 || true
    fi
    docker compose -p "$project" -f "$compose" down --remove-orphans || true
  fi
  rm -rf -- "$STAGING_DIR"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
mkdir -p "$STAGING_DIR"/{bin,certs,data}

python3 - "$root/config-example.yaml" "$STAGING_DIR/config.yaml" \
  "$root/derp-example.yaml" "$STAGING_DIR/derp.yaml" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
changes = {
    '\nserver_url: http://127.0.0.1:8080\n': '\nserver_url: https://stage.headscale.test\n',
    '\nlisten_addr: 127.0.0.1:8080\n': '\nlisten_addr: 0.0.0.0:8080\n',
    '\ntrusted_proxies: []\n': '\ntrusted_proxies: [172.30.88.3/32]\n',
    '  urls:\n    - https://controlplane.tailscale.com/derpmap/default\n': '  urls: []\n',
    '\n  auto_update_enabled: true\n': '\n  auto_update_enabled: false\n',
    '\n  paths: []\n': '\n  paths:\n    - /staging/derp.yaml\n',
    '\ndisable_check_updates: false\n': '\ndisable_check_updates: true\n',
    '\n  mode: file\n': '\n  mode: database\n',
}
for old, new in changes.items():
    assert source.count(old) == 1, f'config-example changed: {old!r}'
    source = source.replace(old, new)
Path(sys.argv[2]).write_text(source + '\nlocal_auth:\n  enabled: true\n')
derp = Path(sys.argv[3]).read_text()
for old, new in {
    'myderp.example.com': 'staging-derp.invalid',
    '198.51.100.1': '127.0.0.1',
    '2001:db8::1': '::1',
}.items():
    assert derp.count(old) == 1, f'derp-example changed: {old!r}'
    derp = derp.replace(old, new)
Path(sys.argv[4]).write_text(derp)
PY
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj "/CN=$host" -addext "subjectAltName=DNS:$host" \
  -keyout "$STAGING_DIR/certs/key.pem" -out "$STAGING_DIR/certs/cert.pem" \
  >/dev/null 2>&1
chmod 600 "$STAGING_DIR/certs/key.pem"

docker run --rm -v "$root:/src:ro" -v "$STAGING_DIR/bin:/out" \
  -v headscale-local-auth-gomodcache:/go/pkg/mod \
  -v headscale-local-auth-gocache:/root/.cache/go-build \
  -w /src -e GOTOOLCHAIN=local -e GIT_CONFIG_COUNT=1 \
  -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
  golang:1.26.5-trixie go build -o /out/headscale ./cmd/headscale
docker run --rm -v "$STAGING_DIR/config.yaml:/staging/config.yaml:ro" \
  -v "$STAGING_DIR/bin:/staging/bin:ro" \
  -v "$STAGING_DIR/derp.yaml:/staging/derp.yaml:ro" golang:1.26.5-trixie \
  /staging/bin/headscale --config /staging/config.yaml configtest
docker compose -p "$project" -f "$compose" config -q

started=1
docker compose -p "$project" -f "$compose" up -d
proxy_id=$(docker compose -p "$project" -f "$compose" ps -q traefik)
backend_id=$(docker compose -p "$project" -f "$compose" ps -q headscale)
if [[ -z "$proxy_id" || -z "$backend_id" ]]; then
  echo 'a staging service stopped immediately after startup' >&2
  exit 1
fi
docker inspect --format '{{json .HostConfig.PortBindings}}' "$backend_id" |
  python3 -c 'import json,sys; assert not json.load(sys.stdin), "backend published a host port"'
docker inspect --format '{{json .HostConfig.PortBindings}}' "$proxy_id" |
  python3 -c 'import json,sys; assert not json.load(sys.stdin), "proxy published a host port"'
for id in "$backend_id" "$proxy_id"; do
  docker inspect --format '{{json .NetworkSettings.Ports}}' "$id" |
    python3 -c 'import json,sys; assert not any((json.load(sys.stdin) or {}).values()), "container has an effective published port"'
done

url="https://$host/local-auth/enroll"
code=''
for _ in $(seq 1 30); do
  code=$(docker run --rm --network "$network" curlimages/curl:8.11.1 \
    --silent --insecure --noproxy '*' --max-time 3 \
    --resolve "$host:443:172.30.88.3" -o /dev/null \
    -w '%{http_code}' "$url" || true)
  [[ "$code" == 200 ]] && break
  sleep 1
done
if [[ "$code" != 200 ]]; then
  echo "staging proxy enrollment GET failed: HTTP $code" >&2
  docker compose -p "$project" -f "$compose" logs --no-color --tail=30 >&2
  exit 1
fi

spoofed=$(docker run --rm --network "$network" curlimages/curl:8.11.1 \
  --silent --insecure --noproxy '*' --max-time 5 \
  --resolve "$host:443:172.30.88.3" -o /dev/null -w '%{http_code}' \
  -H 'X-Forwarded-Proto: http' "$url")
[[ "$spoofed" == 200 ]] || { echo "spoofed XFP was not overwritten: $spoofed" >&2; exit 1; }
direct=$(docker run --rm --network "$network" curlimages/curl:8.11.1 \
  --silent --max-time 5 -o /dev/null -w '%{http_code}' \
  -H "Host: $host:18443" -H 'X-Forwarded-Proto: https' \
  http://headscale:8080/local-auth/enroll)
[[ "$direct" == 403 ]] || { echo "untrusted direct backend was not rejected: $direct" >&2; exit 1; }

marker=staging-fixture-marker
rejected=$(docker run --rm --network "$network" curlimages/curl:8.11.1 \
  --silent --insecure --noproxy '*' --max-time 5 \
  --resolve "$host:443:172.30.88.3" -o /dev/null -w '%{http_code}' \
  -H "Origin: https://$host" \
  --data-urlencode "token=$marker" --data-urlencode 'password=not-a-real-password' \
  --data-urlencode 'csrf=not-a-valid-csrf' "$url")
[[ "$rejected" == 403 ]] || { echo "rejected POST returned $rejected" >&2; exit 1; }
docker compose -p "$project" -f "$compose" logs --no-color --tail=250 >"$STAGING_DIR/logs.txt"
if grep -Fq "$marker" "$STAGING_DIR/logs.txt"; then
  echo 'fake request-body token appeared in staging logs' >&2
  exit 1
fi
printf 'PASS isolated Traefik: TLS GET, spoofed XFP overwritten, zero host ports, untrusted direct GET rejected, fake POST body absent from recent logs\n'
