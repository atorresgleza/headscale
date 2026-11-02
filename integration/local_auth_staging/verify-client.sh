#!/usr/bin/env bash
# One disposable real Tailscale software-client login; never target public DNS.
set -euo pipefail
umask 077

root=$(git rev-parse --show-toplevel)
cd "$root"
run_dir=${1:?usage: verify-client.sh FRESH_IGNORED_RUN_DIR}
project=headscale-local-auth-t4
network=headscale-t4-isolated
host=hs.aaaagen.com
client=headscale-t4-client-ts
flow=headscale-t4-client-flow
if [[ ! -d "$run_dir" || -L "$run_dir" || -n $(find "$run_dir" -mindepth 1 -maxdepth 1 ! -name launcher.log -print -quit) ||
      ( -e "$run_dir/launcher.log" && ( ! -f "$run_dir/launcher.log" || -L "$run_dir/launcher.log" ) ) ]]; then
  echo 'requires a fresh run directory (only a regular launcher.log may exist)' >&2; exit 2
fi
run_dir=$(realpath -e -- "$run_dir")
[[ "$run_dir" == "$root"/ignored/client-t4.* ]] || { echo 'run directory outside ignored scope' >&2; exit 2; }
trap 'status=$?; printf "%s\n" "$status" > "$run_dir/exit"' EXIT
[[ -z $(git status --porcelain) ]] || { echo 'requires a clean committed checkout' >&2; exit 2; }
printf '%s\n' "$(git rev-parse HEAD)" > "$run_dir/revision"
for name in "$client" "$flow"; do
  [[ -z $(docker ps -aq --filter "name=^/${name}$") ]] || { echo 'own client name already occupied' >&2; exit 2; }
done
[[ -z $(docker ps -aq --filter "label=com.docker.compose.project=$project") ]] || { echo 'staging project already occupied' >&2; exit 2; }
if docker network inspect "$network" >/dev/null 2>&1; then echo 'staging network already occupied' >&2; exit 2; fi
[[ $(df -Pk "$root" | awk 'NR==2 {print $4}') -ge 3145728 ]] || { echo 'less than 3 GiB free' >&2; exit 2; }
for image in golang:1.26.5-trixie traefik:v3.6.10 mcr.microsoft.com/playwright:v1.58.0-noble tailscale/tailscale@sha256:8c42c4574ab066384fcb72f69e086a2ff1dd3652eb6f56856cee34bcf0d2f680; do
  docker image inspect "$image" >/dev/null || { echo 'required cached image missing' >&2; exit 2; }
done
docker volume inspect headscale-local-auth-gomodcache >/dev/null || { echo 'staging-only module cache unavailable' >&2; exit 2; }
module_kib=$(docker run --rm --network none --read-only \
  -v headscale-local-auth-gomodcache:/source:ro --entrypoint /bin/sh \
  golang:1.26.5-trixie -c 'du -sk /source | cut -f1')
free_kib=$(df -Pk "$root" | awk 'NR==2 {print $4}')
[[ "$module_kib" =~ ^[0-9]+$ && "$module_kib" -le 1572864 && "$free_kib" -ge $((module_kib * 2 + 2097152)) ]] || {
  echo 'insufficient bounded space for private writable Go module cache' >&2; exit 2;
}

STAGING_DIR=$(mktemp -d "$root/ignored/.local-auth-device.XXXXXXXX")
export STAGING_DIR
started=0
client_id=''
flow_id=''
finish() {
  result=$?
  trap - EXIT INT TERM
  set +e
  for owned_id in "$client_id" "$flow_id"; do
    [[ -z "$owned_id" ]] || docker rm -f "$owned_id" >/dev/null 2>&1
  done
  if (( started )); then
    docker compose -p "$project" -f "$compose" -f "$override" down >"$run_dir/cleanup.log" 2>&1
    cleanup_exit=$?
  else
    cleanup_exit=0
  fi
  if docker network inspect "$network" >/dev/null 2>&1 ||
     [[ -n $(docker ps -aq --filter "label=com.docker.compose.project=$project") ]]; then
    cleanup_exit=1
  fi
  for name in "$client" "$flow"; do
    if docker inspect "$name" >/dev/null 2>&1; then cleanup_exit=1; fi
  done
  if [[ -d "$STAGING_DIR/cache/mod" && ! -L "$STAGING_DIR/cache/mod" ]]; then
    chmod -R u+w -- "$STAGING_DIR/cache/mod" >>"$run_dir/cleanup.log" 2>&1 || cleanup_exit=1
  elif [[ -e "$STAGING_DIR/cache/mod" ]]; then
    cleanup_exit=1
  fi
  rm -rf -- "$STAGING_DIR" >>"$run_dir/cleanup.log" 2>&1
  [[ $? == 0 && ! -e "$STAGING_DIR" ]] || cleanup_exit=1
  printf '%s\n' "$cleanup_exit" > "$run_dir/cleanup.exit"
  (( cleanup_exit == 0 )) || result=1
  printf '%s\n' "$result" > "$run_dir/exit"
  exit "$result"
}
trap finish EXIT
trap 'exit 130' INT TERM
git clone --quiet --no-hardlinks --no-checkout -- "$root" "$STAGING_DIR/source"
git -C "$STAGING_DIR/source" -c advice.detachedHead=false checkout --quiet --detach "$(<"$run_dir/revision")"
[[ $(git -C "$STAGING_DIR/source" rev-parse HEAD) == "$(<"$run_dir/revision")" &&
   -z $(git -C "$STAGING_DIR/source" status --porcelain) ]] || { echo 'staging source snapshot mismatch' >&2; exit 2; }
source_root="$STAGING_DIR/source"
compose="$source_root/integration/local_auth_staging/compose.yaml"
override="$source_root/integration/local_auth_staging/client.override.yaml"
mkdir -p "$STAGING_DIR"/{bin,certs,data,secret,ca-private,cache/mod,cache/build}
STAGING_UID=$(id -u)
STAGING_GID=$(id -g)
export STAGING_UID STAGING_GID

python3 - "$source_root/config-example.yaml" "$STAGING_DIR/config.yaml" "$source_root/derp-example.yaml" "$STAGING_DIR/derp.yaml" "$source_root/integration/local_auth_staging/traefik.yaml" "$STAGING_DIR/traefik.yaml" <<'PY'
from pathlib import Path
import sys
config = Path(sys.argv[1]).read_text()
for old, new in {
    '\nserver_url: http://127.0.0.1:8080\n': '\nserver_url: https://hs.aaaagen.com\n',
    '\nlisten_addr: 127.0.0.1:8080\n': '\nlisten_addr: 0.0.0.0:8080\n',
    '\ntrusted_proxies: []\n': '\ntrusted_proxies: [172.30.88.3/32]\n',
    '  urls:\n    - https://controlplane.tailscale.com/derpmap/default\n': '  urls: []\n',
    '\n  auto_update_enabled: true\n': '\n  auto_update_enabled: false\n',
    '\n  paths: []\n': '\n  paths:\n    - /staging/derp.yaml\n',
    '\ndisable_check_updates: false\n': '\ndisable_check_updates: true\n',
    '\nunix_socket: /var/run/headscale/headscale.sock\n': '\nunix_socket: /var/lib/headscale/headscale.sock\n',
    '\n  mode: file\n': '\n  mode: database\n',
}.items():
    assert config.count(old) == 1, 'config example changed'
    config = config.replace(old, new)
Path(sys.argv[2]).write_text(config + '\nlocal_auth:\n  enabled: true\n')
derp = Path(sys.argv[3]).read_text()
for old, new in {'myderp.example.com':'staging-derp.invalid','198.51.100.1':'127.0.0.1','2001:db8::1':'::1'}.items():
    assert derp.count(old) == 1, 'DERP example changed'
    derp = derp.replace(old, new)
Path(sys.argv[4]).write_text(derp)
traefik = Path(sys.argv[5]).read_text()
assert traefik.count('stage.headscale.test') == 1
Path(sys.argv[6]).write_text(traefik.replace('stage.headscale.test', 'hs.aaaagen.com'))
PY
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -sha256 -subj '/CN=staging-only-test-ca' \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$STAGING_DIR/ca-private/key.pem" -out "$STAGING_DIR/certs/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=$host" \
  -keyout "$STAGING_DIR/certs/key.pem" -out "$STAGING_DIR/certs/leaf.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$host" > "$STAGING_DIR/certs/leaf.ext"
openssl x509 -req -in "$STAGING_DIR/certs/leaf.csr" -CA "$STAGING_DIR/certs/ca.pem" \
  -CAkey "$STAGING_DIR/ca-private/key.pem" -CAcreateserial -days 1 \
  -extfile "$STAGING_DIR/certs/leaf.ext" -out "$STAGING_DIR/certs/cert.pem" >/dev/null 2>&1

docker compose -p "$project" -f "$compose" -f "$override" config --format json |
  python3 -c 'import json,sys; c=json.load(sys.stdin); n=c["networks"]["isolated"]; p=c["services"]["traefik"]; assert n["internal"] is True and "hs.aaaagen.com" in p["networks"]["isolated"]["aliases"] and not p.get("ports"); assert not c["services"]["headscale"].get("ports")'
docker run --rm --network none --read-only -u "$(id -u):$(id -g)" \
  -v headscale-local-auth-gomodcache:/source:ro -v "$STAGING_DIR/cache/mod:/dest" \
  --entrypoint /bin/sh golang:1.26.5-trixie \
  -c 'cp -R /source/. /dest/ && chmod -R u+w /dest/cache/download'
docker run --rm --network none -u "$(id -u):$(id -g)" -v "$source_root:/src:ro" \
  -v "$STAGING_DIR/bin:/out" -v "$STAGING_DIR/cache/mod:/cache/mod" \
  -v "$STAGING_DIR/cache/build:/cache/build" -w /src \
  -e GOMODCACHE=/cache/mod -e GOCACHE=/cache/build -e GOPROXY=off -e GOSUMDB=off -e GOTOOLCHAIN=local \
  -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
  golang:1.26.5-trixie go build -buildvcs=true -o /out/headscale ./cmd/headscale
docker run --rm --network none -v "$STAGING_DIR/bin:/out:ro" golang:1.26.5-trixie go version -m /out/headscale |
  python3 -c 'import sys; lines=sys.stdin.read().splitlines(); expected=sys.argv[1]; assert "\tbuild\tvcs.revision="+expected in lines and "\tbuild\tvcs.modified=false" in lines, "staging binary revision mismatch"' "$(<"$run_dir/revision")"
docker run --rm --network none -v "$STAGING_DIR/config.yaml:/staging/config.yaml:ro" -v "$STAGING_DIR/bin:/staging/bin:ro" -v "$STAGING_DIR/derp.yaml:/staging/derp.yaml:ro" golang:1.26.5-trixie /staging/bin/headscale --config /staging/config.yaml configtest >/dev/null
started=1
docker compose -p "$project" -f "$compose" -f "$override" up -d >/dev/null
for service in traefik headscale; do
  id=$(docker compose -p "$project" -f "$compose" -f "$override" ps -q "$service")
  if [[ -z "$id" ]]; then
    {
      docker compose -p "$project" -f "$compose" -f "$override" ps --all || true
      docker compose -p "$project" -f "$compose" -f "$override" logs --no-color --tail=80 "$service" || true
    } >"$run_dir/startup-diagnostic.log" 2>&1
    echo 'staging service unavailable (private startup diagnostic retained)' >&2; exit 1
  fi
  docker inspect "$id" --format '{{json .HostConfig.PortBindings}} {{json .NetworkSettings.Ports}}' |
    python3 -c 'import json,sys; a,b=sys.stdin.read().strip().split(" ",1); assert not json.loads(a) and not any((json.loads(b) or {}).values()), "published host port"'
done
[[ $(docker network inspect "$network" --format '{{.Internal}}') == true ]] || { echo 'staging network not internal' >&2; exit 1; }

flow_id=$(docker run -d --name "$flow" --network "$network" --user "$(id -u):$(id -g)" \
  -v "$STAGING_DIR/secret:/staging/secret" -v "$STAGING_DIR/certs/ca.pem:/staging/certs/ca.pem:ro" \
  -v "$source_root/integration/local_auth_staging/client-flow.cjs:/staging/client-flow.cjs:ro" \
  -e NODE_EXTRA_CA_CERTS=/staging/certs/ca.pem --entrypoint /bin/sh \
  mcr.microsoft.com/playwright:v1.58.0-noble -c 'sleep 600')
for attempt in $(seq 1 30); do
  if docker exec "$flow" node /staging/client-flow.cjs preflight >"$run_dir/preflight.log" 2>&1; then break; fi
  if [[ "$attempt" == 30 ]]; then echo 'staging private DNS/CA HTTPS preflight failed' >&2; exit 1; fi
  sleep 1
done
printf 'PASS staging-only DNS and trusted test CA; no public endpoint requested\n'

# Only after the private alias and TLS have passed, issue a disposable token.
docker compose -p "$project" -f "$compose" -f "$override" exec -T headscale /staging/bin/headscale --config /staging/config.yaml users create staging-test-user >"$STAGING_DIR/secret/user.out" 2>"$STAGING_DIR/secret/user.err"
docker compose -p "$project" -f "$compose" -f "$override" exec -T headscale /staging/bin/headscale --config /staging/config.yaml users list -o json >"$STAGING_DIR/secret/users.json" 2>"$STAGING_DIR/secret/users.err"
user_id=$(python3 - "$STAGING_DIR/secret/users.json" <<'PY'
import json,sys
users=json.load(open(sys.argv[1])); assert len(users)==1 and users[0]['name']=='staging-test-user'
print(users[0]['id'])
PY
)
docker compose -p "$project" -f "$compose" -f "$override" exec -T headscale /staging/bin/headscale --config /staging/config.yaml users invite --identifier "$user_id" --origin "https://$host" >"$STAGING_DIR/secret/invitation" 2>"$STAGING_DIR/secret/invite.err"
printf 'isolated-staging-password-only-2026\n' >"$STAGING_DIR/secret/password"
docker exec "$flow" node /staging/client-flow.cjs enroll
printf 'PASS staging-only user credential enrolled without exporting invitation\n'

# A real Tailscale binary, not a mock or the Windows client. No host ports or external networks.
client_id=$(docker run -d --name "$client" --network "$network" --read-only \
  --tmpfs /tmp --tmpfs /var/run/tailscale \
  -v "$STAGING_DIR/certs/ca.pem:/staging/ca.pem:ro" -v "$STAGING_DIR/secret:/staging/secret" \
  -e SSL_CERT_FILE=/staging/ca.pem --entrypoint /usr/local/bin/tailscaled \
  tailscale/tailscale@sha256:8c42c4574ab066384fcb72f69e086a2ff1dd3652eb6f56856cee34bcf0d2f680 \
  --tun=userspace-networking --socket=/tmp/tailscaled.sock --state=/tmp/state)
[[ $(docker inspect "$client" --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}') == "$network" ]] || { echo 'Tailscale client left private network' >&2; exit 1; }
docker exec "$client" getent hosts "$host" | python3 -c 'import sys; addresses={line.split()[0] for line in sys.stdin}; assert addresses=={"172.30.88.3"}, "Tailscale DNS alias escaped staging"'
docker exec "$client" tailscale version | head -n 1 > "$run_dir/client-version"
docker exec -d "$client" /bin/sh -c 'tailscale --socket=/tmp/tailscaled.sock login --login-server=https://hs.aaaagen.com >/staging/secret/login.out 2>&1; printf "%s\n" "$?" >/staging/secret/login.exit'
for attempt in $(seq 1 60); do
  if [[ -f "$STAGING_DIR/secret/login.out" ]] && grep -Eq 'https://hs\.aaaagen\.com/register/[A-Za-z0-9_-]+' "$STAGING_DIR/secret/login.out"; then break; fi
  if [[ -f "$STAGING_DIR/secret/login.exit" || "$attempt" == 60 ]]; then echo 'real client did not produce pending staging registration' >&2; exit 1; fi
  sleep 1
done
docker exec "$flow" node /staging/client-flow.cjs login
nodes_before=$(docker compose -p "$project" -f "$compose" -f "$override" exec -T headscale /staging/bin/headscale --config /staging/config.yaml nodes list -o json)
python3 -c 'import json,sys; assert len(json.load(sys.stdin) or [])==0, "login approved node without confirmation"' <<< "$nodes_before"
printf 'PASS real Tailscale client pending; password login did not register node\n'
docker exec "$flow" node /staging/client-flow.cjs approve
nodes_after=$(docker compose -p "$project" -f "$compose" -f "$override" exec -T headscale /staging/bin/headscale --config /staging/config.yaml nodes list -o json)
python3 -c 'import json,sys; nodes=json.load(sys.stdin); assert len(nodes)==1, "expected exactly one approved node"; assert str(nodes[0]["user"]["id"])==sys.argv[1], "wrong node owner"' "$user_id" <<< "$nodes_after"
for attempt in $(seq 1 30); do
  [[ -f "$STAGING_DIR/secret/login.exit" ]] && break
  sleep 1
done
[[ $(cat "$STAGING_DIR/secret/login.exit" 2>/dev/null) == 0 ]] || { echo 'real Tailscale login did not complete after approval' >&2; exit 1; }
if ! docker exec "$client" tailscale --socket=/tmp/tailscaled.sock status --json \
  >"$STAGING_DIR/secret/client-status.json" 2>"$STAGING_DIR/secret/client-status.err"; then
  echo 'real Tailscale status command failed' >&2; exit 1
fi
python3 - "$STAGING_DIR/secret/client-status.json" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    status = json.load(stream)
assert status.get('BackendState') == 'Running', 'client backend is not Running'
assert isinstance(status.get('Self'), dict) and status['Self'].get('PublicKey'), 'client self identity unavailable'
PY
printf 'PASS one local-password-approved Tailscale software node, Running client and rejected confirmation replay\n'
