#!/usr/bin/env bash
# Run one isolated T4 integration check with a durable result across SSH disconnects.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd -P)
mode=${1:-}
run_dir=${2:-}
case "$mode" in
  doctor|cli|oidc) ;;
  *) echo 'expected doctor, cli or oidc' >&2; exit 2 ;;
esac
if [[ -L "$root/ignored" || $(dirname "$run_dir") != "$root/ignored" || $(basename "$run_dir") != hi-t4.* || ! -d "$run_dir" || -L "$run_dir" ]]; then
  echo 'run directory must be a real directory under ignored/hi-t4.*' >&2
  exit 2
fi
for entry in "$run_dir"/* "$run_dir"/.[!.]* "$run_dir"/..?*; do
  if [[ -e "$entry" || -L "$entry" ]]; then
    if [[ "$entry" != "$run_dir/launcher.log" || -L "$entry" || ! -f "$entry" ]]; then
      echo 'run directory must be fresh (only a regular launcher.log is allowed)' >&2
      exit 2
    fi
  fi
done
if ! ( set -C; : > "$run_dir/started" ); then
  echo 'run directory already started' >&2
  exit 2
fi
if [[ -n $(git -C "$root" status --porcelain) ]]; then
  echo 'integration runner requires a clean committed checkout' >&2
  exit 1
fi

finish() {
  status=$?
  trap - EXIT
  printf '%s\n' "$status" > "$run_dir/exit"
  exit "$status"
}
trap finish EXIT
printf '%s\n' "$(git -C "$root" rev-parse HEAD)" > "$run_dir/revision"
printf '%s\n' "$mode" > "$run_dir/mode"
mkdir -p "$run_dir/go" "$run_dir/go-build"

args=(doctor)
if [[ "$mode" != doctor ]]; then
  pattern=TestUserCommand
  [[ "$mode" == oidc ]] && pattern=TestOIDCAuthenticationPingAll
  args=(run "$pattern" --clean-before=false --clean-after=true --keep-on-failure=false --timeout=900s --go-version=1.26.5 --logs-dir="$run_dir/artifacts")
fi

docker run --rm --pull=never --name "hs-t4-hi-${mode}-$(basename "$run_dir")" \
  --network bridge \
  --mount "type=bind,src=$root,dst=$root" \
  --mount "type=bind,src=$run_dir/go,dst=/go" \
  --mount "type=bind,src=$run_dir/go-build,dst=/root/.cache/go-build" \
  --mount type=bind,src=/usr/bin/docker,dst=/usr/bin/docker,readonly \
  --mount type=bind,src=/run/docker.sock,dst=/var/run/docker.sock \
  --workdir "$root" \
  --env HEADSCALE_INTEGRATION_T4_ISOLATED=1 \
  --env "HEADSCALE_INTEGRATION_GO_CACHE=$run_dir/go" \
  --env "HEADSCALE_INTEGRATION_GO_BUILD_CACHE=$run_dir/go-build" \
  --env GIT_CONFIG_COUNT=1 \
  --env GIT_CONFIG_KEY_0=safe.directory \
  --env "GIT_CONFIG_VALUE_0=$root" \
  golang:1.26.5-trixie \
  sh -c 'go run ./cmd/hi "$@"' sh "${args[@]}" \
  > "$run_dir/stdout" 2> "$run_dir/stderr"
