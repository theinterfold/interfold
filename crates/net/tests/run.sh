#!/usr/bin/env bash
set -euo pipefail

THIS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$THIS_DIR"
# Export env vars once for all docker compose commands
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Get the current commit SHA
export IMAGE_TAG=$(git rev-parse --short HEAD)

echo ""
echo "Building docker image (p2p_test:${IMAGE_TAG})"
echo ""
docker build --network host -f ./Dockerfile -t "p2p_test:${IMAGE_TAG}" ../../..
echo ""
echo "NETWORK TESTS"
echo ""
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/interfold-net.XXXXXXXX")"
PROJECT="interfold-net-$(basename "$RUN_DIR" | tr '[:upper:].' '[:lower:]-')"
COMPOSE=(docker compose --project-name "$PROJECT" --file "$THIS_DIR/docker-compose.yaml")

cleanup() {
  local result=$?
  trap - EXIT
  "${COMPOSE[@]}" logs --no-color > "$RUN_DIR/compose.log" 2>&1 || result=1
  "${COMPOSE[@]}" down --volumes --remove-orphans || result=1
  echo "Network test logs: $RUN_DIR/compose.log"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# A successful node must not stop peers that have not finished their assertions.
result=0
"${COMPOSE[@]}" up --abort-on-container-failure || result=1
for service in alice bob charlie daniel eve fabian; do
  container_id="$("${COMPOSE[@]}" ps --all --quiet "$service")" || container_id=""
  if [[ -z "$container_id" || "$container_id" == *$'\n'* ]]; then
    echo "Expected one scenario container for $service" >&2
    result=1
    continue
  fi
  state="$(docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$container_id")" || state="unknown"
  if [[ "$state" != "exited 0" ]]; then
    echo "Network scenario $service failed or did not finish: $state" >&2
    result=1
  fi
done
exit "$result"
