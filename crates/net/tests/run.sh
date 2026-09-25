#!/usr/bin/env bash
set -euo pipefail
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
trap 'docker compose down --volumes --remove-orphans' EXIT
# Abort only on failure: a node that finishes first must not stop peers still asserting.
docker compose up --abort-on-container-failure
# Require every scenario container to have run to a successful exit.
for service in alice bob charlie daniel eve fabian; do
  state=$(docker inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$(docker compose ps --all --quiet "$service")")
  if [[ "$state" != "exited 0" ]]; then
    echo "Network scenario $service failed or did not finish: $state" >&2
    exit 1
  fi
done
