#!/usr/bin/env bash

set -eu  # Exit immediately if a command exits with a non-zero status

THIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# The base scenario, with the active aggregator stopped and started again after the committee
# publishes its key. The round must still decrypt.

restart_active_aggregator() {
  local active_agg_address active_agg
  active_agg_address=$(wait_for_active_aggregator_address "$E3_ID")
  if ! active_agg=$(node_name_for_address "$active_agg_address"); then
    echo "Failed to resolve active aggregator node name for address: $active_agg_address" >&2
    exit 1
  fi

  if [[ -z "$active_agg" ]]; then
    echo "Resolved empty active aggregator node name for address: $active_agg_address" >&2
    exit 1
  fi

  # kill active aggregator
  interfold_nodes_stop "$active_agg"

  sleep 15

  # relaunch the active aggregator
  interfold_nodes_start "$active_agg"

  sleep 5
}

AFTER_KEY_PUBLISHED=restart_active_aggregator
source "$THIS_DIR/base.sh"
