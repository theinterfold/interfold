#!/usr/bin/env bash

set -e 

for arg in "$@"; do
    if [[ "$arg" == "--tmux" ]]; then
        ./scripts/dev_all_tmux.sh
        exit 0
    fi
done

./scripts/dev_all_concurrently.sh
