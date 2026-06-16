#!/usr/bin/env bash

RUSTFLAGS="-A warnings" cargo run --quiet --bin interfold -- -v "$@"
