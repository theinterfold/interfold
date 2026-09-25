#!/usr/bin/env bash
# r127 prebuild: make the 3 recursive_aggregation fold artifacts present so the
# NEXT cargo test's build.rs sees empty missing_artifacts and never enters the
# nested-cargo branch (no outer-cargo lock cycle). Standalone (top-level), no par...[truncated]