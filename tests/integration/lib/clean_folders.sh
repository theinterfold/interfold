#!/usr/bin/env bash
clean_folders() {
    local SCRIPT_DIR=$1

    # Delete output artifacts
    rm -rf "$SCRIPT_DIR/output/"*
    rm -rf "$SCRIPT_DIR/.interfold/"
}

clean_folders $1
