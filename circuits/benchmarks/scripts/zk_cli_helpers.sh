#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is provided WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.

# Shared circuit-path -> zk_cli argument mapping.
#
# Consumed by `generate_prover_toml.sh` (single circuit) and
# `scripts/generate-circuit-configs.sh` (batch over all presets/committees) so the
# mapping never drifts between the two.
#
# Sourced, not executed directly. Define `CIRCUIT_PATH` (e.g. "dkg/pk") before
# calling `get_zk_args()`, which prints `"<zk_cli_circuit> [zk_cli_inputs]"` — or
# `"_no_zk_cli"` for circuits without witness inputs (the `config` sanity circuit).

get_zk_args() {
    local path="$1"
    case "$path" in
        config)
            echo "_no_zk_cli"
            return
            ;;
        dkg/pk)
            echo "pk"
            return
            ;;
        dkg/sk_share_computation)
            echo "share-computation secret-key"
            return
            ;;
        dkg/e_sm_share_computation)
            echo "share-computation smudging-noise"
            return
            ;;
        dkg/share_encryption)
            echo "share-encryption secret-key"
            return
            ;;
        dkg/share_decryption)
            echo "share-decryption secret-key"
            return
            ;;
        threshold/user_data_encryption_ct0)
            echo "user-data-encryption"
            return
            ;;
        threshold/user_data_encryption_ct1)
            echo "user-data-encryption"
            return
            ;;
        threshold/pk_generation)
            echo "pk-generation"
            return
            ;;
        threshold/pk_aggregation)
            echo "pk-aggregation"
            return
            ;;
        threshold/share_decryption)
            echo "threshold-share-decryption"
            return
            ;;
        threshold/decrypted_shares_aggregation)
            echo "decrypted-shares-aggregation"
            return
            ;;
        *)
            echo "Error: unknown circuit path: $path" >&2
            return 1
            ;;
    esac
}