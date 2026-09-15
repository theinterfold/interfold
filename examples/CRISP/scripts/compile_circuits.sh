#!/usr/bin/env bash

set -euo pipefail

# Script runs from examples/CRISP. Interfold circuits are at ../../circuits.
INTERFOLD_CIRCUITS="../../circuits"
CRISP_CIRCUITS="circuits"

# The generated verifiers are NOT preset-specific. They are written from the fold circuit's
# verification key, and the fold circuit takes the inner key as an input and checks its hash against
# either preset's constant, so its own structure carries no BFV degree. Compiling the supported presets
# produces byte-identical verifiers; one directory is correct.
VERIFIER_DIR="packages/crisp-contracts/contracts/verifiers"
mkdir -p "$VERIFIER_DIR"

# Two ballot stacks share the same user_data_encryption dependencies and differ only in how a
# round establishes eligibility:
#
#   crisp         + fold         -> CRISPVerifier.sol         (census Merkle tree)
#   crisp_onchain + fold_onchain -> CRISPOnchainVerifier.sol  (voting power read on chain)
#
# Each row is "crisp package dir : fold package dir : fold package name : verifier file name".
STACKS=(
    "crisp:fold:crisp_fold:CRISPVerifier.sol"
    "crisp_onchain:fold_onchain:crisp_onchain_fold:CRISPOnchainVerifier.sol"
)

echo "Compiling interfold user_data_encryption circuits (dependencies)..."

echo "Compiling user_data_encryption_ct0..."
if ! (cd "$INTERFOLD_CIRCUITS/bin/threshold/user_data_encryption_ct0" && nargo compile); then
    echo "Error: user_data_encryption_ct0 compilation failed"
    exit 1
fi

echo "Compiling user_data_encryption_ct1..."
if ! (cd "$INTERFOLD_CIRCUITS/bin/threshold/user_data_encryption_ct1" && nargo compile); then
    echo "Error: user_data_encryption_ct1 compilation failed"
    exit 1
fi

echo "Compiling user_data_encryption..."
if ! (cd "$INTERFOLD_CIRCUITS/bin/threshold/user_data_encryption" && nargo compile); then
    echo "Error: user_data_encryption compilation failed"
    exit 1
fi

# Inner recursive proofs use noir-recursive-no-zk; fold's compute_vk_hash chain reads
# `{name}.vk_recursive_hash` in each package target/ (same layout as interfold `scripts/build-circuits.ts`).
THRESHOLD_TARGET="${INTERFOLD_CIRCUITS}/bin/threshold/target"
echo "Writing noir-recursive-no-zk VKs (user_data_encryption)..."
for name in user_data_encryption_ct0 user_data_encryption_ct1 user_data_encryption; do
    if ! bb write_vk -b "${THRESHOLD_TARGET}/${name}.json" -o "${THRESHOLD_TARGET}" -t noir-recursive-no-zk; then
        echo "Error: bb write_vk (noir-recursive-no-zk) failed for ${name}"
        exit 1
    fi
    mv "${THRESHOLD_TARGET}/vk" "${THRESHOLD_TARGET}/${name}.vk_recursive"
    mv "${THRESHOLD_TARGET}/vk_hash" "${THRESHOLD_TARGET}/${name}.vk_recursive_hash"
done

# Apply project-specific checks that the generated verifier does not emit.
patch_verifier() {
    local verifier_path="$1"

    python3 - "$verifier_path" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

replacements = [
    (
        "bytes4 internal constant FRLIB_MODEXP_FAILED_SELECTOR = 0xf8d61709;",
        "bytes4 internal constant FRLIB_MODEXP_FAILED_SELECTOR = 0x1f7ec5f0;",
    ),
    (
        "    error ConsistencyCheckFailed();",
        "    error ConsistencyCheckFailed();\n    error VerificationKeyConfigurationMismatch();",
    ),
    (
        "    proofLength += NUM_ELEMENTS_COMM * 3; // Libra concat, grand sum, quotient comms + Gemini masking",
        "    proofLength += NUM_ELEMENTS_COMM * 3; // Libra concat, grand sum, quotient comms",
    ),
    (
        """    constructor(uint256 _N, uint256 _logN, uint256 _vkHash, uint256 _numPublicInputs) {
        $N = _N;
        $LOG_N = _logN;
        $VK_HASH = _vkHash;
        $NUM_PUBLIC_INPUTS = _numPublicInputs;
        $MSMSize = NUMBER_UNSHIFTED_ZK + _logN + LIBRA_COMMITMENTS + 2;
    }
""",
        """    constructor(uint256 _N, uint256 _logN, uint256 _vkHash, uint256 _numPublicInputs) {
        $N = _N;
        $LOG_N = _logN;
        $VK_HASH = _vkHash;
        $NUM_PUBLIC_INPUTS = _numPublicInputs;
        $MSMSize = NUMBER_UNSHIFTED_ZK + _logN + LIBRA_COMMITMENTS + 2;
    }

    function validateVerificationKey(Honk.VerificationKey memory vk) internal view {
        require($N == vk.circuitSize, Errors.VerificationKeyConfigurationMismatch());
        require($LOG_N == vk.logCircuitSize, Errors.VerificationKeyConfigurationMismatch());
        require($NUM_PUBLIC_INPUTS == vk.publicInputsSize, Errors.VerificationKeyConfigurationMismatch());
    }
""",
    ),
    (
        """contract HonkVerifier is BaseZKHonkVerifier(N, LOG_N, VK_HASH, NUMBER_OF_PUBLIC_INPUTS) {
     function loadVerificationKey() internal pure override returns (Honk.VerificationKey memory) {
""",
        """contract HonkVerifier is BaseZKHonkVerifier(N, LOG_N, VK_HASH, NUMBER_OF_PUBLIC_INPUTS) {
    constructor() {
        validateVerificationKey(HonkVerificationKey.loadVerificationKey());
    }

    function loadVerificationKey() internal pure override returns (Honk.VerificationKey memory) {
""",
    ),
]

for old, new in replacements:
    if text.count(old) != 1:
        raise SystemExit(f"expected one generated verifier match, found {text.count(old)}: {old[:80]}")
    text = text.replace(old, new)

path.write_text(text)
PY
}

for stack in "${STACKS[@]}"; do
    IFS=":" read -r crisp_dir fold_dir fold_pkg verifier_file <<<"$stack"
    crisp_target="${CRISP_CIRCUITS}/bin/${crisp_dir}/target"

    echo "Compiling ${crisp_dir} circuit..."
    if ! (cd "$CRISP_CIRCUITS/bin/${crisp_dir}" && nargo compile); then
        echo "Error: ${crisp_dir} circuit compilation failed"
        exit 1
    fi

    echo "Writing noir-recursive-no-zk VK for ${crisp_dir}..."
    if ! bb write_vk -b "${crisp_target}/${crisp_dir}.json" -o "${crisp_target}" -t noir-recursive-no-zk; then
        echo "Error: bb write_vk (noir-recursive-no-zk) failed for ${crisp_dir}"
        exit 1
    fi
    mv "${crisp_target}/vk" "${crisp_target}/${crisp_dir}.vk_recursive"
    mv "${crisp_target}/vk_hash" "${crisp_target}/${crisp_dir}.vk_recursive_hash"

    echo "Compiling ${fold_dir} circuit (verifies user_data_encryption + ${crisp_dir})..."
    if ! (cd "$CRISP_CIRCUITS/bin/${fold_dir}" && nargo compile); then
        echo "Error: ${fold_dir} circuit compilation failed"
        exit 1
    fi

    # Generate verifier from fold circuit (on-chain proof verifies the folded proof)
    echo "Generating ${fold_dir} Verifier Key..."
    if ! bb write_vk -b "$CRISP_CIRCUITS/bin/${fold_dir}/target/${fold_pkg}.json" -o "$CRISP_CIRCUITS/bin/${fold_dir}/target" --oracle_hash keccak; then
        echo "Error: Failed to generate ${fold_dir} Verifier Key"
        exit 1
    fi

    echo "Generating Solidity Verifier ${verifier_file}..."
    if ! bb write_solidity_verifier -k "$CRISP_CIRCUITS/bin/${fold_dir}/target/vk" -o "$CRISP_CIRCUITS/bin/${fold_dir}/target/${verifier_file}"; then
        echo "Error: Failed to generate Solidity Verifier ${verifier_file}"
        exit 1
    fi

    echo "Copying ${verifier_file} to contracts folder..."
    if ! cp "$CRISP_CIRCUITS/bin/${fold_dir}/target/${verifier_file}" "${VERIFIER_DIR}/${verifier_file}"; then
        echo "Error: Failed to copy ${verifier_file} to contracts folder"
        exit 1
    fi

    # Add the correct license header
    echo "Adding license header to ${verifier_file}..."
    LICENSE_HEADER="// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE."
    # Remove the first 2 lines (Apache license and copyright) and prepend our license header
    TEMP_FILE=$(mktemp)
    {
        echo "$LICENSE_HEADER"
        tail -n +3 "${VERIFIER_DIR}/${verifier_file}"
    } >"$TEMP_FILE"
    mv "$TEMP_FILE" "${VERIFIER_DIR}/${verifier_file}"

    patch_verifier "${VERIFIER_DIR}/${verifier_file}"

    echo "Formatting ${verifier_file} with Prettier..."
    if pnpm exec prettier --write "${VERIFIER_DIR}/${verifier_file}" 2>/dev/null; then
        echo "Prettier formatting complete"
    else
        echo "Warning: Prettier formatting skipped (run pnpm install from repo root if needed)"
    fi
done

echo "Noir setup completed successfully"
