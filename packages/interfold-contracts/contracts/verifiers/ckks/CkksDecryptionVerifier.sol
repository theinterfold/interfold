// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IDecryptionVerifier } from "../../interfaces/IDecryptionVerifier.sol";
import { ICircuitVerifier } from "../../interfaces/ICircuitVerifier.sol";
import { IInterfold } from "../../interfaces/IInterfold.sol";
import { E3 } from "../../interfaces/IE3.sol";
import { CommitteeHashLib } from "../../lib/CommitteeHashLib.sol";

/**
 * @title CkksDecryptionVerifier
 * @notice Verifies the decrypted output of a CKKS E3 on-chain by Honk-verifying one
 *         C7-CKKS (`decrypted_shares_aggregation_ckks_ps<N>`) proof.
 * @dev Registered against `encryptionSchemeId = keccak256("fhe.rs:CKKS")`. C7-CKKS is
 *      NOT recursive — it aggregates the `T+1` decryption shares in-circuit — so this
 *      wrapper verifies that single proof directly rather than a folded one.
 *
 *      PROOF BLOB ENCODING
 *      `proof` decodes as `abi.encode(bytes rawProof, bytes32[] publicInputs)`, the
 *      same shape `e3_evm::helpers::encode_zk_proof` already produces for BFV.
 *
 *      C7-CKKS PUBLIC-INPUT LAYOUT (518 words for the `minimum` committee T=1;
 *      `decrypted_shares_aggregation_ckks_ps<N>/src/main.nr`):
 *          [0 .. T+1)                 = expected_d_commitments  (T+1 words)
 *          [T+1 .. 2T+2)              = party_ids               (T+1 words)
 *          [2T+2]                     = domain_hi  (E3 decryption domain, high 128 bits)
 *          [2T+3]                     = domain_lo  (E3 decryption domain, low 128 bits)
 *          [2T+4 .. 2T+4+N)           = u_global   (N = 512 coefficient words: the FULL
 *                                       ring, the same window C6-CKKS hashes)
 *      With T=1 that is 2 + 2 + 2 + 512 = 518. The circuit's `NUMBER_OF_PUBLIC_INPUTS`
 *      is 526; the extra 8 are the pairing-point object, which
 *      `BaseZKHonkVerifier.verify` reads from the proof, not this array.
 *
 *      WHAT THIS CONTRACT BINDS
 *        1. The C7-CKKS proof Honk-verifies against the param-set-specific circuit
 *           verifier. That proof attests, for the committed `u_global`:
 *             - each of the `T+1` decryption shares hashes to its declared
 *               `expected_d_commitments[i]` (the C6-CKKS link);
 *             - Lagrange interpolation of those shares at the declared `party_ids`
 *               reconstructs `u^(l)` per CRT basis;
 *             - the CRT glue `u^(l) + r^(l)*q_l == u_global` holds on every limb,
 *               with `u_global < Q` and each quotient `r^(l) < Q/q_l` RANGE-CONSTRAINED
 *               in-circuit (`verify_crt_reconstruction_ckks`), so the field identity
 *               implies the integer identity and `u_global` is the UNIQUE canonical
 *               reconstruction — not a free witness (the shared BFV glue leaves the
 *               quotients unconstrained; see docs/BFV_C7_CRT_SOUNDNESS_FINDING.md).
 *           In short: `u_global` really is the threshold reconstruction of `T+1`
 *           committed decryption shares. This is the substantive claim and it is
 *           now checked on-chain.
 *        1b. `decryptionDomain` IS bound: `domain_hi/lo` must equal the hi/lo split of
 *           `keccak256(abi.encode(chainid, interfold, e3Id, committeeHash,
 *           ciphertextHash, committeePublicKey))` that Interfold derives for this E3
 *           — one proof, one E3, one committee, one ciphertext. No replay.
 *        2. `party_ids` are strictly increasing and non-zero — distinct Shamir
 *           x-coordinates, so one party's share cannot be counted twice to reach
 *           the reconstruction threshold.
 *        3. `expected_d_commitments` are pairwise distinct.
 *        4. Every public input is a canonical BN254 scalar.
 *
 *      WHAT THIS CONTRACT DOES *NOT* BIND (read this before trusting it)
 *        A. `plaintextOutputHash` is NOT bound to `u_global`. The published plaintext
 *           is `encode_fixed_point_output` bytes (i128 big-endian, 16 bytes per slot
 *           value — crates/trckks/src/program.rs:330), whereas `u_global` is the raw
 *           CKKS ring element `delta*m + e` with coefficients mod Q. Recovering the
 *           published values from `u_global` requires centering mod Q, dividing by the
 *           scale `delta`, and — for the slot-encoded param sets (0/2/3) — an inverse
 *           FFT over the cyclotomic ring. None of that is tractable in the EVM, and
 *           CKKS decode is deliberately an off-circuit real-number operation (see the
 *           module docs on `decrypted_shares_aggregation_ckks.nr`).
 *           CONSEQUENCE: a malicious aggregator can prove a correct reconstruction of
 *           `u_global` and still publish plaintext bytes that do not correspond to it.
 *           The decode step is trusted. Closing this needs a circuit that exposes
 *           `keccak256(encode_fixed_point_output(decode(u_global)))` as a public input.
 *           It does not exist and is out of the current scope.
 *        B. (CLOSED — see 1b.) The domain words bind e3Id, committee, ciphertext hash
 *           and key commitment; a C7-CKKS proof is no longer replayable across E3s.
 *        C. `ciphertextCommitment` is bound only THROUGH the domain (its keccak is one
 *           of the six domain inputs). C7-CKKS itself never sees the ciphertext; the
 *           relation "these shares decrypt THIS ciphertext" is proven by C6-CKKS
 *           (`ct_commitment` public input), which the aggregator verifies off-chain
 *           before aggregating and which this wrapper does not re-verify (no C6 fold
 *           exists for CKKS).
 *        D. `expected_d_commitments` are NOT checked against any registry anchor.
 *           `ICiphernodeRegistry.getDkgAnchors` stores sk/esm commitments from the
 *           DKG, not per-round `d` commitments, so there is nothing on-chain to
 *           compare them to.
 *
 *      GAS
 *      MEASURED (test/CkksOnchainVerifiers.spec.ts, ParamSet 2, T=1): 2,865,226 gas.
 *      Independent of committee size — C7-CKKS aggregates the shares in-circuit, so
 *      exactly one Honk verification runs however large the committee is.
 */
contract CkksDecryptionVerifier is IDecryptionVerifier {
    error InvalidCircuitVerifier(address verifier);
    error NonCanonicalPublicInput(uint256 index);
    error PartyIdsNotStrictlyIncreasing(uint256 index);
    error ZeroPartyId(uint256 index);
    error DuplicateShareCommitment(uint256 index);
    error UnsupportedParamSet(uint8 paramSet);
    error InvalidInterfold(address interfold);

    uint256 internal constant BN254_SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Length of the public `u_global` polynomial = the CKKS ring degree N.
    ///      C7-CKKS binds ALL N coefficients (CKKS has no sparse-message window;
    ///      `DECRYPTED_SHARES_AGGREGATION_CKKS_N`), the same width C6-CKKS hashes
    ///      into `d_commitment` — that equality is what makes the C6 -> C7 link hold.
    ///      Every registered CKKS param set uses N = 512.
    uint256 internal constant U_GLOBAL_COEFFS = 512;

    /// @notice Reconstruction threshold `T` compiled into the C7-CKKS circuit.
    uint256 public immutable override threshold;

    /// @dev `2*(T+1) + U_GLOBAL_COEFFS`. The circuit's `NUMBER_OF_PUBLIC_INPUTS`
    ///      is 524 (T=1), but the trailing 8 pairing-point words travel inside the
    ///      proof: `BaseZKHonkVerifier.verify` requires
    ///      `publicInputs.length == vk.publicInputsSize - PAIRING_POINTS_SIZE`.
    uint256 internal immutable expectedPublicInputsLen;

    /// @dev Start index of the `party_ids[T+1]` column.
    uint256 internal immutable partyIdColOffset;

    /// @dev Indices of the two E3-decryption-domain words (`domain_hi`,
    ///      `domain_lo`) that follow the `party_ids` column. Same hash and
    ///      hi/lo split as BFV (`InterfoldLifecycle.verifyPlaintext`,
    ///      `CommitteeHashLib`) and as C6-CKKS on the node side.
    uint256 internal immutable domainHiIdx;
    uint256 internal immutable domainLoIdx;

    /// @notice Interfold deployment consulted for the E3's `paramSet`.
    IInterfold public immutable interfold;

    /// @notice Per-param-set Honk verifiers for
    ///         `decrypted_shares_aggregation_ckks[_ps<N>]`, indexed by the E3's
    ///         on-chain `paramSet`. ONE deployment serves every CKKS param set.
    mapping(uint8 paramSet => ICircuitVerifier) public circuitVerifiers;

    /// @param _interfold        Interfold deployment used to resolve `e3.paramSet`.
    /// @param _paramSets        CKKS param-set indices (e.g. `[0, 2, 3, 4]`).
    /// @param _circuitVerifiers Matching `DecryptedSharesAggregationCkks*Verifier` addresses.
    /// @param _threshold        Reconstruction threshold `T` of the compiled circuits.
    constructor(
        address _interfold,
        uint8[] memory _paramSets,
        address[] memory _circuitVerifiers,
        uint256 _threshold
    ) {
        require(_threshold > 0, "CkksDecryptionVerifier: threshold=0");
        require(
            _paramSets.length == _circuitVerifiers.length,
            "CkksDecryptionVerifier: length mismatch"
        );
        require(
            _paramSets.length > 0,
            "CkksDecryptionVerifier: no param sets"
        );
        if (_interfold.code.length == 0) revert InvalidInterfold(_interfold);
        for (uint256 i = 0; i < _paramSets.length; ++i) {
            if (_circuitVerifiers[i].code.length == 0) {
                revert InvalidCircuitVerifier(_circuitVerifiers[i]);
            }
            circuitVerifiers[_paramSets[i]] = ICircuitVerifier(
                _circuitVerifiers[i]
            );
        }
        interfold = IInterfold(_interfold);
        threshold = _threshold;
        partyIdColOffset = _threshold + 1;
        // Layout: [d_commitments T+1][party_ids T+1][domain_hi][domain_lo][u_global N]
        expectedPublicInputsLen = (2 * (_threshold + 1)) + 2 + U_GLOBAL_COEFFS;
        domainHiIdx = 2 * (_threshold + 1);
        domainLoIdx = domainHiIdx + 1;
    }

    /// @inheritdoc IDecryptionVerifier
    /// @dev `decryptionDomain` IS bound: the proof's `domain_hi`/`domain_lo`
    ///      words must equal the hi/lo split of the domain Interfold derives
    ///      on-chain (`keccak256(abi.encode(chainid, interfold, e3Id,
    ///      committeeHash, ciphertextHash, committeePublicKey))`) — the same
    ///      hash C6-CKKS binds on the node, so one proof serves exactly one
    ///      E3 / committee / ciphertext and cannot be replayed.
    ///      `plaintextOutputHash`, `committeeHash` and `ciphertextCommitment`
    ///      are already folded into `decryptionDomain` by the caller; the
    ///      plaintext bytes themselves remain unbound to `u_global` (note A).
    function verify(
        uint256 e3Id,
        bytes32 decryptionDomain,
        bytes32 plaintextOutputHash,
        bytes32 committeeHash,
        bytes32 ciphertextCommitment,
        bytes calldata proof
    ) external view override returns (bool) {
        E3 memory e3 = interfold.getE3(e3Id);
        ICircuitVerifier circuitVerifier = circuitVerifiers[e3.paramSet];
        if (address(circuitVerifier) == address(0)) {
            revert UnsupportedParamSet(e3.paramSet);
        }

        (bytes memory rawProof, bytes32[] memory publicInputs) = abi.decode(
            proof,
            (bytes, bytes32[])
        );

        if (publicInputs.length != expectedPublicInputsLen) {
            revert InvalidPublicInputsLength();
        }

        // (4) Canonical field elements only.
        for (uint256 i = 0; i < publicInputs.length; ++i) {
            if (uint256(publicInputs[i]) >= BN254_SCALAR_MODULUS) {
                revert NonCanonicalPublicInput(i);
            }
        }

        // (3) Distinct C6 share commitments.
        for (uint256 i = 0; i < threshold + 1; ++i) {
            for (uint256 j = 0; j < i; ++j) {
                if (publicInputs[i] == publicInputs[j]) {
                    revert DuplicateShareCommitment(i);
                }
            }
        }

        // (2) Strictly increasing, non-zero Shamir x-coordinates.
        uint256 previous = 0;
        for (uint256 i = 0; i < threshold + 1; ++i) {
            uint256 partyId = uint256(publicInputs[partyIdColOffset + i]);
            if (partyId == 0) revert ZeroPartyId(i);
            if (partyId <= previous) revert PartyIdsNotStrictlyIncreasing(i);
            previous = partyId;
        }

        // (0) Domain binding: this proof was produced for THIS E3's
        //     (chain, deployment, e3Id, committee, ciphertext, key) tuple.
        if (publicInputs[domainHiIdx] != CommitteeHashLib.hi(decryptionDomain)) {
            revert DomainBindingMismatch();
        }
        if (publicInputs[domainLoIdx] != CommitteeHashLib.lo(decryptionDomain)) {
            revert DomainBindingMismatch();
        }

        // (1) The substantive check: shares really do reconstruct `u_global`
        //     (the circuit range-constrains the CRT lift, so `u_global` is the
        //     unique canonical reconstruction, not a free witness).
        if (!circuitVerifier.verify(rawProof, publicInputs)) {
            revert InvalidProof();
        }

        // Folded into `decryptionDomain` by the caller; the plaintext bytes
        // are not bound to `u_global` (note A).
        plaintextOutputHash;
        committeeHash;
        ciphertextCommitment;

        return true;
    }
}
