// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IPkVerifier } from "../../interfaces/IPkVerifier.sol";
import { ICircuitVerifier } from "../../interfaces/ICircuitVerifier.sol";
import { IInterfold } from "../../interfaces/IInterfold.sol";
import { E3 } from "../../interfaces/IE3.sol";

/**
 * @title CkksPkVerifier
 * @notice Verifies the committee public key of a CKKS E3 on-chain by Honk-verifying
 *         one C1-CKKS (`pk_generation_ckks_ps<N>`) proof per committee member.
 * @dev Registered against `encryptionSchemeId = keccak256("fhe.rs:CKKS")`. The CKKS
 *      pipeline has NO recursive aggregation circuit (deliberately: no C5-CKKS /
 *      DkgAggregator-CKKS exists), so this wrapper verifies the per-party leaf
 *      proofs directly instead of a single folded proof.
 *
 *      PROOF BLOB ENCODING
 *      `proof` decodes as:
 *          abi.encode(
 *              bytes[]     partyProofs,        // one raw Honk proof per committee member
 *              bytes32[][] partyPublicInputs,  // matching public inputs, 11 words each
 *              bytes       aggregatePublicKey  // the committee pk bytes the aggregator published
 *          )
 *      `partyProofs[i]` / `partyPublicInputs[i]` are in ASCENDING party order, matching
 *      `sortedNodes[i]`.
 *
 *      C1-CKKS PUBLIC-INPUT LAYOUT (3 words; `pk_generation_ckks_ps<N>/src/main.nr`
 *      returns `(Field, Field, Field)`):
 *          [0] = sk_commitment      (compute_share_computation_sk_commitment)
 *          [1] = pk_commitment      (compute_ckks_threshold_pk_commitment(pk0 || a))
 *          [2] = e_sm_commitment    (compute_share_computation_e_sm_commitment)
 *      The circuit's `NUMBER_OF_PUBLIC_INPUTS` is 11, but the trailing 8 are the
 *      pairing-point object, which `BaseZKHonkVerifier.verify` reads from the proof
 *      rather than the `publicInputs` array.
 *
 *      WHAT THIS CONTRACT BINDS
 *        1. Every committee member supplied a C1-CKKS proof: `partyProofs.length ==
 *           sortedNodes.length`. CKKS threshold decryption sums over ALL N dealers,
 *           so an unproven share can never be silently dropped (matching the
 *           aggregator's all-or-nothing rogue-key gate in `verify_key_proofs.rs`).
 *        2. Each party proof Honk-verifies against the param-set-specific circuit
 *           verifier. Each therefore attests: the prover knows `sk_i`, `e_i`, `e_sm_i`
 *           with `pk0_i = -a*sk_i + e_i` over every CKKS limb, with `pk0_i || a` bound
 *           into `pk_commitment` and the range checks on all witnesses satisfied.
 *           This is the rogue-key defence: a party cannot publish an adversarially
 *           chosen `pk0_i` without knowing a corresponding small `sk_i`.
 *        3. Per-party `pk_commitment` AND `sk_commitment` values are pairwise
 *           distinct. Two parties replaying one share (or one party submitting
 *           the same proof twice to reach the committee count) is rejected.
 *        4. `keccak256(aggregatePublicKey) == pkCommitment`, i.e. the commitment the
 *           registry stores for this E3 is the hash of concrete published key bytes
 *           and not an unconstrained 32-byte value. This mirrors the aggregator's
 *           `pk_commitment = keccak256(pubkey)` in `public_key_aggregation/effects/ckks.rs`.
 *
 *      WHAT THIS CONTRACT DOES *NOT* BIND (read this before trusting it)
 *        A. `aggregatePublicKey` is NOT proven to be the sum of the per-party `pk0_i`
 *           the proofs commit to. The circuit's `pk_commitment` is a SAFE/Poseidon
 *           commitment over `N*L` packed limb coefficients (`compute_ckks_threshold_pk_commitment`,
 *           circuits/lib/src/math/commitments.nr:182); the on-chain commitment is a
 *           keccak256 over serialised key bytes. Neither is recomputable from the
 *           other in the EVM, and summing CKKS polynomials on-chain is not tractable.
 *           An aggregator that verifies N honest shares and then publishes a DIFFERENT
 *           aggregate key still passes this verifier. That link is enforced OFF-chain
 *           by `check_c1_ckks_keyshare_commitments` (crates/aggregator/.../validation.rs:152),
 *           which recomputes each party's `pk_commitment` from the received share bytes
 *           and rejects a mismatch. Closing it on-chain needs a C5-CKKS aggregation
 *           circuit that exposes the keccak256 of the serialised aggregate as a public
 *           input; that circuit does not exist and is explicitly out of the current scope.
 *        B. `e3Id`, `committeeRoot` and `committeeHash` are NOT bound into the proofs.
 *           The C1-CKKS circuit exposes no domain-binding public input, so a valid
 *           per-party proof from one E3 is replayable into another E3 that reuses the
 *           same CRP `a`. Interfold derives `a` from the E3 seed (`CkksCrp::from_seed`),
 *           so distinct E3s have distinct `a` and distinct `pk_commitment`s in practice,
 *           but this contract cannot check that. Identical to the documented relaxation
 *           on `BfvPkVerifier`.
 *        C. Committee membership: the proofs are counted against `sortedNodes.length`
 *           but no public input carries a node address, so proof `i` is not bound to
 *           `sortedNodes[i]`.
 *
 *      GAS
 *      MEASURED (test/CkksOnchainVerifiers.spec.ts, ParamSet 2, n=3): 9,128,457 gas.
 *      One C1-CKKS Honk verification is therefore ~3.0M gas, not the ~400k a small
 *      circuit costs — `pk_generation_ckks` proves the pk relation over every CKKS
 *      limb, so LOG_N and the Shplemini opening set are large.
 *      Budget `n * ~3.0M + ~50k`. n=3 is ~9.1M and fits a 30M block; n=5 is ~15M;
 *      n=9 is ~27M and is effectively the ceiling. A committee larger than that
 *      CANNOT be verified this way and needs the C5-CKKS aggregation circuit
 *      described in note (A), which folds the N leaves into one proof.
 *
 *      PARAM-SET DISPATCH
 *      `Interfold` keys verifiers by encryption scheme alone, but the three CKKS
 *      demo apps run on different param sets (auction ps2, salary-survey ps3,
 *      credit-scoring ps4) whose circuits have different verification keys. This
 *      contract therefore holds a `paramSet => ICircuitVerifier` table and resolves
 *      the right one from `interfold.getE3(e3Id).paramSet` on every call, so ONE
 *      deployment registered once under the CKKS scheme id serves all of them.
 */
contract CkksPkVerifier is IPkVerifier {
    error InvalidCircuitVerifier(address verifier);
    error PartyProofCountMismatch(uint256 supplied, uint256 committeeSize);
    error PublicInputArrayLengthMismatch();
    error DuplicatePartyCommitment(uint256 index);
    error NonCanonicalPublicInput(uint256 party, uint256 index);
    error PartyProofInvalid(uint256 party);
    error UnsupportedParamSet(uint8 paramSet);
    error InvalidInterfold(address interfold);

    uint256 internal constant BN254_SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev C1-CKKS returns `(sk_commitment, pk_commitment, e_sm_commitment)`.
    ///      The 8 Barretenberg pairing-point words are carried INSIDE the proof and
    ///      are not part of the `publicInputs` array the Honk verifier accepts
    ///      (`BaseZKHonkVerifier.verify` requires
    ///      `publicInputs.length == vk.publicInputsSize - PAIRING_POINTS_SIZE`),
    ///      so this is 3, not 11.
    uint256 internal constant C1_PUBLIC_INPUTS_LEN = 3;

    /// @dev Public-input index of `compute_share_computation_sk_commitment(sk)`.
    uint256 internal constant SK_COMMITMENT_IDX = 0;

    /// @dev Public-input index of `compute_ckks_threshold_pk_commitment(pk0 || a)`.
    uint256 internal constant PK_COMMITMENT_IDX = 1;

    /// @notice Required honest-party count. CKKS aggregates over every dealer, so the
    ///         committee is all-or-nothing and `h` equals the full committee size `N`.
    uint256 public immutable override h;

    /// @notice Interfold deployment consulted for the E3's `paramSet`.
    IInterfold public immutable interfold;

    /// @notice Per-param-set Honk verifiers for `pk_generation_ckks_ps<N>`.
    ///         Indexed by the E3's on-chain `paramSet`; `address(0)` means the
    ///         param set is not supported and `verify` reverts.
    ///         ONE deployment of this contract serves every CKKS param set, so a
    ///         single `setPkVerifier(ckksSchemeId, ...)` registration covers the
    ///         auction (ps2), salary-survey (ps3) and credit-scoring (ps4) apps.
    mapping(uint8 paramSet => ICircuitVerifier) public circuitVerifiers;

    /// @param _interfold        Interfold deployment used to resolve `e3.paramSet`.
    /// @param _paramSets        CKKS param-set indices (e.g. `[0, 2, 3, 4]`).
    /// @param _circuitVerifiers Matching `PkGenerationCkksPs<N>Verifier` addresses.
    /// @param _h                Committee size `N` every CKKS E3 must supply proofs for.
    constructor(
        address _interfold,
        uint8[] memory _paramSets,
        address[] memory _circuitVerifiers,
        uint256 _h
    ) {
        require(_h > 0, "CkksPkVerifier: h=0");
        require(
            _paramSets.length == _circuitVerifiers.length,
            "CkksPkVerifier: length mismatch"
        );
        require(_paramSets.length > 0, "CkksPkVerifier: no param sets");
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
        h = _h;
    }

    /// @inheritdoc IPkVerifier
    /// @dev `committeeRoot` and `committeeHash` are accepted for interface parity and
    ///      are unused — see note (B) in the contract docs.
    function verify(
        uint256 e3Id,
        uint256 committeeRoot,
        address[] calldata sortedNodes,
        bytes32 pkCommitment,
        bytes32 committeeHash,
        bytes calldata proof
    ) external view override returns (bool) {
        // Resolve the circuit for THIS E3's param set: the CKKS scheme id is one
        // mapping key but the demo apps run on ps2/ps3/ps4 with different VKs.
        E3 memory e3 = interfold.getE3(e3Id);
        ICircuitVerifier circuitVerifier = circuitVerifiers[e3.paramSet];
        if (address(circuitVerifier) == address(0)) {
            revert UnsupportedParamSet(e3.paramSet);
        }

        (
            bytes[] memory partyProofs,
            bytes32[][] memory partyPublicInputs,
            bytes memory aggregatePublicKey
        ) = abi.decode(proof, (bytes[], bytes32[][], bytes));

        if (partyProofs.length != sortedNodes.length) {
            revert PartyProofCountMismatch(
                partyProofs.length,
                sortedNodes.length
            );
        }
        if (partyPublicInputs.length != partyProofs.length) {
            revert PublicInputArrayLengthMismatch();
        }

        // (4) The registry's stored commitment must be the hash of concrete key bytes.
        if (keccak256(aggregatePublicKey) != pkCommitment) {
            revert PkCommitmentMismatch();
        }

        for (uint256 i = 0; i < partyProofs.length; ++i) {
            bytes32[] memory publicInputs = partyPublicInputs[i];
            if (publicInputs.length != C1_PUBLIC_INPUTS_LEN) {
                revert InvalidPublicInputsLength();
            }

            for (uint256 j = 0; j < C1_PUBLIC_INPUTS_LEN; ++j) {
                if (uint256(publicInputs[j]) >= BN254_SCALAR_MODULUS) {
                    revert NonCanonicalPublicInput(i, j);
                }
            }

            // (3) Reject a replayed share: both the pk-share and the sk commitment
            //     must be fresh across the committee.
            for (uint256 k = 0; k < i; ++k) {
                bytes32[] memory prior = partyPublicInputs[k];
                if (
                    prior[PK_COMMITMENT_IDX] ==
                    publicInputs[PK_COMMITMENT_IDX] ||
                    prior[SK_COMMITMENT_IDX] == publicInputs[SK_COMMITMENT_IDX]
                ) {
                    revert DuplicatePartyCommitment(i);
                }
            }

            // (2) Every party proof must Honk-verify against this param set's circuit.
            if (!circuitVerifier.verify(partyProofs[i], publicInputs)) {
                revert PartyProofInvalid(i);
            }
        }

        // Unused; retained for interface compatibility (see note (B)).
        committeeRoot;
        committeeHash;

        return true;
    }
}
