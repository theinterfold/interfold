// SPDX-License-Identifier: LGPL-3.0-only

use alloy_sol_types::sol;

sol! {
    /// Input/proof errors forwarded by `publishPlaintextOutput` from the synchronized wrapper.
    #[sol(abi)]
    interface SynchronizedDecryptionVerifier {
        error InvalidProof();
        error InvalidPublicInputsLength();
        error NonCanonicalPublicInput(uint256 index);
        error MessageCoefficientOutOfRange(uint256 index);
        error VkHashMismatch();
        error PlaintextHashMismatch();
        error DomainBindingMismatch();
        error CiphertextCommitmentMismatch();
        error DkgAnchorMismatch();
    }

    /// Proof-data failures from the generated decryption Honk verifier's `Errors` library.
    #[sol(abi)]
    interface DecryptionHonk {
        error ValueGeLimbMax();
        error ValueGeGroupOrder();
        error ValueGeFieldOrder();
        error InvertOfZero();
        error ProofLengthWrong();
        error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength);
        error PublicInputsLengthWrong();
        error SumcheckFailed();
        error ShpleminiFailed();
        error PointAtInfinity();
        error ConsistencyCheckFailed();
        error GeminiChallengeInSubgroup();
    }
}
