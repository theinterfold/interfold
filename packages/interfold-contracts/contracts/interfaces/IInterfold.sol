// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { E3, IE3Program } from "./IE3.sol";
import { ICiphernodeRegistry } from "./ICiphernodeRegistry.sol";
import { IBondingRegistry } from "./IBondingRegistry.sol";
import { IDecryptionVerifier } from "./IDecryptionVerifier.sol";
import { IPkVerifier } from "./IPkVerifier.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IInterfold {
    ////////////////////////////////////////////////////////////
    //                                                        //
    //                         Enums                          //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Sizes of committees for E3 computations
    enum CommitteeSize {
        Minimum,
        Micro,
        Small
    }

    /// @notice BFV encryption parameter sets.
    /// @dev Each variant maps to a threshold BFV preset. The DKG counterpart is
    /// derived automatically via `BfvPreset::dkg_counterpart()` on the node side.

    /// @notice Lifecycle stages of an E3 computation
    enum E3Stage {
        None,
        Requested,
        CommitteeFinalized,
        KeyPublished,
        CiphertextReady,
        Complete,
        Failed
    }

    /// @notice Reasons why an E3 failed
    /// @dev Any new failure reason should be added before _MAX_FAILURE_REASON.
    enum FailureReason {
        None,
        CommitteeFormationTimeout,
        InsufficientCommitteeMembers,
        DKGTimeout,
        DKGInvalidShares,
        NoInputsReceived,
        ComputeTimeout,
        ComputeProviderExpired,
        ComputeProviderFailed,
        RequesterCancelled,
        DecryptionTimeout,
        DecryptionInvalidShares,
        VerificationFailed,
        _MAX_FAILURE_REASON
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                        Structs                         //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Timeout configuration for E3 stages
    struct E3TimeoutConfig {
        uint256 dkgWindow;
        uint256 computeWindow;
        uint256 decryptionWindow;
    }

    /// @notice Deadlines for each E3
    struct E3Deadlines {
        uint256 dkgDeadline;
        uint256 computeDeadline;
        uint256 decryptionDeadline;
    }

    /// @notice All pricing-related configuration for parametric E3 fee calculation
    struct PricingConfig {
        uint256 keyGenFixedPerNode;
        uint256 keyGenPerEncryptionProof;
        uint256 coordinationPerPair;
        uint256 availabilityPerNodePerSec;
        uint256 decryptionPerNode;
        uint256 publicationBase;
        uint256 verificationPerProof;
        address protocolTreasury;
        uint16 marginBps;
        uint16 protocolShareBps;
        uint16 dkgUtilizationBps;
        uint16 computeUtilizationBps;
        uint16 decryptUtilizationBps;
        uint32 minCommitteeSize;
        uint32 minThreshold;
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                         Events                         //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice This event MUST be emitted when an Encrypted Execution Environment (E3) is successfully requested.
    /// @param e3Id ID of the E3.
    /// @param e3 Details of the E3.
    /// @param e3Program Address of the Computation module selected.
    event E3Requested(uint256 e3Id, E3 e3, IE3Program indexed e3Program);

    /// @notice This event MUST be emitted when an input to an Encrypted Execution Environment (E3) is
    /// successfully published.
    /// @param e3Id ID of the E3.
    /// @param data ABI encoded input data.
    event InputPublished(
        uint256 indexed e3Id,
        bytes data,
        uint256 inputHash,
        uint256 index
    );

    /// @notice This event MUST be emitted when the plaintext output of an Encrypted Execution Environment (E3)
    /// is successfully published.
    /// @param e3Id ID of the E3.
    /// @param plaintextOutput ABI encoded plaintext output.
    /// @param proof ABI encoded verification proof (C7) for the plaintext output.
    event PlaintextOutputPublished(
        uint256 indexed e3Id,
        bytes plaintextOutput,
        bytes proof
    );

    /// @notice This event MUST be emitted when the ciphertext output of an Encrypted Execution Environment (E3)
    /// is successfully published.
    /// @param e3Id ID of the E3.
    /// @param ciphertextOutput ABI encoded ciphertext output.
    event CiphertextOutputPublished(
        uint256 indexed e3Id,
        bytes ciphertextOutput
    );

    /// @notice This event MUST be emitted any time the `maxDuration` is set.
    /// @param maxDuration The maximum duration of a computation in seconds.
    event MaxDurationSet(uint256 maxDuration);

    /// @notice This event MUST be emitted any time the CiphernodeRegistry is set.
    /// @param ciphernodeRegistry The address of the CiphernodeRegistry contract.
    event CiphernodeRegistrySet(address ciphernodeRegistry);

    /// @notice This event MUST be emitted any time the BondingRegistry is set.
    /// @param bondingRegistry The address of the BondingRegistry contract.
    event BondingRegistrySet(address bondingRegistry);

    /// @notice This event MUST be emitted any time the fee token is set.
    /// @param feeToken The address of the fee token.
    event FeeTokenSet(address feeToken);

    /// @notice This event MUST be emitted when rewards are credited to committee members.
    /// @dev Distribution is pull-based — recipients must call `claimReward(e3Id)`.
    /// @param e3Id The ID of the E3 computation.
    /// @param nodes The addresses of the committee members receiving rewards.
    /// @param amounts The reward amounts for each committee member.
    event RewardsDistributed(
        uint256 indexed e3Id,
        address[] nodes,
        uint256[] amounts
    );

    /// @notice Emitted when a reward is credited to a committee member's pull-payment balance.
    /// @param e3Id The ID of the E3 computation.
    /// @param account The committee-member address being credited.
    /// @param token The ERC20 fee token used for this E3.
    /// @param amount The amount credited.
    event RewardCredited(
        uint256 indexed e3Id,
        address indexed account,
        IERC20 indexed token,
        uint256 amount
    );

    /// @notice Emitted when a recipient claims their accrued E3 reward.
    /// @param e3Id The ID of the E3 computation.
    /// @param account The claimant address.
    /// @param token The ERC20 fee token transferred.
    /// @param amount The amount claimed.
    event RewardClaimed(
        uint256 indexed e3Id,
        address indexed account,
        IERC20 indexed token,
        uint256 amount
    );

    /// @notice Emitted when the protocol-treasury share is credited for later pull.
    /// @param e3Id The ID of the E3 computation.
    /// @param treasury The treasury address credited (snapshotted at request time).
    /// @param token The ERC20 fee token used for this E3.
    /// @param amount The amount credited.
    event TreasuryCredited(
        uint256 indexed e3Id,
        address indexed treasury,
        IERC20 indexed token,
        uint256 amount
    );

    /// @notice Emitted when a treasury withdraws its accrued protocol share.
    /// @param treasury The treasury address pulling its credits.
    /// @param token The ERC20 token transferred.
    /// @param amount The amount transferred.
    event TreasuryClaimed(
        address indexed treasury,
        IERC20 indexed token,
        uint256 amount
    );

    /// @notice Emitted when an ERC20 token is allow-listed or removed as an E3 fee token.
    /// @param token The ERC20 token.
    /// @param allowed The new allow-list status.
    event FeeTokenAllowed(IERC20 indexed token, bool allowed);

    /// @notice The event MUST be emitted any time an encryption scheme is enabled.
    /// @param encryptionSchemeId The ID of the encryption scheme that was enabled.
    event EncryptionSchemeEnabled(bytes32 encryptionSchemeId);

    /// @notice This event MUST be emitted any time an encryption scheme is disabled.
    /// @param encryptionSchemeId The ID of the encryption scheme that was disabled.
    event EncryptionSchemeDisabled(bytes32 encryptionSchemeId);

    /// @notice This event MUST be emitted any time a E3 Program is registered.
    /// @param e3Program The address of the E3 Program.
    /// @dev Registration is append-only; programs cannot be deregistered.
    event E3ProgramRegistered(IE3Program e3Program);

    /// @notice Emitted when a BFV param set is registered or updated.
    /// @param paramSet The param set index.
    /// @param encodedParams ABI-encoded BFV parameters.
    event ParamSetRegistered(uint8 paramSet, bytes encodedParams);

    /// @notice Emitted when an existing param set slot is overwritten by
    ///         {Interfold.setParamSet}. The new value replaces the
    ///         previous encoded parameters atomically.
    event ParamSetUpdated(
        uint8 paramSet,
        bytes previousEncodedParams,
        bytes newEncodedParams
    );

    /// @notice Emitted when E3RefundManager contract is set.
    /// @param e3RefundManager The address of the E3RefundManager contract.
    event E3RefundManagerSet(address indexed e3RefundManager);

    /// @notice Emitted when the SlashingManager contract is set.
    /// @param slashingManager The address of the SlashingManager contract.
    event SlashingManagerSet(address indexed slashingManager);

    /// @notice Emitted when slashed funds are escrowed for an E3
    /// @param e3Id The E3 ID.
    /// @param amount The amount of slashed funds escrowed.
    event SlashedFundsEscrowed(uint256 indexed e3Id, uint256 amount);

    /// @notice Emitted when a failed E3 is processed for refunds.
    /// @param e3Id The ID of the failed E3.
    /// @param paymentAmount The original payment amount being refunded.
    /// @param honestNodeCount The number of honest nodes in the refund distribution.
    event E3FailureProcessed(
        uint256 indexed e3Id,
        uint256 paymentAmount,
        uint256 honestNodeCount
    );

    /// @notice Emitted when a committee is published and E3 lifecycle is updated.
    /// @param e3Id The ID of the E3.
    event CommitteeFormed(uint256 indexed e3Id);

    /// @notice Emitted when a committee is finalized (sortition complete, DKG starting).
    /// @param e3Id The ID of the E3.
    event CommitteeFinalized(uint256 indexed e3Id);

    /// @notice MUST be emitted whenever {Interfold.setPkVerifier} updates the
    ///         verifier address for an encryption scheme.
    event PkVerifierSet(
        bytes32 indexed encryptionSchemeId,
        IPkVerifier indexed pkVerifier
    );

    /// @notice Emitted when E3 stage changes
    event E3StageChanged(
        uint256 indexed e3Id,
        E3Stage previousStage,
        E3Stage newStage
    );

    /// @notice Emitted when an E3 is marked as failed
    event E3Failed(
        uint256 indexed e3Id,
        E3Stage failedAtStage,
        FailureReason reason
    );

    /// @notice Emitted when timeout config is updated
    event TimeoutConfigUpdated(E3TimeoutConfig config);

    /// @notice Emitted when committee thresholds are updated
    /// @param size The committee size enum value.
    /// @param threshold The M/N threshold values.
    event CommitteeThresholdsUpdated(
        CommitteeSize indexed size,
        uint32[2] threshold
    );

    /// @notice Emitted when pricing configuration is updated
    event PricingConfigUpdated(PricingConfig config);

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                        Errors                          //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Thrown when committee selection fails during E3 request or activation.
    error CommitteeSelectionFailed();

    /// @notice Thrown when an E3 request uses a program that is not enabled.
    /// @param e3Program The E3 program address that is not allowed.
    error E3ProgramNotAllowed(IE3Program e3Program);

    /// @notice Thrown when attempting to access an E3 that does not exist.
    /// @param e3Id The ID of the non-existent E3.
    error E3DoesNotExist(uint256 e3Id);

    /// @notice Thrown when attempting to register a program that is already registered.
    /// @param module The address of the program that is already registered.
    error ModuleAlreadyEnabled(address module);

    /// @notice Thrown when an invalid or disabled encryption scheme is used.
    /// @param encryptionSchemeId The ID of the invalid encryption scheme.
    error InvalidEncryptionScheme(bytes32 encryptionSchemeId);

    /// @notice Thrown when attempting to set an invalid ciphernode registry address.
    /// @param ciphernodeRegistry The invalid ciphernode registry address.
    error InvalidCiphernodeRegistry(ICiphernodeRegistry ciphernodeRegistry);

    /// @notice Thrown when the requested duration exceeds maxDuration or is zero.
    /// @param duration The invalid duration value.
    error InvalidDuration(uint256 duration);

    /// @notice Thrown when output verification fails.
    /// @param output The invalid output data.
    error InvalidOutput(bytes output);

    /// @notice Thrown when proof aggregation is enabled but no proof was supplied.
    error ProofRequired();

    /// @notice Thrown when the committee size has not been configured with thresholds.
    /// @param committeeSize The unconfigured committee size.
    error CommitteeSizeNotConfigured(CommitteeSize committeeSize);

    /// @notice Thrown when attempting to publish ciphertext output that has already been published.
    /// @param e3Id The ID of the E3.
    error CiphertextOutputAlreadyPublished(uint256 e3Id);

    /// @notice Thrown when attempting to publish plaintext output before ciphertext output.
    /// @param e3Id The ID of the E3.
    error CiphertextOutputNotPublished(uint256 e3Id);

    /// @notice Thrown when payment is required but not provided or insufficient.
    /// @param value The required payment amount.
    error PaymentRequired(uint256 value);

    /// @notice Thrown when attempting to publish plaintext output that has already been published.
    /// @param e3Id The ID of the E3.
    error PlaintextOutputAlreadyPublished(uint256 e3Id);

    /// @notice Thrown when attempting to set an invalid bonding registry address.
    /// @param bondingRegistry The invalid bonding registry address.
    error InvalidBondingRegistry(IBondingRegistry bondingRegistry);

    /// @notice Thrown when attempting to set an invalid fee token address.
    /// @param feeToken The invalid fee token address.
    error InvalidFeeToken(IERC20 feeToken);

    /// @notice E3 is not in expected stage
    error InvalidStage(uint256 e3Id, E3Stage expected, E3Stage actual);

    /// @notice E3 has already been marked as failed
    error E3AlreadyFailed(uint256 e3Id);

    /// @notice E3 has already completed
    error E3AlreadyComplete(uint256 e3Id);

    /// @notice Failure condition not yet met
    error FailureConditionNotMet(uint256 e3Id);

    /// @notice The Input deadline is invalid
    error InvalidInputDeadline(uint256 deadline);

    /// @notice The input deadline start is in the past
    error InvalidInputDeadlineStart(uint256 start);

    /// @notice The input deadline end is before the start
    error InvalidInputDeadlineEnd(uint256 end);

    /// @notice Below minimum committee size
    error CommitteeSizeTooSmall(CommitteeSize committeeSize);

    /// @notice Below minimum threshold
    error ThresholdTooSmall(uint256 threshold);

    /// @notice The duties are completed, and ciphernodes are not required to act anymore for this E3
    /// @param e3Id The ID of the E3
    /// @param expiration The expiration timestamp of the E3
    error CommitteeDutiesCompleted(uint256 e3Id, uint256 expiration);

    /// @notice The input deadline has not yet been reached
    /// @param e3Id The ID of the E3
    /// @param inputDeadline The input deadline timestamp of the E3
    error InputDeadlineNotReached(uint256 e3Id, uint256 inputDeadline);

    /// @notice Caller is not the CiphernodeRegistry
    error OnlyCiphernodeRegistry();

    /// @notice Caller is not the CiphernodeRegistry or SlashingManager
    error OnlyCiphernodeRegistryOrSlashingManager();

    /// @notice Thrown when {markE3Failed} is called by a non-privileged
    ///         account inside the grace window.
    error MarkE3FailedInGracePeriod(uint256 e3Id, uint256 gracePeriodEnds);

    /// @notice Caller is not the SlashingManager
    error OnlySlashingManager();

    /// @notice E3 is not in the Failed stage
    /// @param e3Id The ID of the E3
    error E3NotFailed(uint256 e3Id);

    /// @notice No payment available to refund for this E3
    /// @param e3Id The ID of the E3
    error NoPaymentToRefund(uint256 e3Id);

    /// @notice Timeout window value is invalid (must be > 0)
    error InvalidTimeoutWindow();

    /// @notice Threshold values are invalid
    error InvalidThresholdValues();

    /// @notice Committee size is below the configured minimum
    /// @param size The provided committee size
    /// @param minimum The required minimum
    error BelowMinCommitteeSize(uint256 size, uint256 minimum);

    /// @notice Threshold is below the configured minimum
    /// @param threshold The provided threshold
    /// @param minimum The required minimum
    error BelowMinThreshold(uint256 threshold, uint256 minimum);

    /// @notice A basis-points value exceeds its configured maximum
    /// @param value The invalid BPS value
    error BpsExceedsMax(uint256 value);

    /// @notice Protocol treasury address required when protocol share > 0
    error TreasuryRequired();

    /// @notice Minimum committee size must be >= minimum threshold
    error MinSizeBelowMinThreshold();

    /// @notice Utilization BPS exceeds 100%
    /// @param value The invalid utilization BPS value
    error UtilizationBpsExceedsMax(uint256 value);

    /// @notice The supplied or current fee token is not on the allow-list.
    /// @param token The disallowed token.
    error FeeTokenNotAllowed(IERC20 token);

    /// @notice Caller has no balance to claim for the given E3 / treasury / token.
    error NothingToClaim();

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                  Structs                               //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice This struct contains the parameters to submit a request to Interfold.
    /// @param committeeSize The M/N threshold and honest parties for the committee.
    /// @param inputWindow When the program will start and stop accepting inputs.
    /// @param e3Program The address of the E3 Program.
    /// @param paramSet The BFV encryption parameter set to use.
    /// @param computeProviderParams The ABI encoded compute provider parameters.
    /// @param customParams Arbitrary ABI-encoded application-defined parameters.
    struct E3RequestParams {
        CommitteeSize committeeSize;
        uint256[2] inputWindow;
        IE3Program e3Program;
        uint8 paramSet;
        bytes computeProviderParams;
        bytes customParams;
        /// @notice When true, ciphernodes generate and fold wrapper proofs
        ///         for DKG proof aggregation (public verifiability). When
        ///         false, wrapper/fold proofs are skipped to reduce latency.
        ///         C5 and C7 proofs are always generated and verified on-chain
        ///         regardless of this flag.
        bool proofAggregationEnabled;
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                  Core Entrypoints                      //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice This function should be called to request a computation within an Encrypted Execution Environment (E3).
    /// @dev This function MUST emit the E3Requested event.
    /// @param requestParams The parameters for the E3 request.
    /// @return e3Id ID of the E3.
    /// @return e3 The E3 struct.
    function request(
        E3RequestParams calldata requestParams
    ) external returns (uint256 e3Id, E3 memory e3);

    /// @notice This function should be called to publish output data for an Encrypted Execution Environment (E3).
    /// @dev This function MUST emit the CiphertextOutputPublished event.
    /// @param e3Id ID of the E3.
    /// @param ciphertextOutput ABI encoded output data to verify.
    /// @param proof ABI encoded data to verify the ciphertextOutput.
    /// @return success True if the output was successfully published.
    function publishCiphertextOutput(
        uint256 e3Id,
        bytes calldata ciphertextOutput,
        bytes calldata proof
    ) external returns (bool success);

    /// @notice This function publishes the plaintext output of an Encrypted Execution Environment (E3).
    /// @dev This function MUST revert if the output has not been published.
    /// @dev This function MUST emit the PlaintextOutputPublished event.
    /// @param e3Id ID of the E3.
    /// @param plaintextOutput ABI encoded plaintext output.
    /// @param proof DecryptionAggregator (EVM) proof ABI-encoded
    ///        `(bytes rawProof, bytes32[] publicInputs)`, or empty bytes when proof
    ///        aggregation is disabled for the E3.
    function publishPlaintextOutput(
        uint256 e3Id,
        bytes calldata plaintextOutput,
        bytes calldata proof
    ) external returns (bool success);

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Set Functions                        //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice This function should be called to set the maximum duration of requested computations.
    /// @param _maxDuration The maximum duration of a computation in seconds.
    function setMaxDuration(uint256 _maxDuration) external;

    /// @notice Sets the Ciphernode Registry contract address.
    /// @dev This function MUST revert if the address is zero or the same as the current registry.
    /// @param _ciphernodeRegistry The address of the new Ciphernode Registry contract.
    function setCiphernodeRegistry(
        ICiphernodeRegistry _ciphernodeRegistry
    ) external;

    /// @notice Sets the Bonding Registry contract address.
    /// @dev This function MUST revert if the address is zero or the same as the current registry.
    /// @param _bondingRegistry The address of the new Bonding Registry contract.
    function setBondingRegistry(IBondingRegistry _bondingRegistry) external;

    /// @notice Sets the fee token used for E3 payments.
    /// @dev This function MUST revert if the address is zero or the same as the current fee token.
    ///      Auto-adds the token to the fee-token allow-list.
    /// @param _feeToken The address of the new fee token.
    function setFeeToken(IERC20 _feeToken) external;

    /// @notice Add or remove a token from the fee-token allow-list.
    /// @dev Owner-only. The contract `feeToken()` must be on the allow-list for `request()` to succeed.
    /// @param token The ERC20 token.
    /// @param allowed `true` to allow, `false` to remove.
    function setFeeTokenAllowed(IERC20 token, bool allowed) external;

    /// @notice Returns whether a token is currently allow-listed as an E3 fee token.
    function isFeeTokenAllowed(IERC20 token) external view returns (bool);

    /// @notice Register an E3 Program. Append-only — programs cannot be deregistered.
    /// @param e3Program The address of the E3 Program.
    function registerE3Program(IE3Program e3Program) external;

    /// @notice Sets or enables a decryption verifier for a specific encryption scheme.
    /// @dev This function MUST revert if the verifier address is zero or already set to the same value.
    /// @param encryptionSchemeId The unique identifier for the encryption scheme.
    /// @param decryptionVerifier The address of the decryption verifier contract.
    function setDecryptionVerifier(
        bytes32 encryptionSchemeId,
        IDecryptionVerifier decryptionVerifier
    ) external;

    /// @notice Sets the C5 (pk_aggregation) proof verifier for an encryption scheme.
    /// @param encryptionSchemeId The encryption scheme identifier.
    /// @param pkVerifier The pk verifier contract (optional; address(0) to disable).
    function setPkVerifier(
        bytes32 encryptionSchemeId,
        IPkVerifier pkVerifier
    ) external;

    /// @notice Disables a previously enabled encryption scheme.
    /// @dev This function MUST revert if the encryption scheme is not currently enabled.
    /// @param encryptionSchemeId The unique identifier for the encryption scheme to disable.
    function disableEncryptionScheme(bytes32 encryptionSchemeId) external;

    /// @notice Registers ABI-encoded BFV parameters for a param set enum variant.
    /// @param paramSet The param set index to register.
    /// @param encodedParams ABI-encoded BFV parameters.
    function setParamSet(uint8 paramSet, bytes calldata encodedParams) external;

    /// @notice Sets the full pricing configuration.
    /// @param config The new pricing configuration.
    function setPricingConfig(PricingConfig calldata config) external;

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Get Functions                        //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice This function should be called to retrieve the details of an Encrypted Execution Environment (E3).
    /// @dev This function MUST revert if the E3 does not exist.
    /// @param e3Id ID of the E3.
    /// @return e3 The struct representing the requested E3.
    function getE3(uint256 e3Id) external view returns (E3 memory e3);

    /// @notice This function returns the fee of an E3
    /// @dev This function MUST revert if the E3 parameters are invalid.
    /// @param e3Params the struct representing the E3 request parameters
    /// @return fee the fee of the E3
    function getE3Quote(
        E3RequestParams calldata e3Params
    ) external view returns (uint256 fee);

    /// @notice Returns the full pricing configuration.
    function getPricingConfig() external view returns (PricingConfig memory);

    /// @notice Returns the decryption verifier for a given encryption scheme.
    /// @param encryptionSchemeId The unique identifier for the encryption scheme.
    /// @return The decryption verifier contract for the specified encryption scheme.
    function getDecryptionVerifier(
        bytes32 encryptionSchemeId
    ) external view returns (IDecryptionVerifier);

    /// @notice Returns the C5 pk verifier for an encryption scheme.
    /// @param encryptionSchemeId The encryption scheme identifier.
    /// @return The pk verifier contract (address(0) if not set).
    function getPkVerifier(
        bytes32 encryptionSchemeId
    ) external view returns (IPkVerifier);

    /// @notice Returns the ERC20 token used to pay for E3 fees.
    function feeToken() external view returns (IERC20);

    /// @notice Returns the BondingRegistry contract.
    function bondingRegistry() external view returns (IBondingRegistry);

    /// @notice Called by CiphernodeRegistry when committee is finalized (sortition complete).
    /// @dev Updates E3 lifecycle to CommitteeFinalized stage, starts DKG deadline.
    /// @param e3Id ID of the E3.
    function onCommitteeFinalized(uint256 e3Id) external;

    /// @notice Called by CiphernodeRegistry when committee public key is published (DKG complete).
    /// @dev Updates E3 lifecycle to KeyPublished stage.
    /// @param e3Id ID of the E3.
    /// @param committeePublicKey Hash of the committee's aggregated public key.
    function onCommitteePublished(
        uint256 e3Id,
        bytes32 committeePublicKey
    ) external;

    /// @notice Called by authorized contracts to mark an E3 as failed with a specific reason.
    /// @dev Updates E3 lifecycle to Failed stage with the given reason.
    /// @param e3Id ID of the E3.
    /// @param reason The failure reason from FailureReason enum.
    function onE3Failed(uint256 e3Id, uint8 reason) external;

    /// @notice Escrow slashed funds for deferred distribution
    /// @dev Called by SlashingManager. Proxies to E3RefundManager.
    /// @param e3Id The E3 ID.
    /// @param amount Amount of slashed funds to escrow.
    function escrowSlashedFunds(uint256 e3Id, uint256 amount) external;

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                  Lifecycle Functions                   //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Anyone can mark an E3 as failed if timeout passed
    /// @param e3Id The E3 ID
    /// @return reason The failure reason
    function markE3Failed(uint256 e3Id) external returns (FailureReason reason);

    /// @notice Process a failed E3: transfer payment to E3RefundManager and calculate refunds.
    /// @dev Permissionless. Requires E3 to be in Failed stage.
    /// @param e3Id The E3 ID
    function processE3Failure(uint256 e3Id) external;

    /// @notice Check if E3 can be marked as failed
    /// @param e3Id The E3 ID
    /// @return canFail Whether failure condition is met
    /// @return reason The failure reason if applicable
    function checkFailureCondition(
        uint256 e3Id
    ) external view returns (bool canFail, FailureReason reason);

    /// @notice Get current stage of an E3
    /// @param e3Id The E3 ID
    /// @return stage The current stage
    function getE3Stage(uint256 e3Id) external view returns (E3Stage stage);

    /// @notice Get failure reason for an E3
    /// @param e3Id The E3 ID
    /// @return reason The failure reason
    function getFailureReason(
        uint256 e3Id
    ) external view returns (FailureReason reason);

    /// @notice Get requester address for an E3
    /// @param e3Id The E3 ID
    /// @return requester The requester address
    function getRequester(
        uint256 e3Id
    ) external view returns (address requester);

    /// @notice Get deadlines for an E3
    /// @param e3Id The E3 ID
    /// @return deadlines The E3 deadlines
    function getDeadlines(
        uint256 e3Id
    ) external view returns (E3Deadlines memory deadlines);

    /// @notice Get timeout configuration
    /// @return config The current timeout config
    function getTimeoutConfig()
        external
        view
        returns (E3TimeoutConfig memory config);

    /// @notice Set timeout configuration
    /// @param config The new timeout config
    function setTimeoutConfig(E3TimeoutConfig calldata config) external;

    /// @notice Set the threshold values for a committee size
    /// @param size The committee size enum value
    /// @param threshold The M/N threshold values [quorum, total]
    function setCommitteeThresholds(
        CommitteeSize size,
        uint32[2] calldata threshold
    ) external;

    ////////////////////////////////////////////////////////////
    //                                                        //
    //              Pull-Payment Claim Functions              //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Claim accrued reward for a single completed E3.
    /// @dev Pull-payment counterpart to `RewardsDistributed`. Transfers the caller's
    ///      pending balance for `e3Id` in the E3's fee token.
    /// @param e3Id The E3 ID to claim from.
    /// @return amount The amount transferred to the caller.
    function claimReward(uint256 e3Id) external returns (uint256 amount);

    /// @notice Batch claim rewards across multiple completed E3s.
    /// @dev Per-id transfer; different e3Ids may use different fee tokens (each token
    ///      is snapshotted at request time). A mixed-token sum return would be
    ///      meaningless; listen to per-E3 {RewardClaimed} events instead.
    /// @param e3Ids The E3 IDs to claim from.
    function claimRewards(uint256[] calldata e3Ids) external;

    /// @notice Get the pending reward balance for an account on a given E3.
    function pendingReward(
        uint256 e3Id,
        address account
    ) external view returns (uint256);

    /// @notice Treasury pull-payment for accumulated protocol-share credits.
    /// @dev Caller must be the treasury that was credited; transfers all credits
    ///      for the given token. Each treasury address pulls its own balance.
    /// @param token The ERC20 token to claim.
    /// @return amount The amount transferred.
    function treasuryClaim(IERC20 token) external returns (uint256 amount);

    /// @notice Get pending treasury credits for a (treasury, token) pair.
    function pendingTreasuryClaim(
        address treasury,
        IERC20 token
    ) external view returns (uint256);
}
