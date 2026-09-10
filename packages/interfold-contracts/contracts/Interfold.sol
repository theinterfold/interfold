// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IInterfold, E3, IE3Program } from "./interfaces/IInterfold.sol";
import { ICiphernodeRegistry } from "./interfaces/ICiphernodeRegistry.sol";
import { IBondingRegistry } from "./interfaces/IBondingRegistry.sol";
import { INodeReleaseRegistry } from "./interfaces/INodeReleaseRegistry.sol";
import { ISlashingManager } from "./interfaces/ISlashingManager.sol";
import { IE3RefundManager } from "./interfaces/IE3RefundManager.sol";
import { IDecryptionVerifier } from "./interfaces/IDecryptionVerifier.sol";
import { IPkVerifier } from "./interfaces/IPkVerifier.sol";
import { ICiphertextVerifier } from "./interfaces/ICiphertextVerifier.sol";
import {
    Ownable2StepUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {
    ReentrancyGuardUpgradeable
} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { InterfoldLifecycle } from "./lib/InterfoldLifecycle.sol";
import { InterfoldPricing } from "./lib/InterfoldPricing.sol";
import { ActiveCryptoConfig } from "./lib/ActiveCryptoConfig.sol";

/**
 * @title Interfold
 * @notice Main contract for managing Encrypted Execution Environments (E3)
 * @dev Coordinates E3 lifecycle including request, activation, input publishing, and output verification
 */
// solhint-disable-next-line max-states-count
contract Interfold is
    IInterfold,
    Ownable2StepUpgradeable,
    ReentrancyGuardUpgradeable
{
    /// @notice Thrown when {renounceOwnership} is called.
    error RenounceOwnershipDisabled();

    /// @notice Upper bound on {maxDuration}.
    uint256 public constant MAX_DURATION_CAP = 365 days; // duration in seconds; not calendar-aware

    /// @notice Upper bound on any single timeout window.
    uint256 public constant MAX_TIMEOUT_WINDOW = 30 days;

    /// @notice Upper bound on configured committee size.
    uint32 public constant MAX_COMMITTEE_SIZE = ActiveCryptoConfig.N;

    /// @notice Cap on {PricingConfig.protocolShareBps}. Protocol share
    ///         is hard-capped at 50% so a compromised owner cannot route an
    ///         arbitrary fraction of every E3 fee away from honest nodes.
    uint16 public constant MAX_PROTOCOL_SHARE_BPS = 5_000;

    /// @notice Cap on {PricingConfig.marginBps}. Mirrors the protocol-share cap so
    ///         operator margin cannot be configured to make requests unaffordable.
    uint16 public constant MAX_MARGIN_BPS = 5_000;

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                 Storage Variables                      //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Address of the Ciphernode Registry contract.
    /// @dev Manages the pool of ciphernodes and committee selection.
    ICiphernodeRegistry public ciphernodeRegistry;

    /// @notice Address of the Bonding Registry contract.
    /// @dev Handles staking and reward distribution for ciphernodes.
    IBondingRegistry public bondingRegistry;

    /// @notice E3 Refund Manager contract for handling failed E3 refunds.
    /// @dev Manages refund calculation and claiming for failed E3s.
    IE3RefundManager public e3RefundManager;

    /// @notice Slashing Manager contract for fault attribution.
    /// @dev Used to check which operators have been slashed for E3s.
    ISlashingManager public slashingManager;

    /// @notice Address of the ERC20 token used for E3 fees.
    /// @dev All E3 request fees must be paid in this token.
    IERC20 public feeToken;

    /// @notice Maximum allowed duration for an E3 computation in seconds.
    /// @dev Requests with duration exceeding this value will be rejected.
    uint256 public maxDuration;

    /// @notice ID counter for the next E3 to be created.
    /// @dev Incremented after each successful E3 request.
    uint256 public nexte3Id;

    /// @notice Mapping of allowed E3 Programs.
    /// @dev Only enabled E3 Programs can be used in computation requests.
    mapping(IE3Program e3Program => bool allowed) public e3Programs;

    /// @notice Mapping storing all E3 instances by their ID.
    /// @dev Contains the full state and configuration of each E3.
    mapping(uint256 e3Id => E3 e3) public e3s;

    /// @notice Mapping of enabled encryption schemes to their decryption verifiers.
    /// @dev Each encryption scheme ID maps to a contract that can verify decrypted outputs.
    mapping(bytes32 encryptionSchemeId => IDecryptionVerifier decryptionVerifier)
        public decryptionVerifiers;

    /// @notice Mapping of encryption schemes to their DkgAggregator (EVM) proof verifiers.
    /// @dev Required per scheme; gates E3 requests like decryptionVerifier.
    mapping(bytes32 encryptionSchemeId => IPkVerifier pkVerifier)
        public pkVerifiers;

    /// @notice Mapping from param set index to ABI-encoded BFV parameters.
    /// @dev Ciphernodes map the uint8 index to their local BfvPreset.
    ///      New param sets can be added without a contract upgrade.
    mapping(uint8 => bytes) public paramSetRegistry;

    /// @notice Mapping tracking fee payments for each E3.
    /// @dev Stores service escrow. The request-time randomness fee is credited separately.
    mapping(uint256 e3Id => uint256 e3Payment) public e3Payments;

    /// @notice Maps E3 ID to its current stage
    mapping(uint256 e3Id => E3Stage stage) internal _e3Stages;

    /// @notice Maps E3 ID to its deadlines
    mapping(uint256 e3Id => E3Deadlines deadlines) internal _e3Deadlines;

    /// @notice Maps E3 ID to failure reason (if failed)
    mapping(uint256 e3Id => FailureReason reason) internal _e3FailureReasons;

    /// @notice Maps E3 ID to requester address
    mapping(uint256 e3Id => address requester) internal _e3Requesters;

    /// @notice Maps E3 ID to the fee token used at request time
    mapping(uint256 e3Id => IERC20 token) internal _e3FeeTokens;

    /// @notice Maps committee size to viability threshold and total members [H, N].
    mapping(CommitteeSize => uint32[2] threshold) public committeeThresholds;

    /// @notice Maps E3 ID to the protocol share BPS snapshotted at request time
    mapping(uint256 e3Id => uint16 protocolShareBps)
        internal _e3ProtocolShareBps;

    /// @notice Maps E3 ID to the protocol treasury snapshotted at request time
    mapping(uint256 e3Id => address protocolTreasury)
        internal _e3ProtocolTreasury;
    /// @notice Global timeout configuration
    E3TimeoutConfig internal _timeoutConfig;

    /// @notice All pricing-related configuration
    PricingConfig internal _pricingConfig;
    /// @notice Basis points denominator
    uint16 internal constant BPS_BASE = 10000;

    // Selectors for E3ProgramNotAllowed(address) and
    // ModuleAlreadyEnabled(address). Registration tests verify both values.
    uint256 private constant E3_PROGRAM_NOT_ALLOWED_SELECTOR = 0x52b4d4de;
    uint256 private constant MODULE_ALREADY_ENABLED_SELECTOR = 0xb29d4595;

    /// @notice Allow-list of ERC20 tokens that may be used as the contract fee token.
    /// @dev Owner-managed. `request()` reverts if the active `feeToken` is not allow-listed.
    mapping(IERC20 token => bool allowed) internal _feeTokenAllowed;

    /// @notice Pull-payment ledger for committee rewards. (e3Id => account => amount)
    /// @dev Credited by `_distributeRewards`, drained by `claimReward` / `claimRewards`.
    mapping(uint256 e3Id => mapping(address account => uint256 amount))
        internal _pendingRewards;

    /// @notice Pull-payment ledger for treasury randomness-fee and protocol-share credits.
    /// @dev Per-treasury / per-token so treasury rotations are non-destructive.
    mapping(address treasury => mapping(IERC20 token => uint256 amount))
        internal _pendingTreasury;

    struct E3Dependencies {
        ICiphernodeRegistry registry;
        IE3RefundManager refundManager;
        ISlashingManager slashManager;
        IBondingRegistry bonding;
    }

    /// @notice Grace window (seconds) after a stage deadline during which only
    ///         the original requester, owner, or an active committee member
    ///         can call {markE3Failed}. After the grace window, anyone
    ///         may finalise the failure. Default `0` preserves legacy
    ///         permissionless behaviour for tests and chains where the
    ///         restriction is undesired.
    uint256 public markFailedGracePeriod;

    /// @notice Lifecycle contracts frozen when each E3 is requested.
    mapping(uint256 e3Id => E3Dependencies dependencies)
        internal _e3Dependencies;

    /// @notice Expected decimals for the active fee token.
    uint8 public feeTokenDecimals;

    /// @inheritdoc IInterfold
    bool public requestsPaused;

    /// @inheritdoc IInterfold
    uint256 public activeE3Count;

    /// @notice Whether the first complete dependency graph has been activated.
    bool private _dependencyConfigurationActivated;

    /// @notice Timeout windows frozen when each E3 is requested.
    mapping(uint256 e3Id => E3TimeoutConfig config) private _e3TimeoutConfigs;

    /// @notice Latest possible lifecycle deadline derived at request time.
    mapping(uint256 e3Id => uint256 deadline) private _e3LifecycleDeadlines;

    /// @notice Circuit configuration frozen for each E3 request.
    mapping(uint256 e3Id => bytes32 configId) public e3CryptoConfigIds;

    /// @notice Governance-selected controller for ciphernode release eligibility.
    INodeReleaseRegistry public nodeReleaseRegistry;

    /// @notice Emitted when the {markFailedGracePeriod} value is updated.
    event MarkFailedGracePeriodSet(uint256 gracePeriod);

    /// @notice Emitted when governance replaces the ciphernode release controller.
    event NodeReleaseRegistrySet(
        INodeReleaseRegistry indexed nodeReleaseRegistry
    );

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                       Modifiers                        //
    //                                                        //
    ////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Initialization                       //
    ////////////////////////////////////////////////////////////

    /// @notice Locks the implementation; initialize via the proxy.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the Interfold contract with initial configuration.
    /// @param _owner The owner address of this contract.
    /// @param _ciphernodeRegistry The address of the Ciphernode Registry contract.
    /// @param _bondingRegistry The address of the Bonding Registry contract.
    /// @param _e3RefundManager The address of the E3 Refund Manager contract.
    /// @param feeAssetConfig Fee token and raw-unit pricing configuration.
    /// @param _maxDuration The maximum duration of a computation in seconds.
    /// @param config Initial timeout configuration for E3 lifecycle stages.
    /// @param initialE3Program The E3 Program to allow before ownership transfers.
    function initialize(
        address _owner,
        ICiphernodeRegistry _ciphernodeRegistry,
        IBondingRegistry _bondingRegistry,
        IE3RefundManager _e3RefundManager,
        FeeAssetConfig calldata feeAssetConfig,
        uint256 _maxDuration,
        E3TimeoutConfig calldata config,
        IE3Program initialE3Program
    ) public initializer {
        require(_owner != address(0), "Invalid owner");
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();
        setMaxDuration(_maxDuration);
        setCiphernodeRegistry(_ciphernodeRegistry);
        setBondingRegistry(_bondingRegistry);
        setE3RefundManager(_e3RefundManager);
        _setFeeAssetConfig(feeAssetConfig);
        _setTimeoutConfig(config);
        nexte3Id = uint256(uint160(address(this))) << 96;
        requestsPaused = true;
        emit RequestsPausedSet(true);

        registerE3Program(initialE3Program);

        if (_owner != owner()) _transferOwnership(_owner);
    }

    /// @notice Disabled. Reverts unconditionally to prevent permanent
    ///         loss of administrative control over Interfold.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceOwnershipDisabled();
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                  Core Entrypoints                      //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IInterfold
    function request(
        E3RequestParams calldata requestParams
    ) external nonReentrant returns (uint256 e3Id, E3 memory e3) {
        if (requestsPaused) revert RequestsPaused();
        _validateDependencyGraph();
        // Fee-token allow-list gate: protects requesters from being
        // forced into a fee token they did not consent to (e.g. a malicious
        // owner pointing `feeToken` at a fee-on-transfer or rebasing token).
        require(_feeTokenAllowed[feeToken], FeeTokenNotAllowed(feeToken));

        // Threshold gates ([1] > 0, min size, min threshold) are enforced inside {getE3Quote} below.
        // Input-window / duration gates are enforced by
        // {InterfoldLifecycle.validateRequest} (external library link, EIP-170 cap).
        require(
            e3Programs[requestParams.e3Program],
            E3ProgramNotAllowed(requestParams.e3Program)
        );

        uint256 quotedFee = getE3Quote(requestParams);
        InterfoldLifecycle.validateQuoteLimit(
            address(feeToken),
            address(requestParams.expectedFeeToken),
            requestParams.paramSet,
            requestParams.expectedCryptoConfigId,
            requestParams.maxFee,
            quotedFee
        );

        if (uint96(nexte3Id) == type(uint96).max) revert E3IdSpaceExhausted();
        e3Id = nexte3Id++;
        E3Dependencies storage dependencies = _e3Dependencies[e3Id];
        dependencies.registry = ciphernodeRegistry;
        dependencies.refundManager = e3RefundManager;
        dependencies.slashManager = slashingManager;
        dependencies.bonding = bondingRegistry;
        _e3TimeoutConfigs[e3Id] = _timeoutConfig;
        _e3LifecycleDeadlines[e3Id] =
            block.timestamp +
            InterfoldLifecycle.requestLifecycleDuration(
                requestParams.inputWindow[1],
                block.timestamp,
                address(dependencies.registry),
                _timeoutConfig
            );
        dependencies.refundManager.snapshotE3Policy(
            e3Id,
            address(dependencies.registry)
        );
        // This seed belongs to the E3 computation. The registry derives a
        // separate committee seed after this request is final.
        uint256 seed = uint256(keccak256(abi.encode(block.prevrandao, e3Id)));

        e3CryptoConfigIds[e3Id] = requestParams.expectedCryptoConfigId;

        e3.seed = seed;
        e3.committeeSize = requestParams.committeeSize;
        // Store the request as an EIP-6372 timestamp. The Registry and ticket
        // token use the same clock for request-time voting-power lookups.
        e3.requestBlock = block.timestamp;
        e3.inputWindow = requestParams.inputWindow;
        e3.e3Program = requestParams.e3Program;
        e3.paramSet = requestParams.paramSet;
        e3.customParams = requestParams.customParams;
        e3.requester = msg.sender;

        // Programs can validate request timing against the exact E3 and timeout snapshot. Store
        // the request before the external validation call; the transaction rolls this write back
        // if validation fails. Its stage and requester remain unset until validation completes,
        // so lifecycle entry points cannot act on this provisional record.
        e3s[e3Id] = e3;

        bytes32 encryptionSchemeId = requestParams.e3Program.validate(
            e3Id,
            seed,
            paramSetRegistry[requestParams.paramSet],
            requestParams.computeProviderParams,
            requestParams.customParams
        );
        InterfoldLifecycle.bindCryptoConfig(
            e3Id,
            encryptionSchemeId,
            paramSetRegistry[requestParams.paramSet]
        );
        require(
            address(decryptionVerifiers[encryptionSchemeId]) != address(0),
            InvalidEncryptionScheme(encryptionSchemeId)
        );

        require(
            address(pkVerifiers[encryptionSchemeId]) != address(0),
            InvalidEncryptionScheme(encryptionSchemeId)
        );
        // Complete the provisional record in place. Copying the full struct a second time wastes
        // enough runtime bytecode to put this upgrade too close to EIP-170.
        E3 storage storedE3 = e3s[e3Id];
        storedE3.encryptionSchemeId = encryptionSchemeId;
        storedE3.decryptionVerifier = decryptionVerifiers[encryptionSchemeId];
        storedE3.pkVerifier = pkVerifiers[encryptionSchemeId];
        // Keep the memory event payload in sync without copying the full dynamic struct back from
        // storage. Encoding the storage value directly consumes too much proxy runtime bytecode.
        e3.encryptionSchemeId = storedE3.encryptionSchemeId;
        e3.decryptionVerifier = storedE3.decryptionVerifier;
        e3.pkVerifier = storedE3.pkVerifier;
        _e3Stages[e3Id] = E3Stage.Requested;
        _e3Requesters[e3Id] = msg.sender;
        activeE3Count++;

        // Transfer fee after all validations and state changes
        InterfoldPricing.transferFromExact(
            feeToken,
            msg.sender,
            address(this),
            quotedFee
        );
        // Credit the payment only after the tokens are in custody. In particular, the external
        // program-validation call above must not expose a claimable treasury balance backed by
        // another E3's escrow.
        InterfoldPricing.recordRequestPayment(
            e3Payments,
            _e3FeeTokens,
            _e3ProtocolShareBps,
            _e3ProtocolTreasury,
            _pendingTreasury,
            _pricingConfig,
            e3Id,
            quotedFee,
            feeToken
        );

        require(
            dependencies.registry.requestCommittee(
                e3Id,
                seed,
                committeeThresholds[requestParams.committeeSize]
            ),
            CommitteeSelectionFailed()
        );

        emit E3Requested(e3Id, e3, requestParams.expectedCryptoConfigId);
        emit E3StageChanged(e3Id, E3Stage.None, E3Stage.Requested);
    }

    /// @inheritdoc IInterfold
    function publishCiphertextOutput(
        uint256 e3Id,
        bytes calldata encodedOutputReference
    ) external nonReentrant {
        InterfoldLifecycle.publishCiphertext(
            e3s,
            _e3Stages,
            _e3Deadlines,
            address(_registryFor(e3Id)),
            e3Id,
            _e3TimeoutConfigs[e3Id].decryptionWindow,
            encodedOutputReference
        );
    }

    /// @inheritdoc IInterfold
    function publishPlaintextOutput(
        uint256 e3Id,
        bytes calldata plaintextOutput,
        bytes calldata proof
    ) external nonReentrant returns (bool success) {
        require(
            e3s[e3Id].e3Program != IE3Program(address(0)),
            E3DoesNotExist(e3Id)
        );

        // Check we are in the right stage
        // no need to check if there's a ciphertext as we would not
        // be in this stage otherwise
        E3Stage current = _e3Stages[e3Id];
        require(
            current == E3Stage.CiphertextReady,
            InvalidStage(e3Id, E3Stage.CiphertextReady, current)
        );

        // you cannot post a decryption after the decryption deadline
        E3Deadlines memory deadlines = _e3Deadlines[e3Id];
        require(
            deadlines.decryptionDeadline >= block.timestamp,
            CommitteeDutiesCompleted(e3Id, deadlines.decryptionDeadline)
        );

        e3s[e3Id].plaintextOutput = plaintextOutput;
        _e3Stages[e3Id] = E3Stage.Complete;
        activeE3Count--;

        _verifyPlaintext(e3Id, keccak256(plaintextOutput), proof);
        success = true;

        _distributeRewards(e3Id);

        emit PlaintextOutputPublished(e3Id, plaintextOutput, proof);
        emit E3StageChanged(e3Id, E3Stage.CiphertextReady, E3Stage.Complete);
    }

    function _verifyPlaintext(
        uint256 e3Id,
        bytes32 plaintextHash,
        bytes calldata proof
    ) internal view {
        E3 storage e3 = e3s[e3Id];
        InterfoldLifecycle.verifyPlaintext(
            address(e3.decryptionVerifier),
            address(_registryFor(e3Id)),
            e3Id,
            e3.ciphertextOutput,
            e3.committeePublicKey,
            plaintextHash,
            e3.ciphertextCommitment,
            proof
        );
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Internal Functions                   //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Credits per-node rewards to the pull-payment ledger after a successful E3.
    /// @dev Pull payment so one reverting/blacklisted recipient cannot brick payouts.
    ///      Requester refund (when the whole committee is expelled) stays a direct
    ///      transfer — single recipient, no other party harmed.
    /// @param e3Id The ID of the E3 for which to distribute rewards.
    function _distributeRewards(uint256 e3Id) internal {
        InterfoldPricing.distributeRewards(
            e3Payments,
            _e3FeeTokens,
            _e3Requesters,
            _e3ProtocolShareBps,
            _e3ProtocolTreasury,
            _pendingTreasury,
            _pendingRewards,
            address(_registryFor(e3Id)),
            _refundManagerFor(e3Id),
            e3Id
        );
    }

    /// @notice Retrieves the honest committee nodes for a given E3.
    /// @dev Uses active committee view from the registry (which excludes expelled/slashed members).
    /// @param e3Id The ID of the E3.
    /// @return honestNodes An array of addresses of honest committee nodes.
    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Set Functions                        //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IInterfold
    function setMaxDuration(uint256 _maxDuration) public onlyOwner {
        require(
            _maxDuration > 0 && _maxDuration <= MAX_DURATION_CAP,
            InvalidDuration(_maxDuration)
        );
        maxDuration = _maxDuration;
        emit MaxDurationSet(_maxDuration);
    }

    /// @inheritdoc IInterfold
    function setCiphernodeRegistry(
        ICiphernodeRegistry _ciphernodeRegistry
    ) public onlyOwner {
        require(
            address(_ciphernodeRegistry) != address(0) &&
                _ciphernodeRegistry != ciphernodeRegistry,
            InvalidCiphernodeRegistry(_ciphernodeRegistry)
        );
        _requireDependencyReplacementReady(address(_ciphernodeRegistry));
        ciphernodeRegistry = _ciphernodeRegistry;
        emit CiphernodeRegistrySet(address(_ciphernodeRegistry));
    }

    /// @inheritdoc IInterfold
    function setBondingRegistry(
        IBondingRegistry _bondingRegistry
    ) public onlyOwner {
        require(
            address(_bondingRegistry) != address(0) &&
                _bondingRegistry != bondingRegistry,
            InvalidBondingRegistry(_bondingRegistry)
        );
        _requireDependencyReplacementReady(address(0));
        bondingRegistry = _bondingRegistry;
        emit BondingRegistrySet(address(_bondingRegistry));
    }

    /// @inheritdoc IInterfold
    function setFeeAssetConfig(
        FeeAssetConfig calldata config
    ) external onlyOwner {
        _setFeeAssetConfig(config);
    }

    /// @inheritdoc IInterfold
    function setRandomnessFlatFee(
        uint192 randomnessFlatFee
    ) external onlyOwner {
        InterfoldPricing.setRandomnessFlatFee(
            _pricingConfig,
            feeToken,
            feeTokenDecimals,
            randomnessFlatFee
        );
    }

    /// @inheritdoc IInterfold
    function setFeeTokenAllowed(IERC20 token, bool allowed) external onlyOwner {
        require(address(token) != address(0), InvalidFeeToken(token));
        _feeTokenAllowed[token] = allowed;
        emit FeeTokenAllowed(token, allowed);
    }

    /// @notice Configure the post-deadline {markE3Failed} grace window.
    /// @dev Inside the window only requester / owner / active committee member may
    ///      call {markE3Failed}; permissionless after. Pass `0` to disable.
    /// @param gracePeriod Seconds of caller-restriction after the relevant deadline.
    function setMarkFailedGracePeriod(uint256 gracePeriod) external onlyOwner {
        markFailedGracePeriod = gracePeriod;
        emit MarkFailedGracePeriodSet(gracePeriod);
    }

    /// @inheritdoc IInterfold
    function isFeeTokenAllowed(IERC20 token) external view returns (bool) {
        return _feeTokenAllowed[token];
    }

    /// @inheritdoc IInterfold
    function registerE3Program(IE3Program e3Program) public onlyOwner {
        // Use one storage lookup and compact error encoding. This keeps the
        // runtime below the release budget without changing either error.
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            if iszero(extcodesize(e3Program)) {
                mstore(0x00, E3_PROGRAM_NOT_ALLOWED_SELECTOR)
                mstore(0x20, e3Program)
                revert(0x1c, 0x24)
            }

            mstore(0x00, e3Program)
            mstore(0x20, e3Programs.slot)
            let programSlot := keccak256(0x00, 0x40)
            if sload(programSlot) {
                mstore(0x00, MODULE_ALREADY_ENABLED_SELECTOR)
                mstore(0x20, e3Program)
                revert(0x1c, 0x24)
            }
            sstore(programSlot, 1)
        }
        emit E3ProgramRegistered(e3Program);
    }

    /// @inheritdoc IInterfold
    function unregisterE3Program(IE3Program e3Program) external onlyOwner {
        InterfoldLifecycle.unregisterE3Program(e3Programs, e3Program);
    }

    /// @inheritdoc IInterfold
    function setDecryptionVerifier(
        bytes32 encryptionSchemeId,
        IDecryptionVerifier decryptionVerifier
    ) external onlyOwner {
        InterfoldLifecycle.validateDecryptionVerifier(
            address(decryptionVerifier)
        );
        require(
            decryptionVerifier != IDecryptionVerifier(address(0)) &&
                decryptionVerifiers[encryptionSchemeId] != decryptionVerifier,
            InvalidEncryptionScheme(encryptionSchemeId)
        );
        decryptionVerifiers[encryptionSchemeId] = decryptionVerifier;
        emit EncryptionSchemeEnabled(encryptionSchemeId);
    }

    /// @inheritdoc IInterfold
    function setPkVerifier(
        bytes32 encryptionSchemeId,
        IPkVerifier pkVerifier
    ) external onlyOwner {
        InterfoldLifecycle.validatePkVerifier(address(pkVerifier));
        require(
            address(pkVerifier) != address(0) &&
                pkVerifiers[encryptionSchemeId] != pkVerifier,
            InvalidEncryptionScheme(encryptionSchemeId)
        );
        pkVerifiers[encryptionSchemeId] = pkVerifier;
        emit PkVerifierSet(encryptionSchemeId, pkVerifier);
    }

    /// @inheritdoc IInterfold
    function setCiphertextVerifier(
        bytes32 encryptionSchemeId,
        ICiphertextVerifier ciphertextVerifier
    ) external onlyOwner {
        InterfoldLifecycle.setCiphertextVerifier(
            encryptionSchemeId,
            ciphertextVerifier
        );
        emit CiphertextVerifierSet(encryptionSchemeId, ciphertextVerifier);
    }

    /// @notice Registers the parameter set compiled into the active circuits.
    /// @param paramSet The param set index (0 = Insecure512, 1 = Secure8192, ...).
    /// @param encodedParams ABI-encoded BFV parameters (degree, plaintext_modulus, moduli[]).
    function setParamSet(
        uint8 paramSet,
        bytes calldata encodedParams
    ) external onlyOwner {
        InterfoldLifecycle.validateParamSet(
            paramSet,
            keccak256(encodedParams),
            paramSetRegistry[paramSet].length != 0
        );
        paramSetRegistry[paramSet] = encodedParams;
        emit ParamSetRegistered(paramSet, encodedParams);
    }

    /// @notice Sets the E3 Refund Manager contract address
    /// @param _e3RefundManager The new E3 Refund Manager contract address
    function setE3RefundManager(
        IE3RefundManager _e3RefundManager
    ) public onlyOwner {
        require(address(_e3RefundManager) != address(0));
        _requireDependencyReplacementReady(address(0));
        e3RefundManager = _e3RefundManager;
        emit E3RefundManagerSet(address(_e3RefundManager));
    }

    /// @notice Sets the Slashing Manager contract address
    /// @param _slashingManager The new Slashing Manager contract address
    function setSlashingManager(
        ISlashingManager _slashingManager
    ) external onlyOwner {
        require(address(_slashingManager) != address(0));
        _requireDependencyReplacementReady(address(0));
        slashingManager = _slashingManager;
        emit SlashingManagerSet(address(_slashingManager));
    }

    /// @notice Process a failed E3 and calculate refunds
    /// @dev Can be called by anyone once E3 is in failed state.
    ///      Uses the per-E3 feeToken stored at request time (survives global token rotation).
    /// @param e3Id The ID of the failed E3
    function processE3Failure(uint256 e3Id) external {
        InterfoldPricing.processE3Failure(
            e3Payments,
            _e3FeeTokens,
            uint8(_e3Stages[e3Id]),
            address(_registryFor(e3Id)),
            _refundManagerFor(e3Id),
            e3Id
        );
    }

    /// @inheritdoc IInterfold
    function escrowSlashedFunds(
        uint256 e3Id,
        uint256 proposalId,
        address operator,
        IERC20 token,
        uint256 amount
    ) external {
        InterfoldLifecycle.validateSlashCaller(
            msg.sender,
            address(_slashingManagerFor(e3Id))
        );
        _refundManagerFor(e3Id).escrowSlashedFunds(
            e3Id,
            proposalId,
            operator,
            token,
            amount
        );
        emit SlashedFundsEscrowed(e3Id, token, amount);
    }

    /// @inheritdoc IInterfold
    function onCommitteeFinalized(uint256 e3Id) external {
        uint256 dkgDeadline = InterfoldLifecycle
            .validateAndSnapshotCommitteeFinalization(
                msg.sender,
                address(_registryFor(e3Id)),
                address(_refundManagerFor(e3Id)),
                e3Id,
                uint8(_e3Stages[e3Id]),
                _e3TimeoutConfigs[e3Id].dkgWindow
            );
        // Keep DKG inside the request-time lifecycle bound. Delayed
        // finalization reduces the remaining DKG window instead of moving it.
        _e3Stages[e3Id] = E3Stage.CommitteeFinalized;
        _e3Deadlines[e3Id].dkgDeadline = dkgDeadline;

        emit CommitteeFinalized(e3Id);
        emit E3StageChanged(
            e3Id,
            E3Stage.Requested,
            E3Stage.CommitteeFinalized
        );
    }

    /// @inheritdoc IInterfold
    function onCommitteePublished(
        uint256 e3Id,
        bytes32 committeePublicKey
    ) external {
        InterfoldLifecycle.validateCommitteePublication(
            msg.sender,
            address(_registryFor(e3Id)),
            e3Id,
            uint8(_e3Stages[e3Id]),
            _e3Deadlines[e3Id].dkgDeadline
        );
        E3 storage e3 = e3s[e3Id];

        _e3Stages[e3Id] = E3Stage.KeyPublished;
        e3.committeePublicKey = committeePublicKey;
        uint256 computeStartsAt = block.timestamp > e3.inputWindow[1]
            ? block.timestamp
            : e3.inputWindow[1];
        _e3Deadlines[e3Id].computeDeadline =
            computeStartsAt +
            _e3TimeoutConfigs[e3Id].computeWindow;

        emit CommitteeFormed(e3Id);
        emit E3StageChanged(
            e3Id,
            E3Stage.CommitteeFinalized,
            E3Stage.KeyPublished
        );
    }

    /// @inheritdoc IInterfold
    function onE3Failed(uint256 e3Id, uint8 reason) external {
        E3Stage current = _e3Stages[e3Id];
        InterfoldLifecycle.validateReportedFailure(
            msg.sender,
            address(_registryFor(e3Id)),
            address(_slashingManagerFor(e3Id)),
            e3Id,
            uint8(current),
            reason
        );
        _markE3FailedWithReason(e3Id, current, FailureReason(reason));
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Lifecycle Functions                  //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Anyone can mark an E3 as failed if timeout passed
    /// @dev While `markFailedGracePeriod > 0` and inside the window, only requester /
    ///      owner / active committee member may call; permissionless once
    ///      `block.timestamp > relevantDeadline + markFailedGracePeriod`. Protects
    ///      against short chain or RPC delays without giving up liveness.
    /// @param e3Id The E3 ID
    /// @return reason The failure reason
    function markE3Failed(
        uint256 e3Id
    ) external returns (FailureReason reason) {
        E3Stage current = _e3Stages[e3Id];

        InterfoldLifecycle.validateMarkFailedStage(e3Id, uint8(current));

        bool canFail;
        uint256 deadline;
        (canFail, reason, deadline) = _checkFailureCondition(e3Id, current);
        if (!canFail) revert FailureConditionNotMet(e3Id);

        InterfoldLifecycle.validateMarkFailedCaller(
            e3Id,
            deadline,
            markFailedGracePeriod,
            msg.sender,
            _e3Requesters[e3Id],
            owner(),
            address(_registryFor(e3Id))
        );

        _markE3FailedWithReason(e3Id, current, reason);
        if (current == E3Stage.Requested) {
            _registryFor(e3Id).releaseCommittee(e3Id);
        }
    }

    /// @inheritdoc IInterfold
    function cancelE3(uint256 e3Id) external {
        InterfoldLifecycle.cancelE3(
            _e3Stages,
            _e3FailureReasons,
            _e3Requesters,
            address(_registryFor(e3Id)),
            e3Id,
            msg.sender
        );
        activeE3Count--;
    }

    /// @notice Internal function to mark E3 as failed with specific reason
    /// @param e3Id The E3 ID
    /// @param current The current stage (already loaded by caller)
    /// @param reason The failure reason
    function _markE3FailedWithReason(
        uint256 e3Id,
        E3Stage current,
        FailureReason reason
    ) internal {
        _e3Stages[e3Id] = E3Stage.Failed;
        _e3FailureReasons[e3Id] = reason;
        activeE3Count--;

        emit E3StageChanged(e3Id, current, E3Stage.Failed);
        emit E3Failed(e3Id, current, reason);
    }

    /// @notice Check if E3 can be marked as failed
    /// @param e3Id The E3 ID
    /// @return canFail Whether failure condition is met
    /// @return reason The failure reason if applicable
    function checkFailureCondition(
        uint256 e3Id
    ) external view returns (bool canFail, FailureReason reason) {
        E3Stage current = _e3Stages[e3Id];
        (canFail, reason, ) = _checkFailureCondition(e3Id, current);
    }

    /// @notice Internal function to check failure conditions
    /// @return canFail Whether the failure condition is satisfied.
    /// @return reason  The failure reason classifier.
    /// @return deadline The relevant stage deadline (used by {markE3Failed}
    ///         to compute the {markFailedGracePeriod} window).
    function _checkFailureCondition(
        uint256 e3Id,
        E3Stage stage
    )
        internal
        view
        returns (bool canFail, FailureReason reason, uint256 deadline)
    {
        uint8 rawReason;
        (canFail, rawReason, deadline) = InterfoldLifecycle.failureCondition(
            address(_registryFor(e3Id)),
            e3Id,
            uint8(stage),
            _e3Deadlines[e3Id],
            _e3TimeoutConfigs[e3Id].dkgWindow
        );
        reason = FailureReason(rawReason);
    }

    /// @notice Get current stage of an E3
    /// @param e3Id The E3 ID
    /// @return stage The current stage
    function getE3Stage(uint256 e3Id) external view returns (E3Stage stage) {
        return _e3Stages[e3Id];
    }

    /// @notice Get failure reason for an E3
    /// @param e3Id The E3 ID
    /// @return reason The failure reason
    function getFailureReason(
        uint256 e3Id
    ) external view returns (FailureReason reason) {
        return _e3FailureReasons[e3Id];
    }

    /// @notice Get requester address for an E3
    /// @param e3Id The E3 ID
    /// @return requester The requester address
    function getRequester(
        uint256 e3Id
    ) external view returns (address requester) {
        return _e3Requesters[e3Id];
    }

    /// @notice Get deadlines for an E3
    /// @param e3Id The E3 ID
    /// @return deadlines The E3 deadlines
    function getDeadlines(
        uint256 e3Id
    ) external view returns (E3Deadlines memory deadlines) {
        return _e3Deadlines[e3Id];
    }

    /// @notice Get timeout configuration
    /// @return config The current timeout config
    function getTimeoutConfig()
        external
        view
        returns (E3TimeoutConfig memory config)
    {
        return _timeoutConfig;
    }

    /// @inheritdoc IInterfold
    function getE3TimeoutConfig(
        uint256 e3Id
    ) external view returns (E3TimeoutConfig memory config) {
        return _e3TimeoutConfigs[e3Id];
    }

    /// @inheritdoc IInterfold
    function getE3LifecycleDeadline(
        uint256 e3Id
    ) external view returns (uint256 deadline) {
        return _e3LifecycleDeadlines[e3Id];
    }

    /// @inheritdoc IInterfold
    function setRequestsPaused(bool paused) external onlyOwner {
        if (requestsPaused == paused) return;
        if (!paused) {
            _validateDependencyGraph();
            _dependencyConfigurationActivated = true;
        }
        requestsPaused = paused;
        emit RequestsPausedSet(paused);
    }

    /// @notice Sets the release controller while the protocol is paused and drained.
    function setNodeReleaseRegistry(
        INodeReleaseRegistry newNodeReleaseRegistry
    ) external onlyOwner {
        if (address(newNodeReleaseRegistry).code.length == 0) {
            revert DependencyConfigurationMismatch();
        }
        nodeReleaseRegistry = newNodeReleaseRegistry;
        newNodeReleaseRegistry.activate();
        emit NodeReleaseRegistrySet(newNodeReleaseRegistry);
    }

    /// @notice Set timeout configuration
    /// @param config The new timeout config
    function setTimeoutConfig(
        E3TimeoutConfig calldata config
    ) external onlyOwner {
        _setTimeoutConfig(config);
    }

    /// @notice Internal function to set timeout config
    function _setTimeoutConfig(E3TimeoutConfig calldata config) internal {
        InterfoldLifecycle.validateTimeoutConfig(config, MAX_TIMEOUT_WINDOW);
        _timeoutConfig = config;
        emit TimeoutConfigUpdated(config);
    }

    /// @inheritdoc IInterfold
    function setCommitteeThresholds(
        CommitteeSize size,
        uint32[2] calldata threshold
    ) external onlyOwner {
        PricingConfig memory pc = _pricingConfig;
        InterfoldLifecycle.validateCommitteeThresholds(
            uint8(size),
            threshold,
            pc.minCommitteeSize,
            pc.minThreshold
        );
        committeeThresholds[size] = threshold;
        emit CommitteeThresholdsUpdated(size, threshold);
    }

    function _setFeeAssetConfig(FeeAssetConfig calldata config) internal {
        // Validation is delegated to {InterfoldPricing.validateFeeAssetConfig}
        // (external library link) to keep the deployed Interfold runtime
        // bytecode under the EIP-170 24,576-byte cap. Revert selectors are
        // preserved via shared {IInterfold} error declarations.
        InterfoldPricing.validateFeeAssetConfig(
            config,
            MAX_MARGIN_BPS,
            MAX_PROTOCOL_SHARE_BPS
        );
        IERC20 token = IERC20(config.token);
        feeToken = token;
        feeTokenDecimals = config.expectedDecimals;
        _pricingConfig = config.pricing;
        _feeTokenAllowed[token] = true;
        emit FeeAssetConfigUpdated(
            token,
            config.expectedDecimals,
            config.pricing
        );
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                   Get Functions                        //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IInterfold
    function getE3(uint256 e3Id) public view returns (E3 memory e3) {
        e3 = e3s[e3Id];
        require(e3.e3Program != IE3Program(address(0)), E3DoesNotExist(e3Id));
    }

    /// @inheritdoc IInterfold
    function getE3Quote(
        E3RequestParams calldata requestParams
    ) public view returns (uint256 fee) {
        InterfoldLifecycle.validateRequest(
            requestParams.inputWindow,
            block.timestamp,
            address(ciphernodeRegistry),
            _timeoutConfig,
            maxDuration
        );
        require(
            paramSetRegistry[requestParams.paramSet].length > 0,
            "BFV param set not registered"
        );
        uint32[2] memory threshold = committeeThresholds[
            requestParams.committeeSize
        ];
        // Fee math is delegated to {InterfoldPricing.quote} (external library
        // link) to keep the deployed Interfold runtime bytecode under
        // the EIP-170 24,576-byte cap. Inputs are snapshotted into calldata
        // for the call site; behaviour and revert selectors match the
        // original inlined implementation.
        fee = InterfoldPricing.quote(
            _pricingConfig,
            _timeoutConfig,
            ciphernodeRegistry.sortitionSubmissionWindow(),
            requestParams.paramSet,
            uint8(requestParams.committeeSize),
            threshold,
            block.timestamp,
            requestParams.inputWindow[0],
            requestParams.inputWindow[1]
        );
    }

    /// @inheritdoc IInterfold
    function getPricingConfig() external view returns (PricingConfig memory) {
        return _pricingConfig;
    }

    /// @inheritdoc IInterfold
    function getDecryptionVerifier(
        bytes32 encryptionSchemeId
    ) external view returns (IDecryptionVerifier) {
        return decryptionVerifiers[encryptionSchemeId];
    }

    /// @inheritdoc IInterfold
    function getPkVerifier(
        bytes32 encryptionSchemeId
    ) external view returns (IPkVerifier) {
        return pkVerifiers[encryptionSchemeId];
    }

    /// @inheritdoc IInterfold
    function getCiphertextVerifier(
        bytes32 encryptionSchemeId
    ) external view returns (address) {
        return InterfoldLifecycle.getCiphertextVerifier(encryptionSchemeId);
    }

    /// @inheritdoc IInterfold
    function activeCryptoConfigId() external pure returns (bytes32) {
        return ActiveCryptoConfig.CONFIG_ID;
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //              Pull-Payment Claim Functions              //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @inheritdoc IInterfold
    function claimReward(uint256 e3Id) external returns (uint256 amount) {
        amount = _claimReward(e3Id, msg.sender);
        require(amount > 0, NothingToClaim());
    }

    /// @inheritdoc IInterfold
    function claimRewards(uint256[] calldata e3Ids) external {
        uint256 len = e3Ids.length;
        bool claimed;
        for (uint256 i = 0; i < len; i++) {
            if (_claimReward(e3Ids[i], msg.sender) != 0) claimed = true;
        }
        require(claimed, NothingToClaim());
    }

    /// @notice Internal helper: drains the caller's pull balance for one E3
    ///         and emits `RewardClaimed`. Returns 0 if nothing to claim
    ///         (so batch calls don't revert on partially-empty inputs).
    function _claimReward(
        uint256 e3Id,
        address account
    ) internal returns (uint256 amount) {
        return
            InterfoldPricing.claimReward(
                _pendingRewards,
                _e3FeeTokens,
                e3Id,
                account
            );
    }

    /// @inheritdoc IInterfold
    function pendingReward(
        uint256 e3Id,
        address account
    ) external view returns (uint256) {
        return _pendingRewards[e3Id][account];
    }

    /// @inheritdoc IInterfold
    function treasuryClaim(IERC20 token) external returns (uint256 amount) {
        amount = InterfoldPricing.claimTreasury(
            _pendingTreasury,
            msg.sender,
            token
        );
        require(amount > 0, NothingToClaim());
    }

    /// @inheritdoc IInterfold
    function pendingTreasuryClaim(
        address treasury,
        IERC20 token
    ) external view returns (uint256) {
        return _pendingTreasury[treasury][token];
    }

    function _registryFor(
        uint256 e3Id
    ) private view returns (ICiphernodeRegistry) {
        return _e3Dependencies[e3Id].registry;
    }

    function _refundManagerFor(
        uint256 e3Id
    ) private view returns (IE3RefundManager) {
        return _e3Dependencies[e3Id].refundManager;
    }

    function _slashingManagerFor(
        uint256 e3Id
    ) private view returns (ISlashingManager) {
        return _e3Dependencies[e3Id].slashManager;
    }

    function _validateDependencyGraph() private view {
        InterfoldLifecycle.validateDependencyGraph(
            address(ciphernodeRegistry),
            address(bondingRegistry),
            address(slashingManager),
            address(e3RefundManager),
            address(nodeReleaseRegistry)
        );
    }

    function _requireDependencyReplacementReady(
        address replacementRegistry
    ) private view {
        InterfoldLifecycle.validateGenerationDrained(
            _dependencyConfigurationActivated,
            requestsPaused,
            activeE3Count,
            address(ciphernodeRegistry),
            address(bondingRegistry),
            address(slashingManager),
            replacementRegistry
        );
    }

    ////////////////////////////////////////////////////////////
    //                                                        //
    //              ERC-165 Interface Detection               //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice ERC-165 interface detection. Advertises {IInterfold} and
    ///         {IERC165} so off-chain integrators can discover the public ABI.
    /// @param interfaceId Candidate interface identifier.
    /// @return True if `interfaceId` matches a supported interface.
    function supportsInterface(
        bytes4 interfaceId
    ) external pure virtual returns (bool) {
        return
            interfaceId == type(IInterfold).interfaceId ||
            interfaceId == 0x01ffc9a7; // IERC165.supportsInterface selector
    }

    /// @dev Reserved storage slots for future upgrades. Adding new state
    ///      variables in derived versions of this contract must reduce this
    ///      array's length accordingly to preserve storage layout compatibility
    ///      across upgrades.
    // solhint-disable-next-line var-name-mixedcase
    uint256[42] private __gap;
}
