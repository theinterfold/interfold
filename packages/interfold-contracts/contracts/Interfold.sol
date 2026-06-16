// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IInterfold, E3, IE3Program } from "./interfaces/IInterfold.sol";
import { ICiphernodeRegistry } from "./interfaces/ICiphernodeRegistry.sol";
import { IBondingRegistry } from "./interfaces/IBondingRegistry.sol";
import { ISlashingManager } from "./interfaces/ISlashingManager.sol";
import { IE3RefundManager } from "./interfaces/IE3RefundManager.sol";
import { IDecryptionVerifier } from "./interfaces/IDecryptionVerifier.sol";
import { IPkVerifier } from "./interfaces/IPkVerifier.sol";
import {
    Ownable2StepUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {
    SafeERC20
} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { InterfoldPricing } from "./lib/InterfoldPricing.sol";

/**
 * @title Interfold
 * @notice Main contract for managing Encrypted Execution Environments (E3)
 * @dev Coordinates E3 lifecycle including request, activation, input publishing, and output verification
 */
// solhint-disable-next-line max-states-count
contract Interfold is IInterfold, Ownable2StepUpgradeable {
    using SafeERC20 for IERC20;

    /// @notice Thrown when {renounceOwnership} is called.
    error RenounceOwnershipDisabled();

    /// @notice Upper bound on {maxDuration}.
    uint256 public constant MAX_DURATION_CAP = 365 days; // duration in seconds; not calendar-aware

    /// @notice Upper bound on any single timeout window.
    uint256 public constant MAX_TIMEOUT_WINDOW = 30 days;

    /// @notice Upper bound on configured committee size.
    uint32 public constant MAX_COMMITTEE_SIZE = 256;

    /// @notice Cap on {PricingConfig.protocolShareBps}. Protocol share
    ///         is hard-capped at 50% so a compromised owner cannot route an
    ///         arbitrary fraction of every E3 fee away from honest nodes.
    uint16 public constant MAX_PROTOCOL_SHARE_BPS = 5_000;

    /// @notice Cap on {PricingConfig.marginBps}. Mirrors the protocol-share cap so
    ///         operator margin cannot be configured to make requests unaffordable.
    uint16 public constant MAX_MARGIN_BPS = 5_000;

    /// @notice Thrown when the quoted fee exceeds the requester-supplied bound.
    ///         Declared in {IInterfold} so {InterfoldPricing} can revert with the
    ///         same selector when validating a quote via DELEGATECALL.

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
    /// @dev Stores the amount paid for an E3, distributed to committee upon completion.
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

    /// @notice Maps committee size to threshold values [quorum, total]
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

    /// @notice Allow-list of ERC20 tokens that may be used as the contract fee token.
    /// @dev Owner-managed. `request()` reverts if the active `feeToken` is not allow-listed.
    mapping(IERC20 token => bool allowed) internal _feeTokenAllowed;

    /// @notice Pull-payment ledger for committee rewards. (e3Id => account => amount)
    /// @dev Credited by `_distributeRewards`, drained by `claimReward` / `claimRewards`.
    mapping(uint256 e3Id => mapping(address account => uint256 amount))
        internal _pendingRewards;

    /// @notice Pull-payment ledger for treasury protocol-share credits.
    /// @dev Per-treasury / per-token so treasury rotations are non-destructive.
    mapping(address treasury => mapping(IERC20 token => uint256 amount))
        internal _pendingTreasury;

    /// @notice Grace window (seconds) after a stage deadline during which only
    ///         the original requester, owner, or an active committee member
    ///         can call {markE3Failed}. After the grace window, anyone
    ///         may finalise the failure. Default `0` preserves legacy
    ///         permissionless behaviour for tests and chains where the
    ///         restriction is undesired.
    uint256 public markFailedGracePeriod;

    /// @notice Emitted when the {markFailedGracePeriod} value is updated.
    event MarkFailedGracePeriodSet(uint256 gracePeriod);

    ////////////////////////////////////////////////////////////
    //                                                        //
    //                       Modifiers                        //
    //                                                        //
    ////////////////////////////////////////////////////////////

    /// @notice Restricts function to CiphernodeRegistry contract only
    modifier onlyCiphernodeRegistry() {
        require(
            msg.sender == address(ciphernodeRegistry),
            OnlyCiphernodeRegistry()
        );
        _;
    }

    /// @notice Restricts function to CiphernodeRegistry or SlashingManager
    modifier onlyCiphernodeRegistryOrSlashingManager() {
        require(
            msg.sender == address(ciphernodeRegistry) ||
                msg.sender == address(slashingManager),
            OnlyCiphernodeRegistryOrSlashingManager()
        );
        _;
    }

    /// @notice Restricts function to SlashingManager contract only
    modifier onlySlashingManager() {
        require(msg.sender == address(slashingManager), OnlySlashingManager());
        _;
    }

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
    /// @param _feeToken The address of the ERC20 token used for E3 fees.
    /// @param _maxDuration The maximum duration of a computation in seconds.
    /// @param config Initial timeout configuration for E3 lifecycle stages.
    function initialize(
        address _owner,
        ICiphernodeRegistry _ciphernodeRegistry,
        IBondingRegistry _bondingRegistry,
        IE3RefundManager _e3RefundManager,
        IERC20 _feeToken,
        uint256 _maxDuration,
        E3TimeoutConfig calldata config
    ) public initializer {
        require(_owner != address(0), "Invalid owner");
        __Ownable_init(msg.sender);
        setMaxDuration(_maxDuration);
        setCiphernodeRegistry(_ciphernodeRegistry);
        setBondingRegistry(_bondingRegistry);
        setE3RefundManager(_e3RefundManager);
        setFeeToken(_feeToken);
        _setTimeoutConfig(config);

        // Default pricing parameters applied via the linked InterfoldPricing
        // library (assembly SSTOREs against the caller's _pricingConfig
        // slots) so the 15-field literal stays out of Interfold's runtime
        // bytecode (EIP-170 24,576-byte cap).
        InterfoldPricing.applyDefaultPricingConfig();

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
    ) external returns (uint256 e3Id, E3 memory e3) {
        // Fee-token allow-list gate: protects requesters from being
        // forced into a fee token they did not consent to (e.g. a malicious
        // owner pointing `feeToken` at a fee-on-transfer or rebasing token).
        require(_feeTokenAllowed[feeToken], FeeTokenNotAllowed(feeToken));

        // Threshold gates ([1] > 0, min size, min threshold) are enforced inside {getE3Quote} below.
        uint32[2] memory threshold = committeeThresholds[
            requestParams.committeeSize
        ];

        // Input-window / duration gates are enforced by
        // {InterfoldPricing.validateRequest} (external library link, EIP-170 cap).
        require(
            e3Programs[requestParams.e3Program],
            E3ProgramNotAllowed(requestParams.e3Program)
        );

        uint256 e3Fee = getE3Quote(requestParams);
        InterfoldPricing.validateRequest(
            requestParams.inputWindow,
            block.timestamp,
            _timeoutConfig.computeWindow,
            _timeoutConfig.decryptionWindow,
            maxDuration,
            e3Fee
        );

        e3Id = nexte3Id;
        nexte3Id++;
        // Seed uses block.prevrandao combined with e3Id as additional entropy.
        // While prevrandao is not cryptographically unpredictable (validator-controlled),
        // the combination with the unique, incrementing e3Id mitigates manipulation.
        // The seed is used solely for weighted sortition, not for cryptographic key generation.
        uint256 seed = uint256(keccak256(abi.encode(block.prevrandao, e3Id)));

        e3Payments[e3Id] = e3Fee;
        _e3FeeTokens[e3Id] = feeToken;
        _e3ProtocolShareBps[e3Id] = _pricingConfig.protocolShareBps;
        _e3ProtocolTreasury[e3Id] = _pricingConfig.protocolTreasury;

        // Initialize E3 Lifecycle
        _e3Stages[e3Id] = E3Stage.Requested;
        _e3Requesters[e3Id] = msg.sender;

        // the compute deadline is end of input window + compute window
        _e3Deadlines[e3Id].computeDeadline =
            requestParams.inputWindow[1] +
            _timeoutConfig.computeWindow;

        e3.seed = seed;
        e3.committeeSize = requestParams.committeeSize;
        // store request timepoint as `block.timestamp` (EIP-6372
        // timestamp clock) so it matches the registry's `c.requestBlock`
        // and ticket-token `getPastVotes` lookups across L2s (e.g.
        // Arbitrum where `block.number` ticks every ~250ms and is
        // inconsistent with consensus-time deadlines).
        e3.requestBlock = block.timestamp;
        e3.inputWindow = requestParams.inputWindow;
        e3.e3Program = requestParams.e3Program;
        e3.paramSet = requestParams.paramSet;
        e3.customParams = requestParams.customParams;
        e3.proofAggregationEnabled = requestParams.proofAggregationEnabled;
        e3.requester = msg.sender;

        bytes memory e3ProgramParams = paramSetRegistry[requestParams.paramSet];

        bytes32 encryptionSchemeId = requestParams.e3Program.validate(
            e3Id,
            seed,
            e3ProgramParams,
            requestParams.computeProviderParams,
            requestParams.customParams
        );
        IDecryptionVerifier decryptionVerifier = decryptionVerifiers[
            encryptionSchemeId
        ];

        require(
            address(decryptionVerifier) != address(0),
            InvalidEncryptionScheme(encryptionSchemeId)
        );

        IPkVerifier pkVerifier = pkVerifiers[encryptionSchemeId];
        require(
            address(pkVerifier) != address(0),
            InvalidEncryptionScheme(encryptionSchemeId)
        );

        e3.encryptionSchemeId = encryptionSchemeId;
        e3.decryptionVerifier = decryptionVerifier;
        e3.pkVerifier = pkVerifier;
        // CEI: write all state before external calls below
        e3s[e3Id] = e3;

        // Transfer fee after all validations and state changes
        feeToken.safeTransferFrom(msg.sender, address(this), e3Fee);

        require(
            ciphernodeRegistry.requestCommittee(e3Id, seed, threshold),
            CommitteeSelectionFailed()
        );

        emit E3Requested(e3Id, e3, requestParams.e3Program);
        emit E3StageChanged(e3Id, E3Stage.None, E3Stage.Requested);
    }

    /// @inheritdoc IInterfold
    function publishCiphertextOutput(
        uint256 e3Id,
        bytes calldata ciphertextOutput,
        bytes calldata proof
    ) external returns (bool success) {
        E3 memory e3 = getE3(e3Id);

        E3Stage current = _e3Stages[e3Id];
        E3Deadlines memory deadlines = _e3Deadlines[e3Id];
        // Validation gates are delegated to {InterfoldPricing} (external
        // library link) to keep the deployed Interfold runtime bytecode under
        // the EIP-170 24,576-byte cap. Revert selectors are preserved via
        // shared {IInterfold} error declarations.
        InterfoldPricing.validatePublishCiphertext(
            e3Id,
            uint8(current),
            deadlines.computeDeadline,
            e3.inputWindow[1],
            e3.ciphertextOutput,
            block.timestamp
        );

        bytes32 ciphertextOutputHash = keccak256(ciphertextOutput);
        e3s[e3Id].ciphertextOutput = ciphertextOutputHash;
        _e3Stages[e3Id] = E3Stage.CiphertextReady;
        _e3Deadlines[e3Id].decryptionDeadline =
            block.timestamp +
            _timeoutConfig.decryptionWindow;

        (success) = e3.e3Program.verify(e3Id, ciphertextOutputHash, proof);
        require(success, InvalidOutput(ciphertextOutput));

        emit CiphertextOutputPublished(e3Id, ciphertextOutput);
        emit E3StageChanged(
            e3Id,
            E3Stage.KeyPublished,
            E3Stage.CiphertextReady
        );
    }

    /// @inheritdoc IInterfold
    function publishPlaintextOutput(
        uint256 e3Id,
        bytes calldata plaintextOutput,
        bytes calldata proof
    ) external returns (bool success) {
        E3 memory e3 = getE3(e3Id);

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

        if (e3.proofAggregationEnabled) {
            require(proof.length > 0, ProofRequired());
            // Reaching `CiphertextReady` implies the committee was published, so
            // `getCommitteeHash` is guaranteed non-zero here; the registry still
            // reverts with `CommitteeNotPublished` if that invariant ever breaks.
            bytes32 committeeHash = ciphernodeRegistry.getCommitteeHash(e3Id);
            // Wrapper reverts on any failure with a typed error (no `bool false`).
            e3.decryptionVerifier.verify(
                e3Id,
                ciphernodeRegistry.rootAt(e3Id),
                ciphernodeRegistry.getCommitteeNodes(e3Id),
                e3.ciphertextOutput,
                e3.committeePublicKey,
                keccak256(plaintextOutput),
                committeeHash,
                proof
            );
            success = true;
        } else {
            success = true;
        }

        _distributeRewards(e3Id);

        emit PlaintextOutputPublished(e3Id, plaintextOutput, proof);
        emit E3StageChanged(e3Id, E3Stage.CiphertextReady, E3Stage.Complete);
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
        (address[] memory activeNodes, ) = ciphernodeRegistry
            .getActiveCommitteeNodes(e3Id);
        uint256 activeLength = activeNodes.length;

        uint256 totalAmount = e3Payments[e3Id];
        e3Payments[e3Id] = 0;

        // Use the per-E3 fee token (not the global one, which may have been rotated)
        IERC20 paymentToken = _e3FeeTokens[e3Id];

        if (totalAmount == 0) {
            e3RefundManager.distributeSlashedFundsOnSuccess(
                e3Id,
                activeNodes,
                paymentToken
            );
            return;
        }

        // If all committee members were expelled (all malicious), refund the
        // requester in full — the protocol should not profit from a
        // compromised E3.
        if (activeLength == 0) {
            address requester = _e3Requesters[e3Id];
            if (requester != address(0)) {
                paymentToken.safeTransfer(requester, totalAmount);
            }
            e3RefundManager.distributeSlashedFundsOnSuccess(
                e3Id,
                activeNodes,
                paymentToken
            );
            return;
        }

        // Split between protocol treasury and CN rewards
        uint256 protocolAmount = 0;
        uint16 _protocolShareBps = _e3ProtocolShareBps[e3Id];
        address _protocolTreasury = _e3ProtocolTreasury[e3Id];
        if (_protocolShareBps > 0 && _protocolTreasury != address(0)) {
            protocolAmount =
                (totalAmount * uint256(_protocolShareBps)) /
                uint256(BPS_BASE);
            if (protocolAmount > 0) {
                _pendingTreasury[_protocolTreasury][
                    paymentToken
                ] += protocolAmount;
                emit TreasuryCredited(
                    e3Id,
                    _protocolTreasury,
                    paymentToken,
                    protocolAmount
                );
            }
        }

        uint256 cnAmount = totalAmount - protocolAmount;

        uint256[] memory amounts = InterfoldPricing.computeNodeAmounts(
            cnAmount,
            activeLength,
            e3Id
        );

        // Credit each node's pull-payment balance (instead of pushing via bondingRegistry)
        _creditRewards(e3Id, activeNodes, amounts, paymentToken);

        emit RewardsDistributed(e3Id, activeNodes, amounts);

        e3RefundManager.distributeSlashedFundsOnSuccess(
            e3Id,
            activeNodes,
            paymentToken
        );
    }

    /// @notice Credits per-node reward balances and emits `RewardCredited`.
    function _creditRewards(
        uint256 e3Id,
        address[] memory nodes,
        uint256[] memory amounts,
        IERC20 token
    ) private {
        uint256 n = nodes.length;
        for (uint256 i = 0; i < n; i++) {
            uint256 a = amounts[i];
            if (a == 0) continue;
            _pendingRewards[e3Id][nodes[i]] += a;
            emit RewardCredited(e3Id, nodes[i], token, a);
        }
    }

    /// @notice Retrieves the honest committee nodes for a given E3.
    /// @dev Uses active committee view from the registry (which excludes expelled/slashed members).
    /// @param e3Id The ID of the E3.
    /// @return honestNodes An array of addresses of honest committee nodes.
    function _getHonestNodes(
        uint256 e3Id
    ) private view returns (address[] memory) {
        FailureReason reason = _e3FailureReasons[e3Id];

        // Early failures have no committee
        if (
            reason == FailureReason.CommitteeFormationTimeout ||
            reason == FailureReason.InsufficientCommitteeMembers
        ) {
            return new address[](0);
        }

        // Use active committee nodes (already filtered by expulsion)
        try ciphernodeRegistry.getActiveCommitteeNodes(e3Id) returns (
            address[] memory nodes,
            uint256[] memory
        ) {
            return nodes;
        } catch {
            return new address[](0); // Committee not published (DKG failed)
        }
    }

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
        bondingRegistry = _bondingRegistry;
        emit BondingRegistrySet(address(_bondingRegistry));
    }

    /// @inheritdoc IInterfold
    function setFeeToken(IERC20 _feeToken) public onlyOwner {
        require(
            address(_feeToken) != address(0) && _feeToken != feeToken,
            InvalidFeeToken(_feeToken)
        );
        feeToken = _feeToken;
        // Auto allow-list the active fee token so `request()` keeps working
        // after a rotation. Owner can still explicitly toggle later.
        if (!_feeTokenAllowed[_feeToken]) {
            _feeTokenAllowed[_feeToken] = true;
            emit FeeTokenAllowed(_feeToken, true);
        }
        emit FeeTokenSet(address(_feeToken));
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
    function registerE3Program(IE3Program e3Program) external {
        require(
            !e3Programs[e3Program],
            ModuleAlreadyEnabled(address(e3Program))
        );
        e3Programs[e3Program] = true;
        emit E3ProgramRegistered(e3Program);
    }

    /// @inheritdoc IInterfold
    function setDecryptionVerifier(
        bytes32 encryptionSchemeId,
        IDecryptionVerifier decryptionVerifier
    ) external onlyOwner {
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
        require(
            address(pkVerifier) != address(0) &&
                pkVerifiers[encryptionSchemeId] != pkVerifier,
            InvalidEncryptionScheme(encryptionSchemeId)
        );
        pkVerifiers[encryptionSchemeId] = pkVerifier;
        emit PkVerifierSet(encryptionSchemeId, pkVerifier);
    }

    /// @inheritdoc IInterfold
    function disableEncryptionScheme(
        bytes32 encryptionSchemeId
    ) external onlyOwner {
        require(
            decryptionVerifiers[encryptionSchemeId] !=
                IDecryptionVerifier(address(0)),
            InvalidEncryptionScheme(encryptionSchemeId)
        );
        decryptionVerifiers[encryptionSchemeId] = IDecryptionVerifier(
            address(0)
        );
        emit EncryptionSchemeDisabled(encryptionSchemeId);
    }

    /// @notice Registers or updates ABI-encoded BFV parameters for a param
    ///         set index.
    /// @dev Owner may overwrite an existing slot. The previous value
    ///      is emitted via {ParamSetUpdated} so off-chain consumers can
    ///      reconcile state. Fresh registrations emit {ParamSetRegistered}.
    /// @param paramSet The param set index (0 = Insecure512, 1 = Secure8192, ...).
    /// @param encodedParams ABI-encoded BFV parameters (degree, plaintext_modulus, moduli[]).
    function setParamSet(
        uint8 paramSet,
        bytes calldata encodedParams
    ) external onlyOwner {
        require(encodedParams.length > 0, "Empty params");
        bytes memory previous = paramSetRegistry[paramSet];
        paramSetRegistry[paramSet] = encodedParams;
        if (previous.length == 0) {
            emit ParamSetRegistered(paramSet, encodedParams);
        } else {
            emit ParamSetUpdated(paramSet, previous, encodedParams);
        }
    }

    /// @notice Sets the E3 Refund Manager contract address
    /// @param _e3RefundManager The new E3 Refund Manager contract address
    function setE3RefundManager(
        IE3RefundManager _e3RefundManager
    ) public onlyOwner {
        require(
            address(_e3RefundManager) != address(0),
            "Invalid E3RefundManager address"
        );
        e3RefundManager = _e3RefundManager;
        emit E3RefundManagerSet(address(_e3RefundManager));
    }

    /// @notice Sets the Slashing Manager contract address
    /// @param _slashingManager The new Slashing Manager contract address
    function setSlashingManager(
        ISlashingManager _slashingManager
    ) external onlyOwner {
        require(
            address(_slashingManager) != address(0),
            "Invalid SlashingManager address"
        );
        slashingManager = _slashingManager;
        emit SlashingManagerSet(address(_slashingManager));
    }

    /// @notice Process a failed E3 and calculate refunds
    /// @dev Can be called by anyone once E3 is in failed state.
    ///      Uses the per-E3 feeToken stored at request time (survives global token rotation).
    /// @param e3Id The ID of the failed E3
    function processE3Failure(uint256 e3Id) external {
        E3Stage stage = _e3Stages[e3Id];
        require(stage == E3Stage.Failed, E3NotFailed(e3Id));

        uint256 payment = e3Payments[e3Id];
        require(payment > 0, NoPaymentToRefund(e3Id));
        e3Payments[e3Id] = 0; // Prevent double processing

        address[] memory honestNodes = _getHonestNodes(e3Id);

        IERC20 paymentToken = _e3FeeTokens[e3Id];

        paymentToken.safeTransfer(address(e3RefundManager), payment);
        e3RefundManager.calculateRefund(
            e3Id,
            payment,
            honestNodes,
            paymentToken
        );

        emit E3FailureProcessed(e3Id, payment, honestNodes.length);
    }

    /// @inheritdoc IInterfold
    function escrowSlashedFunds(
        uint256 e3Id,
        uint256 amount
    ) external onlySlashingManager {
        e3RefundManager.escrowSlashedFunds(e3Id, amount);
        emit SlashedFundsEscrowed(e3Id, amount);
    }

    /// @inheritdoc IInterfold
    function onCommitteeFinalized(
        uint256 e3Id
    ) external onlyCiphernodeRegistry {
        // Update E3 lifecycle stage - committee finalized, DKG starting
        E3Stage current = _e3Stages[e3Id];
        if (current != E3Stage.Requested) {
            revert InvalidStage(e3Id, E3Stage.Requested, current);
        }
        _e3Stages[e3Id] = E3Stage.CommitteeFinalized;
        _e3Deadlines[e3Id].dkgDeadline =
            block.timestamp +
            _timeoutConfig.dkgWindow;

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
    ) external onlyCiphernodeRegistry {
        E3 storage e3 = e3s[e3Id];
        E3Stage current = _e3Stages[e3Id];
        if (current != E3Stage.CommitteeFinalized) {
            revert InvalidStage(e3Id, E3Stage.CommitteeFinalized, current);
        }

        _e3Stages[e3Id] = E3Stage.KeyPublished;
        e3.committeePublicKey = committeePublicKey;

        emit CommitteeFormed(e3Id);
        emit E3StageChanged(
            e3Id,
            E3Stage.CommitteeFinalized,
            E3Stage.KeyPublished
        );
    }

    /// @inheritdoc IInterfold
    function onE3Failed(
        uint256 e3Id,
        uint8 reason
    ) external onlyCiphernodeRegistryOrSlashingManager {
        require(
            reason > 0 && reason <= uint8(FailureReason._MAX_FAILURE_REASON),
            "Invalid failure reason"
        );
        E3Stage current = _e3Stages[e3Id];
        InterfoldPricing.validateMarkFailedStage(e3Id, uint8(current));
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
    ///      against L2 sequencer-hiccup races without giving up liveness.
    /// @param e3Id The E3 ID
    /// @return reason The failure reason
    function markE3Failed(
        uint256 e3Id
    ) external returns (FailureReason reason) {
        E3Stage current = _e3Stages[e3Id];

        InterfoldPricing.validateMarkFailedStage(e3Id, uint8(current));

        bool canFail;
        uint256 deadline;
        (canFail, reason, deadline) = _checkFailureCondition(e3Id, current);
        if (!canFail) revert FailureConditionNotMet(e3Id);

        // enforce caller restriction inside the grace window.
        uint256 grace = markFailedGracePeriod;
        if (grace > 0) {
            uint256 graceEnds = deadline + grace;
            if (
                block.timestamp < graceEnds &&
                msg.sender != _e3Requesters[e3Id] &&
                msg.sender != owner() &&
                !ciphernodeRegistry.isCommitteeMember(e3Id, msg.sender)
            ) {
                revert MarkE3FailedInGracePeriod(e3Id, graceEnds);
            }
        }

        _markE3FailedWithReason(e3Id, current, reason);
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
        (deadline, reason) = _stageDeadlineAndReason(e3Id, stage);
        canFail = deadline != 0 && block.timestamp > deadline;
        if (!canFail) reason = FailureReason.None;
    }

    /// @dev Returns the deadline and matching failure reason for `stage`.
    ///      A `deadline == 0` (unknown stage) signals "no failure possible".
    function _stageDeadlineAndReason(
        uint256 e3Id,
        E3Stage stage
    ) private view returns (uint256 deadline, FailureReason reason) {
        if (stage == E3Stage.Requested)
            return (
                ciphernodeRegistry.getCommitteeDeadline(e3Id),
                FailureReason.CommitteeFormationTimeout
            );
        E3Deadlines memory d = _e3Deadlines[e3Id];
        if (stage == E3Stage.CommitteeFinalized)
            return (d.dkgDeadline, FailureReason.DKGTimeout);
        if (stage == E3Stage.KeyPublished)
            return (d.computeDeadline, FailureReason.ComputeTimeout);
        if (stage == E3Stage.CiphertextReady)
            return (d.decryptionDeadline, FailureReason.DecryptionTimeout);
        return (0, FailureReason.None);
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

    /// @notice Set timeout configuration
    /// @param config The new timeout config
    function setTimeoutConfig(
        E3TimeoutConfig calldata config
    ) external onlyOwner {
        _setTimeoutConfig(config);
    }

    /// @notice Internal function to set timeout config
    function _setTimeoutConfig(E3TimeoutConfig calldata config) internal {
        InterfoldPricing.validateTimeoutConfig(config, MAX_TIMEOUT_WINDOW);
        _timeoutConfig = config;
        emit TimeoutConfigUpdated(config);
    }

    /// @inheritdoc IInterfold
    function setCommitteeThresholds(
        CommitteeSize size,
        uint32[2] calldata threshold
    ) external onlyOwner {
        PricingConfig memory pc = _pricingConfig;
        InterfoldPricing.validateCommitteeThresholds(
            threshold,
            pc.minCommitteeSize,
            pc.minThreshold
        );
        committeeThresholds[size] = threshold;
        emit CommitteeThresholdsUpdated(size, threshold);
    }

    /// @inheritdoc IInterfold
    function setPricingConfig(
        PricingConfig calldata config
    ) external onlyOwner {
        // Validation is delegated to {InterfoldPricing.validatePricingConfig}
        // (external library link) to keep the deployed Interfold runtime
        // bytecode under the EIP-170 24,576-byte cap. Revert selectors are
        // preserved via shared {IInterfold} error declarations.
        InterfoldPricing.validatePricingConfig(config);
        _pricingConfig = config;
        emit PricingConfigUpdated(config);
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
        require(
            paramSetRegistry[requestParams.paramSet].length > 0,
            "BFV param set not registered"
        );
        uint32[2] memory threshold = committeeThresholds[
            requestParams.committeeSize
        ];
        PricingConfig memory pc = _pricingConfig;
        InterfoldPricing.validateQuoteThresholds(
            threshold,
            uint8(requestParams.committeeSize),
            pc.minCommitteeSize,
            pc.minThreshold
        );

        // Pure fee math is delegated to {InterfoldPricing.quote} (external
        // library link) to keep the deployed Interfold runtime bytecode under
        // the EIP-170 24,576-byte cap. Inputs are snapshotted into calldata
        // for the call site; behaviour and revert selectors match the
        // original inlined implementation.
        fee = InterfoldPricing.quote(
            _pricingConfig,
            _timeoutConfig,
            ciphernodeRegistry.sortitionSubmissionWindow(),
            threshold,
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
        uint256 totalClaimed;
        for (uint256 i = 0; i < len; i++) {
            totalClaimed += _claimReward(e3Ids[i], msg.sender);
        }
        require(totalClaimed > 0, NothingToClaim());
    }

    /// @notice Internal helper: drains the caller's pull balance for one E3
    ///         and emits `RewardClaimed`. Returns 0 if nothing to claim
    ///         (so batch calls don't revert on partially-empty inputs).
    function _claimReward(
        uint256 e3Id,
        address account
    ) internal returns (uint256 amount) {
        amount = _pendingRewards[e3Id][account];
        if (amount == 0) return 0;
        _pendingRewards[e3Id][account] = 0;
        IERC20 token = _e3FeeTokens[e3Id];
        token.safeTransfer(account, amount);
        emit RewardClaimed(e3Id, account, token, amount);
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
        amount = _pendingTreasury[msg.sender][token];
        require(amount > 0, NothingToClaim());
        _pendingTreasury[msg.sender][token] = 0;
        token.safeTransfer(msg.sender, amount);
        emit TreasuryClaimed(msg.sender, token, amount);
    }

    /// @inheritdoc IInterfold
    function pendingTreasuryClaim(
        address treasury,
        IERC20 token
    ) external view returns (uint256) {
        return _pendingTreasury[treasury][token];
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
    uint256[50] private __gap;
}
