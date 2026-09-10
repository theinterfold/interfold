// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity >=0.8.27;

import { IRiscZeroVerifier } from "risc0/IRiscZeroVerifier.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { IE3Program } from "@interfold/contracts/contracts/interfaces/IE3Program.sol";
import { IInterfold } from "@interfold/contracts/contracts/interfaces/IInterfold.sol";
import { ICiphernodeRegistry } from "@interfold/contracts/contracts/interfaces/ICiphernodeRegistry.sol";
import { E3 } from "@interfold/contracts/contracts/interfaces/IE3.sol";
import { Risc0ComputeProof } from "@interfold/contracts/contracts/lib/Risc0ComputeProof.sol";
import { LazyIMTData, InternalLazyIMT } from "@zk-kit/lazy-imt.sol/InternalLazyIMT.sol";
import { SNARK_SCALAR_FIELD } from "@zk-kit/lazy-imt.sol/Constants.sol";
import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IHonkVerifier } from "./interfaces/IHonkVerifier.sol";
import { IVotesToken } from "./interfaces/IVotesToken.sol";
import { IERC6372Clock } from "./interfaces/IERC6372Clock.sol";
import { IDataAvailabilityVerifier } from "@interfold/contracts/contracts/interfaces/IDataAvailabilityVerifier.sol";

interface IInterfoldProgramRegistry {
  function e3Programs(IE3Program e3Program) external view returns (bool);
}

interface IInterfoldRegistryView {
  function ciphernodeRegistry() external view returns (ICiphernodeRegistry);
}

contract CRISPProgram is IE3Program, Ownable, EIP712 {
  using InternalLazyIMT for LazyIMTData;

  /// @notice Enum to represent credit modes
  enum CreditMode {
    /// @notice Everyone has constant credits
    CONSTANT,
    /// @notice Credits are custom (can be based on token balance, etc)
    CUSTOM
  }

  /// @notice Where the eligible voter set for a round comes from.
  /// @dev Two sources with opposite economics. TOKEN derives the electorate from balances at a
  /// snapshot: the coordinator enumerates holders, which is expensive and needs an indexer, but it
  /// is the only way to answer "everyone holding this token". BY_REQUESTER asks the requesting
  /// contract, which already knows its own membership — a game roster, an allowlisted cohort, a
  /// committee — so nothing is enumerated and no indexer is involved.
  ///
  /// Declared explicitly rather than inferred. A coordinator that probed every requester and
  /// silently fell back on failure would turn a broken census provider into a token vote with the
  /// wrong electorate, and nothing would error.
  ///
  /// Required, not optional: params must carry it. Making it defaultable would mean a caller that
  /// forgot it silently got token discovery, which is the same silent-wrong-electorate failure one
  /// level up.
  enum CensusMode {
    /// @notice Derived from token balances by the coordinator. The default.
    TOKEN,
    /// @notice Supplied by the requester via `getCensus(uint256 e3Id) returns (address[])`.
    BY_REQUESTER,
    /// @notice Read from the token by this contract, one input at a time. No list is enumerated
    /// and no root is posted, so there is no census producer to trust. `publishInput` calls
    /// `getPastVotes` for the slot and passes the result to the circuit as a public input, which
    /// is why this mode uses the `crisp_onchain` verifier rather than the `crisp` one.
    ONCHAIN
  }

  /// @notice Progress of one proof-bound input while its ciphertext becomes available.
  enum InputStatus {
    NONE,
    COMMITTED,
    PUBLISHED
  }

  /// @notice Struct to store all data related to a voting round
  struct RoundData {
    uint256 merkleRoot;
    bytes32 paramsHash;
    mapping(address slot => uint40 index) voteSlots;
    /// @notice The proven ciphertext commitment of every input, keyed by slot and tree index.
    /// @dev Keyed by both so a parent lookup for the wrong slot returns zero and is refused: it
    /// costs no more storage than a single-key map and removes a separate same-slot check.
    ///
    /// A history rather than one commitment per slot. An input names the entry it extends, and
    /// this contract cannot tell whether the bytes published with an entry deserialize to the
    /// ciphertext its commitment describes — only the Secure Process can, once the input window
    /// closes. Keeping only the newest commitment would therefore let anyone leave a slot whose
    /// head nobody but they can open, and a slot that cannot be masked is a slot whose every later
    /// input is provably its owner voting again. With the history, an entry like that is simply
    /// never extended: the next input names the same parent, and masking continues.
    mapping(address slot => mapping(uint40 index => bytes32 commitment)) inputCommitment;
    /// @notice Leaves already reserved in this round's input tree.
    /// @dev A replay guard, not a uniqueness requirement on ballots. The proof constrains the
    /// commitment, not who submits it, so anyone who observes a committed input can resubmit the
    /// identical calldata: the proof still verifies and {_processVote} appends again. The tally
    /// does not change — the replay names the same parent as the original, which is no longer the
    /// head, so the Secure Process drops it — but the tree is fixed-depth, so enough replays reach
    /// capacity and every later input reverts, denying the round.
    ///
    /// Keyed by the leaf rather than the proof because the leaf is exactly what an append adds.
    /// Two genuinely distinct inputs differ in bytes, commitment, slot or parent, so they differ
    /// here; only a byte-identical resubmission collides.
    mapping(uint256 leaf => bool) appendedLeaf;
    /// @notice Proofs accepted before their ciphertexts receive a verified DA receipt.
    /// @dev The key binds every value needed to reproduce the final input leaf. A receipt can
    /// publish only the exact tuple whose Noir proof was accepted in the first transaction.
    mapping(bytes32 inputId => InputStatus status) inputStatus;
    /// @notice Reserved tree index plus one for every accepted input proof.
    mapping(bytes32 inputId => uint40 indexPlusOne) inputIndexPlusOne;
    /// @notice Inputs whose proof is accepted but whose Avail receipt is not yet verified.
    uint40 pendingInputCount;
    LazyIMTData votes;
    uint256 numOptions;
    CreditMode creditMode;
    CensusMode censusMode;
    /// @notice The token that voting power is read from. Only used by `CensusMode.ONCHAIN`.
    address token;
    /// @notice The smallest voting power that may cast an input. Only used by
    /// `CensusMode.ONCHAIN`, where eligibility is checked per input instead of by a census.
    uint256 minVotingPower;
    /// @notice Credits given to each eligible voter under `CreditMode.CONSTANT`.
    uint256 credits;
    /// @notice The timepoint that voting power is read at, in the ERC-6372 clock units of the
    /// token. Recorded when the round is requested, so it is the same for every input.
    uint48 snapshot;
    /// @notice Divides raw token voting power into the units the ballot is encoded in. Only used
    /// by `CensusMode.ONCHAIN`. Never zero for such a round.
    uint256 votingPowerDivisor;
  }

  // Constants
  /// @notice Encryption scheme ID used for the CRISP program.
  bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");
  /// @notice The depth of the input Merkle tree.
  uint8 public constant TREE_DEPTH = 20;
  /// @notice Minimum time available to create new input commitments after a worst-case key setup.
  uint256 public constant MIN_VOTING_DURATION = 1 hours;
  /// @notice Number of leading plaintext coefficients that carry the vote payload.
  /// @dev Must stay aligned with `@crisp-e3/sdk` and `crisp_utils` (`MAX_MSG_NON_ZERO_COEFFS`).
  /// The remaining coefficients up to the BFV degree are zero padding.
  uint256 constant MAX_MSG_NON_ZERO_COEFFS = 100;
  /// @notice Maximum number of vote options a round may configure.
  /// @dev Bounded by the Noir circuit, which asserts `num_options <= MAX_OPTIONS`
  /// (`circuits/lib/src/constants.nr`). A round above this accepts no ballot, because every
  /// vote proof fails. Must stay aligned with the SDK constant of the same name.
  uint256 constant MAX_VOTE_OPTIONS = 10;
  /// @notice Largest `decimals` a divisor can be derived from: `10 ** 77` is the last power of ten
  /// that fits in a uint256.
  uint8 constant MAX_DERIVABLE_DECIMALS = 78;
  // State variables
  IInterfold public interfold;
  IRiscZeroVerifier public risc0Verifier;
  bytes32 public imageId;
  /// @notice Verifies ballots for the census modes that prove membership of a Merkle tree.
  IHonkVerifier private immutable honkVerifier;
  /// @notice Verifies ballots for `CensusMode.ONCHAIN`, whose circuit has no Merkle inputs and
  /// takes voting power as a public input instead.
  IHonkVerifier private immutable onchainHonkVerifier;
  /// @notice Frozen receipt verifier for every large object accepted by this program.
  IDataAvailabilityVerifier public immutable dataAvailabilityVerifier;
  /// @notice Tail of the Interfold input window reserved for DA finalization.
  /// @dev New proofs close this many seconds before the protocol input deadline. Existing
  /// commitments can still receive a VectorX proof during the reserved tail.
  uint256 public immutable availabilityFinalizationWindow;
  /// @notice Service that confirms it durably received a ciphertext before its proof is accepted.
  /// @dev The later VectorX receipt remains the authority for data availability. This signature
  /// only prevents a caller from committing a hash while withholding the bytes from the service.
  address public immutable inputAvailabilitySigner;

  /// @notice Maximum lifetime of an input availability promise.
  /// @dev The service starts this period after it validates and stores the complete ciphertext.
  uint64 public constant INPUT_AVAILABILITY_ATTESTATION_TTL = 10 minutes;

  bytes32 public constant INPUT_AVAILABILITY_TYPEHASH = keccak256("InputAvailability(uint256 e3Id,bytes32 inputId,uint64 expiresAt)");

  /// @notice The EIP-712 type of the message a voter signs to authorise one ballot.
  /// @dev The digest binds the signature to the round, the slot, and this exact ciphertext. The
  /// chain id and this contract address come from the EIP-712 domain, so a signature cannot be
  /// replayed onto another round, another slot, another ballot, or another deployment.
  bytes32 private constant BALLOT_TYPEHASH = keccak256("Ballot(uint256 e3Id,address slot,bytes32 ciphertextCommitment)");

  // Mappings
  mapping(uint256 e3Id => RoundData) e3Data;

  // Errors
  error CallerNotAuthorized();
  error E3AlreadyInitialized();
  error InterfoldAddressZero();
  error InterfoldAlreadyBound();
  error InterfoldNotContract();
  error ProgramNotRegistered();
  error Risc0VerifierAddressZero();
  error InvalidHonkVerifier();
  error EmptyInputData();
  error InvalidNoirProof();
  error InvalidMerkleRoot();
  error MerkleRootAlreadySet();
  error InvalidTallyLength();
  /// @notice A requester-supplied census names who may vote, not how much each vote weighs, so it
  /// only has meaning when every voter carries the same credits.
  error CensusModeRequiresConstantCredits();
  /// @notice `CensusMode.ONCHAIN` reads voting power from a token, so it cannot run without one
  /// that answers `getPastVotes`.
  error CensusModeRequiresToken();
  /// @notice An `ONCHAIN` round with constant credits must grant a non-zero allowance, or it
  /// bounds every ballot to zero and can only accept masks.
  error InvalidCredits();
  /// @notice The slot holds less voting power than the round requires, so it cannot be written to.
  /// @dev Raised for mask inputs as well as real votes. Under `CensusMode.ONCHAIN` this check
  /// replaces the Merkle membership proof that gates both branches in the other modes.
  error SlotNotEligible();
  error InvalidCensusMode();

  /// @notice A token reports more decimals than a divisor can be derived from.
  /// @dev `10 ** (decimals - 1)` must fit in a uint256. Pass an explicit divisor for such a token.
  error UnsupportedTokenDecimals(uint8 decimals);

  /// @notice An ONCHAIN round's floor is below one ballot unit.
  /// @dev `minVotingPower` must be at least the divisor, so every slot that clears the floor
  /// carries at least one unit of weight. Below that, a slot could be eligible to write yet scale
  /// to zero — able to publish, but unable to carry any weight, which is disenfranchisement that
  /// nothing on-chain would report.
  error MinVotingPowerBelowScale();
  /// @notice An input names a parent this slot never wrote to.
  /// @dev Includes an index belonging to another slot, which the per-slot commitment map reads as
  /// absent. Name no parent instead when there is nothing to extend.
  error UnknownParentInput(uint40 parentIndex);

  /// @notice Thrown when an input identical to one already published is submitted again.
  error InputAlreadyPublished(uint256 leaf);
  error InputAlreadyCommitted(bytes32 inputId);
  error InputNotCommitted(bytes32 inputId);
  error InvalidInputAvailabilityAttestation();
  error InputAvailabilityAttestationExpired(uint64 expiresAt);
  error InputAvailabilitySignerAddressZero();
  error InputAvailabilityPending(uint40 count);
  error SlotIsEmpty();
  error MerkleRootNotSet();
  error InvalidNumOptions();
  error InputDeadlinePassed(uint256 e3Id, uint256 deadline);
  error InputCommitmentDeadlinePassed(uint256 e3Id, uint256 deadline);
  error InputWindowTooShort(uint256 e3Id, uint256 duration, uint256 required);
  error VotingWindowTooShort(uint256 e3Id, uint256 votingStartsAt, uint256 commitmentDeadline, uint256 required);
  error KeyNotPublished(uint256 e3Id);
  error E3NotAcceptingInputs(uint256 e3Id);
  error InvalidComputeContext();
  error InvalidDataAvailabilityVerifier();
  error DataAvailabilityHashMismatch(bytes32 expected, bytes32 actual);

  // Events
  event InterfoldBound(address indexed interfold);

  /// @notice A valid ballot proof was accepted before its ciphertext DA receipt was ready.
  event InputCommitted(
    uint256 indexed e3Id,
    bytes32 indexed inputId,
    address indexed slotAddress,
    bytes32 encryptedVoteCommitment,
    bytes32 encryptedVoteHash,
    uint40 parentIndexPlusOne,
    uint40 index
  );

  /// @notice A committed ciphertext received a verified data-availability receipt.
  /// @dev The event carries the values needed to retrieve and validate the exact bytes. The slot,
  /// commitment, hash, parent, and reserved index were already exposed by {InputCommitted}.
  event InputPublished(
    uint256 indexed e3Id,
    address indexed slotAddress,
    bytes32 encryptedVoteCommitment,
    bytes32 encryptedVoteHash,
    uint32 availabilityBlock,
    uint128 availabilityLeafIndex,
    uint256 index,
    uint40 parentIndexPlusOne
  );

  /// @notice Initialize the contract without an Interfold controller.
  /// @dev The owner binds the controller after Interfold registers this program.
  /// @param _initialOwner The account that can configure and bind this program.
  /// @param _risc0Verifier The RISC Zero verifier address
  /// @param _honkVerifier The honk verifier address
  /// @param _imageId The image ID for the guest program
  constructor(
    address _initialOwner,
    IRiscZeroVerifier _risc0Verifier,
    IHonkVerifier _honkVerifier,
    IHonkVerifier _onchainHonkVerifier,
    IDataAvailabilityVerifier _dataAvailabilityVerifier,
    uint256 _availabilityFinalizationWindow,
    address _inputAvailabilitySigner,
    bytes32 _imageId
  ) Ownable(_initialOwner) EIP712("CRISP", "1") {
    if (address(_risc0Verifier) == address(0)) revert Risc0VerifierAddressZero();
    if (address(_honkVerifier) == address(0)) revert InvalidHonkVerifier();
    if (address(_onchainHonkVerifier) == address(0)) revert InvalidHonkVerifier();
    if (address(_dataAvailabilityVerifier).code.length == 0) revert InvalidDataAvailabilityVerifier();

    risc0Verifier = _risc0Verifier;
    honkVerifier = _honkVerifier;
    onchainHonkVerifier = _onchainHonkVerifier;
    dataAvailabilityVerifier = _dataAvailabilityVerifier;
    availabilityFinalizationWindow = _availabilityFinalizationWindow;
    if (_inputAvailabilitySigner == address(0)) revert InputAvailabilitySignerAddressZero();
    inputAvailabilitySigner = _inputAvailabilitySigner;
    imageId = _imageId;
  }

  /// @notice Bind this program to its permanent Interfold controller.
  /// @dev Interfold must register this program before the owner calls this function.
  /// @param _interfold The Interfold controller that registered this program.
  function bindInterfold(IInterfold _interfold) external onlyOwner {
    if (address(interfold) != address(0)) revert InterfoldAlreadyBound();
    if (address(_interfold) == address(0)) revert InterfoldAddressZero();
    if (address(_interfold).code.length == 0) revert InterfoldNotContract();
    if (!IInterfoldProgramRegistry(address(_interfold)).e3Programs(IE3Program(address(this)))) {
      revert ProgramNotRegistered();
    }

    interfold = _interfold;
    emit InterfoldBound(address(_interfold));
  }

  /// @notice The digest a voter signs to authorise one ballot.
  /// @dev Computed for every input, and for mask inputs as well as real votes. The circuit ignores
  /// it on the mask branch, but the contract must not skip it: a digest that were computed only
  /// for real votes would let an observer tell the two apart on-chain, which is exactly what mask
  /// inputs exist to prevent.
  /// @param e3Id The E3 the ballot belongs to.
  /// @param slot The slot address the ballot is written to.
  /// @param ciphertextCommitment The commitment to the ballot ciphertext.
  /// @return The EIP-712 digest.
  function ballotDigest(uint256 e3Id, address slot, bytes32 ciphertextCommitment) public view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(BALLOT_TYPEHASH, e3Id, slot, ciphertextCommitment)));
  }

  /// @notice Sets the Merkle root for an E3 program. Can only be set once.
  /// @param _e3Id The E3 program ID
  /// @param _root The Merkle root to set.
  function setMerkleRoot(uint256 _e3Id, uint256 _root) external onlyOwner {
    if (_root == 0) revert InvalidMerkleRoot();
    if (e3Data[_e3Id].merkleRoot != 0) revert MerkleRootAlreadySet();

    e3Data[_e3Id].merkleRoot = _root;
  }

  /// @notice Set the Image ID for the guest program
  /// @dev This value is application state, not protocol state. Interfold snapshots the protocol
  /// ciphertext verifier for each E3 at request time, and that verifier's own `imageId` is
  /// immutable, so changing this value cannot replace a computation the protocol already accepted.
  /// It can still break an E3 that is in flight: `verify` would then check the receipt against a
  /// guest that did not produce it, the round would fail as a compute timeout, and
  /// `FailurePayerLib` bills that to the requester. Change it only between rounds.
  /// @param _imageId The new image ID.
  function setImageId(bytes32 _imageId) external onlyOwner {
    imageId = _imageId;
  }

  /// @notice Set the RISC Zero verifier.
  /// @dev Carries the same in-flight risk as `setImageId`. Change it only between rounds.
  /// @param _risc0Verifier The new RISC Zero verifier address
  function setRisc0Verifier(IRiscZeroVerifier _risc0Verifier) external onlyOwner {
    if (address(_risc0Verifier) == address(0)) revert Risc0VerifierAddressZero();
    risc0Verifier = _risc0Verifier;
  }

  /// @notice Get the params hash for an E3 program
  /// @param e3Id The E3 program ID
  /// @return The params hash
  function getParamsHash(uint256 e3Id) public view returns (bytes32) {
    return e3Data[e3Id].paramsHash;
  }

  /// @notice Get the details about an E3 such as the merkle root of the census
  /// @dev RoundData cannot be returned directly as it contains nested mappings
  /// @param e3Id The E3 program ID
  /// @return merkleRoot The census merkle root
  /// @return paramsHash The hash of the E3 program params
  /// @return numOptions The number of vote options
  /// @return creditMode The credit mode for the round
  /// @return inputRoot The current root of the input (votes) merkle tree
  /// @return numberOfVotes The number of leaves in the input merkle tree
  function getRoundData(
    uint256 e3Id
  )
    public
    view
    returns (uint256 merkleRoot, bytes32 paramsHash, uint256 numOptions, CreditMode creditMode, uint256 inputRoot, uint40 numberOfVotes)
  {
    RoundData storage round = e3Data[e3Id];

    merkleRoot = round.merkleRoot;
    paramsHash = round.paramsHash;
    numOptions = round.numOptions;
    creditMode = round.creditMode;
    inputRoot = round.votes._root();
    numberOfVotes = round.votes.numberOfLeaves;
  }

  /// @notice The divisor applied to raw token voting power for a `CensusMode.ONCHAIN` round.
  /// @dev A client must divide by exactly this before proving, because the contract passes the
  /// scaled value to the circuit as public input 4 and the proof is checked against it. Zero for
  /// rounds that are not ONCHAIN, where no scaling happens.
  /// @param e3Id The E3 to look up.
  /// @return The divisor recorded at validation.
  function votingPowerDivisorOf(uint256 e3Id) external view returns (uint256) {
    return e3Data[e3Id].votingPowerDivisor;
  }

  /// @notice The voting power a slot may spend in an ONCHAIN round, in ballot units.
  /// @dev The value `publishInput` will hand the circuit as public input 4, computed by the same
  /// contract that will check the proof. A client must prove against exactly this: recomputing it
  /// off-chain means re-deriving the snapshot, the divisor and the rounding, and any drift only
  /// shows up as an opaque verifier failure. Returns 0 for a round that is not ONCHAIN, where the
  /// bound comes from the census leaf instead.
  ///
  /// Does not apply the eligibility floor — it answers "how much weight", not "may this slot
  /// write". `publishInput` still enforces the floor.
  /// @param e3Id The round.
  /// @param slot The slot address.
  /// @return The spendable voting power, in ballot units.
  function votingPowerOf(uint256 e3Id, address slot) external view returns (uint256) {
    RoundData storage round = e3Data[e3Id];
    if (round.censusMode != CensusMode.ONCHAIN) return 0;
    if (round.creditMode == CreditMode.CONSTANT) return round.credits;

    return IVotesToken(round.token).getPastVotes(slot, round.snapshot) / round.votingPowerDivisor;
  }

  /// @notice The census source a round was requested with.
  /// @dev A separate getter rather than a sixth return value on `getRoundData`, whose tuple is
  /// already consumed by the server and the SDK — widening it would break them for a field most
  /// callers do not want.
  /// @param e3Id The E3 to look up.
  /// @return The census mode recorded at validation.
  function censusModeOf(uint256 e3Id) external view returns (CensusMode) {
    return e3Data[e3Id].censusMode;
  }

  /// @inheritdoc IE3Program
  function validate(
    uint256 e3Id,
    uint256,
    bytes calldata e3ProgramParams,
    bytes calldata,
    bytes calldata customParams
  ) external returns (bytes32) {
    if (msg.sender != address(interfold) && msg.sender != owner()) revert CallerNotAuthorized();
    if (e3Data[e3Id].paramsHash != bytes32(0)) revert E3AlreadyInitialized();

    // Delegated to its own frame rather than scoped inline: `validate` is close enough to the
    // stack limit that holding the six decoded values alongside the parameters exceeds it.
    _initRound(e3Id, customParams);
    _validateInputTiming(e3Id);

    e3Data[e3Id].paramsHash = keccak256(e3ProgramParams);

    // Initialize the votes Merkle tree for this E3 ID.
    e3Data[e3Id].votes._init(TREE_DEPTH);

    return ENCRYPTION_SCHEME_ID;
  }

  /// @notice Refuse a round that can close before a worst-case committee leaves one hour to vote.
  /// @dev Interfold stores the E3 and its timeout snapshot before calling {validate}. Read those
  /// exact values instead of duplicating deployment-time settings. A zero finalization window is
  /// the synchronous local mock and keeps its short test rounds.
  function _validateInputTiming(uint256 e3Id) internal view {
    if (availabilityFinalizationWindow == 0) return;

    E3 memory e3 = interfold.getE3(e3Id);
    IInterfold.E3TimeoutConfig memory timeouts = interfold.getE3TimeoutConfig(e3Id);
    ICiphernodeRegistry registry = IInterfoldRegistryView(address(interfold)).ciphernodeRegistry();
    uint256 latestKeyAt = e3.requestBlock + registry.randomnessRequestTimeout() + registry.sortitionSubmissionWindow() + timeouts.dkgWindow;
    uint256 votingStartsAt = e3.inputWindow[0] > latestKeyAt ? e3.inputWindow[0] : latestKeyAt;
    uint256 duration = e3.inputWindow[1] - e3.inputWindow[0];
    if (duration <= availabilityFinalizationWindow) {
      revert InputWindowTooShort(e3Id, duration, availabilityFinalizationWindow + 1);
    }
    uint256 commitmentDeadline = e3.inputWindow[1] - availabilityFinalizationWindow;
    if (commitmentDeadline < votingStartsAt + MIN_VOTING_DURATION) {
      revert VotingWindowTooShort(e3Id, votingStartsAt, commitmentDeadline, MIN_VOTING_DURATION);
    }
  }

  /// @notice Decode the round configuration and record it.
  /// @dev One decode, every field required. `censusMode` is read as a uint and range-checked
  /// rather than decoded straight into the enum, so an unrecognised value gives a named error
  /// instead of a bare panic.
  /// @param e3Id The E3 being configured.
  /// @param customParams The ABI-encoded round configuration.
  function _initRound(uint256 e3Id, bytes calldata customParams) internal {
    (
      address token,
      uint256 minVotingPower,
      uint256 numOptions,
      CreditMode creditMode,
      uint256 credits,
      uint256 rawCensusMode,
      uint256 votingPowerDivisor
    ) = abi.decode(customParams, (address, uint256, uint256, CreditMode, uint256, uint256, uint256));

    // The circuit asserts `num_options <= MAX_OPTIONS`, so a round configured above it accepts no
    // ballot at all. Reject at request time rather than stranding a round nobody can vote in.
    if (numOptions < 2 || numOptions > MAX_VOTE_OPTIONS) revert InvalidNumOptions();
    if (rawCensusMode > uint256(type(CensusMode).max)) revert InvalidCensusMode();

    // Rejected here rather than by the coordinator, so a combination that can never work costs
    // nothing: this reverts in the same transaction that requests the E3, before any fee is paid.
    if (CensusMode(rawCensusMode) == CensusMode.BY_REQUESTER && creditMode != CreditMode.CONSTANT) {
      revert CensusModeRequiresConstantCredits();
    }

    // ONCHAIN reads every voter's power from this token, so a round without one accepts no ballot
    // at all. Same reasoning as the numOptions bound: fail before the fee is paid.
    if (CensusMode(rawCensusMode) == CensusMode.ONCHAIN && token == address(0)) {
      revert CensusModeRequiresToken();
    }

    // An ONCHAIN round hands `credits` to the circuit as the voting-power bound, so zero credits
    // bound every ballot to zero: only a mask would be accepted, and the round would tally
    // nothing. Checked for ONCHAIN only — the Merkle modes take the bound from the census leaf,
    // where `credits` never reaches the circuit and the contract has nothing to check.
    if (CensusMode(rawCensusMode) == CensusMode.ONCHAIN && creditMode == CreditMode.CONSTANT && credits == 0) {
      revert InvalidCredits();
    }

    RoundData storage round = e3Data[e3Id];
    // we need to know the number of options for decoding the tally
    round.numOptions = numOptions;
    // we want to save the credit mode so it can be verified on chain by everyone
    round.creditMode = creditMode;
    // recorded so anyone can verify which electorate the round was requested against
    round.censusMode = CensusMode(rawCensusMode);
    round.token = token;
    round.minVotingPower = minVotingPower;
    round.credits = credits;

    // The snapshot is taken here rather than supplied by the requester. This function runs in the
    // transaction that requests the E3, so `clock() - 1` is the last finalized timepoint of the
    // round, and a requester cannot name a timepoint that suits it. Recording it once also makes
    // every input of the round read the same electorate.
    if (CensusMode(rawCensusMode) == CensusMode.ONCHAIN) {
      // Checked before any call is attempted. A call to an address with no code succeeds and
      // returns nothing, so `clock()` fails while decoding the empty return data rather than
      // inside the call — and a decode failure is not what `try/catch` is there to catch. An EOA
      // would otherwise be refused by a bare panic instead of a named error.
      if (token.code.length == 0) revert CensusModeRequiresToken();

      uint48 snapshot = _previousTimepoint(token);

      // Probe the exact call every input will make. `_previousTimepoint` swallows a missing
      // `clock()` and falls back to block numbers, which is right for a token that predates
      // ERC-6372 but also lets an address that is not a votes token pass validation — and then
      // every `publishInput` reverts inside `getPastVotes`, after the fee is paid.
      try IVotesToken(token).getPastVotes(address(0), snapshot) returns (uint256) {} catch {
        revert CensusModeRequiresToken();
      }

      round.snapshot = snapshot;

      // Derived only after the code check above. `decimals()` on a codeless address returns empty
      // data, and the failure happens while decoding rather than inside the call, which `try` does
      // not catch — deriving any earlier would refuse an EOA with a bare panic instead of the
      // named error the check above raises.
      uint256 divisor = votingPowerDivisor == 0 ? _defaultVotingPowerDivisor(token) : votingPowerDivisor;

      // Only CUSTOM credits take the circuit bound from scaled power; a CONSTANT round hands the
      // circuit `credits` and never reads the scaled value, so the floor and the divisor have
      // nothing to agree about there.
      //
      // Where they do meet, the floor is raw and the bound is scaled, so they only agree when the
      // floor is worth at least one ballot unit. Requiring it here means every slot that passes
      // `_eligibility` carries weight, and it costs nothing: this reverts in the transaction that
      // requests the E3, not per input after the fee is paid. It also keeps masks working — they
      // run the same eligibility check as real votes, so a slot that scaled to zero could not be
      // masked without revealing which inputs were masks.
      if (creditMode == CreditMode.CUSTOM && minVotingPower < divisor) revert MinVotingPowerBelowScale();

      round.votingPowerDivisor = divisor;
    }
  }

  /// @inheritdoc IE3Program
  /// @dev This is the first transaction of the two-step input flow. It verifies the ballot but
  /// reserves its tree leaf and index immediately. The ciphertext is published separately and any
  /// account calls {finalizeInput} after a valid data-availability receipt exists.
  function publishInput(uint256 e3Id, bytes memory data) external {
    E3 memory e3 = _commitmentE3(e3Id);

    if (data.length == 0) revert EmptyInputData();

    (
      bytes memory noirProof,
      address slotAddress,
      bytes32 encryptedVoteCommitment,
      bytes32 encryptedVoteHash,
      uint40 parentIndexPlusOne,
      uint64 availabilityAttestationExpiresAt,
      bytes memory availabilityAttestation
    ) = abi.decode(data, (bytes, address, bytes32, bytes32, uint40, uint64, bytes));

    if (block.timestamp >= availabilityAttestationExpiresAt) {
      revert InputAvailabilityAttestationExpired(availabilityAttestationExpiresAt);
    }

    _verifyInputProof(e3Id, e3, noirProof, slotAddress, encryptedVoteCommitment, encryptedVoteHash, parentIndexPlusOne);

    bytes32 id = inputId(e3Id, encryptedVoteHash, encryptedVoteCommitment, slotAddress, parentIndexPlusOne);
    RoundData storage round = e3Data[e3Id];
    if (round.inputStatus[id] != InputStatus.NONE) revert InputAlreadyCommitted(id);
    if (
      ECDSA.recover(inputAvailabilityDigest(e3Id, id, availabilityAttestationExpiresAt), availabilityAttestation) != inputAvailabilitySigner
    ) {
      revert InvalidInputAvailabilityAttestation();
    }

    // Reserve the leaf and index now, not after VectorX finalizes. A later vote or mask can then
    // name this input as its parent instead of every pending input competing as a first write.
    uint40 voteIndex = _processVote(e3Id, slotAddress, encryptedVoteCommitment, encryptedVoteHash, parentIndexPlusOne);
    round.inputStatus[id] = InputStatus.COMMITTED;
    round.inputIndexPlusOne[id] = voteIndex + 1;
    round.pendingInputCount++;

    emit InputCommitted(e3Id, id, slotAddress, encryptedVoteCommitment, encryptedVoteHash, parentIndexPlusOne, voteIndex);
  }

  /// @notice Publish the DA receipt for a previously proven and reserved input.
  /// @dev Permissionless so the voter does not need to remain online while VectorX finalizes the
  /// Avail publication. The input identifier binds the receipt to the exact proof accepted by
  /// {publishInput}; changing the slot, commitment, content hash, or parent selects no commitment.
  function finalizeInput(
    uint256 e3Id,
    address slotAddress,
    bytes32 encryptedVoteCommitment,
    bytes32 encryptedVoteHash,
    uint40 parentIndexPlusOne,
    bytes calldata availabilityProof
  ) external {
    _finalizationE3(e3Id);

    bytes32 id = inputId(e3Id, encryptedVoteHash, encryptedVoteCommitment, slotAddress, parentIndexPlusOne);
    RoundData storage round = e3Data[e3Id];
    if (round.inputStatus[id] != InputStatus.COMMITTED) revert InputNotCommitted(id);

    IDataAvailabilityVerifier.DataReference memory availabilityReceipt = dataAvailabilityVerifier.verifyDataAvailability(
      encryptedVoteHash,
      availabilityProof
    );
    if (availabilityReceipt.contentHash != encryptedVoteHash) {
      revert DataAvailabilityHashMismatch(encryptedVoteHash, availabilityReceipt.contentHash);
    }

    round.inputStatus[id] = InputStatus.PUBLISHED;
    round.pendingInputCount--;
    uint40 voteIndex = round.inputIndexPlusOne[id] - 1;

    emit InputPublished(
      e3Id,
      slotAddress,
      encryptedVoteCommitment,
      encryptedVoteHash,
      availabilityReceipt.blockNumber,
      availabilityReceipt.leafIndex,
      voteIndex,
      parentIndexPlusOne
    );
  }

  /// @notice Checks a ballot before its proof commitment is sent on chain.
  /// @dev This checks the same proof and timing conditions as {publishInput} without modifying
  /// state. The service does not pay an Avail fee until the commitment transaction is confirmed.
  function validateInputProof(
    uint256 e3Id,
    bytes calldata noirProof,
    address slotAddress,
    bytes32 encryptedVoteCommitment,
    bytes32 encryptedVoteHash,
    uint40 parentIndexPlusOne
  ) external view returns (bool) {
    E3 memory e3 = _commitmentE3(e3Id);
    _verifyInputProof(e3Id, e3, noirProof, slotAddress, encryptedVoteCommitment, encryptedVoteHash, parentIndexPlusOne);
    return true;
  }

  /// @notice Last timestamp before which a new input proof can be committed.
  /// @dev The deadline is exclusive. At the exact timestamp, the reserved finalization tail has
  /// started and no new proof is accepted.
  function inputCommitmentDeadline(uint256 e3Id) public view returns (uint256 deadline) {
    E3 memory e3 = interfold.getE3(e3Id);
    uint256 duration = e3.inputWindow[1] - e3.inputWindow[0];
    if (duration <= availabilityFinalizationWindow) {
      revert InputWindowTooShort(e3Id, duration, availabilityFinalizationWindow + 1);
    }
    return e3.inputWindow[1] - availabilityFinalizationWindow;
  }

  function _keyPublishedE3(uint256 e3Id) internal view returns (E3 memory e3) {
    e3 = interfold.getE3(e3Id);
    if (interfold.getE3Stage(e3Id) != IInterfold.E3Stage.KeyPublished) {
      revert KeyNotPublished(e3Id);
    }
    if (block.timestamp < e3.inputWindow[0]) {
      revert E3NotAcceptingInputs(e3Id);
    }
  }

  function _commitmentE3(uint256 e3Id) internal view returns (E3 memory e3) {
    e3 = _keyPublishedE3(e3Id);
    uint256 deadline = inputCommitmentDeadline(e3Id);
    if (block.timestamp >= deadline) {
      revert InputCommitmentDeadlinePassed(e3Id, deadline);
    }
  }

  function _finalizationE3(uint256 e3Id) internal view returns (E3 memory e3) {
    e3 = _keyPublishedE3(e3Id);
    // The configured finalization tail is a normal target, not a destructive cutoff. No new proof
    // can enter after the commitment deadline, and `verify` blocks computation while a receipt is
    // pending. A delayed VectorX proof can therefore recover until the compute deadline.
    uint256 deadline = interfold.getDeadlines(e3Id).computeDeadline;
    if (block.timestamp > deadline) {
      revert InputDeadlinePassed(e3Id, deadline);
    }
  }

  function _verifyInputProof(
    uint256 e3Id,
    E3 memory e3,
    bytes memory noirProof,
    address slotAddress,
    bytes32 encryptedVoteCommitment,
    bytes32 encryptedVoteHash,
    uint40 parentIndexPlusOne
  ) internal view {
    uint256 leaf = inputLeaf(encryptedVoteHash, encryptedVoteCommitment, slotAddress, parentIndexPlusOne);
    if (e3Data[e3Id].appendedLeaf[leaf]) revert InputAlreadyPublished(leaf);
    bytes32 id = inputId(e3Id, encryptedVoteHash, encryptedVoteCommitment, slotAddress, parentIndexPlusOne);
    if (e3Data[e3Id].inputStatus[id] != InputStatus.NONE) revert InputAlreadyCommitted(id);

    (bytes32 eligibility, IHonkVerifier verifier) = _eligibility(e3Id, slotAddress);
    bytes32 parentCommitment = _parentCommitment(e3Id, slotAddress, parentIndexPlusOne);
    bytes32[] memory noirPublicInputs = new bytes32[](9);
    noirPublicInputs[0] = parentCommitment;
    // A Keccak digest does not fit in one field element, so it enters the circuit as its two
    // 16-byte halves. The circuit rebuilds the 32 bytes with `digest_from_halves`.
    {
      uint256 digest = uint256(ballotDigest(e3Id, slotAddress, encryptedVoteCommitment));
      noirPublicInputs[1] = bytes32(digest >> 128);
      noirPublicInputs[2] = bytes32(digest & type(uint128).max);
    }
    noirPublicInputs[3] = bytes32(uint256(uint160(slotAddress)));
    noirPublicInputs[4] = eligibility;
    noirPublicInputs[5] = bytes32(uint256(parentIndexPlusOne == 0 ? 1 : 0));
    noirPublicInputs[6] = bytes32(e3Data[e3Id].numOptions);
    noirPublicInputs[7] = encryptedVoteCommitment;
    noirPublicInputs[8] = e3.committeePublicKey;

    // Check if the ciphertext was encrypted correctly
    if (!verifier.verify(noirProof, noirPublicInputs)) {
      revert InvalidNoirProof();
    }
  }

  /// @notice The commitment of the entry an input names as its parent.
  /// @dev Zero when the input names none, which is what the circuit reads as `is_first_vote`.
  ///
  /// Naming no parent is allowed even when the slot already holds entries, and it has to be: a
  /// slot whose every entry is unusable has nothing to extend, and refusing that here would leave
  /// it permanently unwritable. Nothing is gained by refusing it either — the Secure Process
  /// accepts an entry only when its parent is the one currently selected for the slot, so an input
  /// that skips a usable parent is dropped from the tally wherever this contract lets it through.
  /// @param e3Id The round.
  /// @param slotAddress The slot the input is written to.
  /// @param parentIndexPlusOne The tree index of the parent entry plus one, or zero for none.
  /// @return The parent's commitment, or zero.
  function _parentCommitment(uint256 e3Id, address slotAddress, uint40 parentIndexPlusOne) internal view returns (bytes32) {
    if (parentIndexPlusOne == 0) return bytes32(0);

    bytes32 commitment = e3Data[e3Id].inputCommitment[slotAddress][parentIndexPlusOne - 1];
    // Zero for an index this slot never wrote to, including one belonging to another slot. The
    // circuit would read it as `is_first_vote` while this contract reads it as an update, so the
    // two would disagree about the same input.
    if (commitment == bytes32(0)) revert UnknownParentInput(parentIndexPlusOne - 1);

    return commitment;
  }

  /// @notice Resolve the eligibility public input and the verifier for a round.
  /// @dev Returns the value that occupies index 4 of the circuit public inputs. The `crisp` and
  /// `crisp_onchain` circuits agree on every other position, so this one value and the verifier
  /// address are the whole difference between the two paths.
  /// @param e3Id The E3 the input belongs to.
  /// @param slotAddress The slot the input is written to.
  /// @return eligibility The Merkle root of the census, or the voting power of the slot.
  /// @return verifier The verifier that matches the circuit of this round.
  function _eligibility(uint256 e3Id, address slotAddress) internal view returns (bytes32 eligibility, IHonkVerifier verifier) {
    RoundData storage round = e3Data[e3Id];

    if (round.censusMode != CensusMode.ONCHAIN) {
      // We need to ensure that the CRISP admin set the merkle root of the census.
      if (round.merkleRoot == 0) revert MerkleRootNotSet();
      return (bytes32(round.merkleRoot), honkVerifier);
    }

    uint256 rawPower = IVotesToken(round.token).getPastVotes(slotAddress, round.snapshot);

    // The floor is compared against RAW power, in the token's own units. `minVotingPower` is a
    // governance setting ("you need N tokens to vote") written the way every other token plugin
    // writes it, so scaling it here would reinterpret a configured value by the divisor.
    uint256 threshold = round.minVotingPower == 0 ? 1 : round.minVotingPower;
    if (rawPower < threshold) revert SlotNotEligible();

    // Scaled only for the circuit. It enforces `vote <= voting_power`, and the BFV encoding caps
    // each choice at `2**(100/numOptions) - 1` — about 8.6e9 for three options. Raw power from an
    // 18-decimal token is ~1e18 per token, so handing it over unscaled would put every holder
    // above the cap and collapse token weighting into a flat ceiling. Dividing mirrors what the
    // coordinator does when it builds a Merkle census (`balance / 10**(decimals - 1)`), so both
    // census families encode ballots in the same units and a tally decodes the same way.
    uint256 power = rawPower / round.votingPowerDivisor;

    // Eligibility comes from the power at the snapshot. The weight the circuit enforces comes from
    // the credit mode, so a CONSTANT round gives every eligible slot the same credits.
    return (bytes32(round.creditMode == CreditMode.CONSTANT ? round.credits : power), onchainHonkVerifier);
  }

  /// @notice The divisor to apply to raw voting power when the requester does not name one.
  /// @dev Mirrors the coordinator's census scaling (`balance / 10**(decimals - 1)`), so an ONCHAIN
  /// round and a Merkle round over the same token encode ballots in identical units. `decimals()`
  /// is optional on an ERC20, so a token without it is left unscaled rather than rejected — a
  /// requester that needs scaling for such a token passes an explicit divisor.
  /// @param token The token voting power is read from.
  /// @return The divisor, never zero.
  function _defaultVotingPowerDivisor(address token) internal view returns (uint256) {
    try IVotesToken(token).decimals() returns (uint8 dec) {
      // `10 ** 78` does not fit in a uint256, and the exponentiation happens in the success body
      // of the `try`, where a revert is NOT caught — an absurd `decimals` would surface as a bare
      // arithmetic panic instead of a named error, which is the failure mode the code check above
      // exists to avoid. Refused explicitly; such a token can still be used by naming a divisor.
      if (dec > MAX_DERIVABLE_DECIMALS) revert UnsupportedTokenDecimals(dec);

      return dec > 1 ? 10 ** (uint256(dec) - 1) : 1;
    } catch {
      return 1;
    }
  }

  /// @notice The last finalized timepoint of a token, in its ERC-6372 clock units.
  /// @dev Falls back to block numbers when the token has no `clock()`, which matches the default
  /// ERC20Votes clock.
  /// @param token The token to read the clock of.
  /// @return The timepoint before the current one.
  function _previousTimepoint(address token) internal view returns (uint48) {
    try IERC6372Clock(token).clock() returns (uint48 current) {
      return current == 0 ? 0 : current - 1;
    } catch {
      return uint48(block.number - 1);
    }
  }

  /// @notice Decode the tally from the plaintext output
  /// @param e3Id The E3 program ID
  /// @return votes - an array of vote counts for each option
  function decodeTally(uint256 e3Id) public view returns (uint256[] memory votes) {
    E3 memory e3 = interfold.getE3(e3Id);

    uint256 numOptions = e3Data[e3Id].numOptions;

    // If num optionsis not configured, return empty array to avoid decoding errors.
    // Users might be calling this function too early and there's no
    if (numOptions == 0) {
      return new uint256[](0);
    }

    uint64[] memory tally = _decodeBytesToUint64Array(e3.plaintextOutput);

    // The payload lives in the first MAX_MSG_NON_ZERO_COEFFS coefficients; the rest of
    // the polynomial is zero padding and must not be read.
    if (tally.length < MAX_MSG_NON_ZERO_COEFFS) revert InvalidTallyLength();

    uint256 segmentSize = MAX_MSG_NON_ZERO_COEFFS / numOptions;
    // More options than payload coefficients leaves nothing to decode.
    if (segmentSize == 0) return new uint256[](0);

    votes = new uint256[](numOptions);

    for (uint256 optIdx = 0; optIdx < numOptions; optIdx++) {
      uint256 segmentStart = optIdx * segmentSize;
      uint256 value = 0;

      // Each segment holds the count in binary, most significant coefficient first.
      for (uint256 i = 0; i < segmentSize; i++) {
        uint256 weight = 2 ** (segmentSize - 1 - i);
        value += uint256(tally[segmentStart + i]) * weight;
      }

      votes[optIdx] = value;
    }

    return votes;
  }

  /// @notice The index of the last input committed to a slot.
  /// @dev The last one *committed*, which is not always the one that holds the slot. This contract
  /// cannot tell whether an input's bytes deserialize to the ciphertext its commitment describes,
  /// so the entry at this index may be one the Secure Process will never select. A client naming a
  /// parent must resolve the chain — from the available bytes, or from the CRISP server's
  /// `state/previous-ciphertext` — rather than reading it from here.
  /// @param e3Id The E3 program ID
  /// @param slotAddress The slot address
  /// @return The index of the last committed input, or -1 if the slot is empty
  function getSlotIndex(uint256 e3Id, address slotAddress) external view returns (int40) {
    uint40 storedIndexPlusOne = e3Data[e3Id].voteSlots[slotAddress];
    return int40(storedIndexPlusOne) - 1;
  }

  /// @notice The commitment this contract recorded for one entry of a slot.
  /// @dev Zero for an index this slot never wrote to. A client names a parent by index and must
  /// prove against exactly the commitment stored for it, so this is how it checks what that will
  /// be before proving.
  /// @param e3Id The round.
  /// @param slotAddress The slot address.
  /// @param index The tree index of the entry.
  /// @return The stored commitment, or zero when there is no such entry for this slot.
  function inputCommitmentOf(uint256 e3Id, address slotAddress, uint40 index) external view returns (bytes32) {
    return e3Data[e3Id].inputCommitment[slotAddress][index];
  }

  /// @inheritdoc IE3Program
  function verify(
    uint256 e3Id,
    bytes32 ciphertextOutputHash,
    bytes32 ciphertextCommitment,
    bytes memory proof
  ) external view override returns (bool) {
    uint40 pending = e3Data[e3Id].pendingInputCount;
    if (pending != 0) revert InputAvailabilityPending(pending);
    E3 memory e3 = interfold.getE3(e3Id);
    bytes32 paramsHash = getParamsHash(e3Id);
    bytes32 inputRoot = bytes32(e3Data[e3Id].votes._root());
    Risc0ComputeProof.Proof memory computeProof = Risc0ComputeProof.decode(proof);
    if (computeProof.paramsHash != paramsHash || computeProof.inputRoot != inputRoot) revert InvalidComputeContext();

    bytes memory journal = Risc0ComputeProof.journal(
      bytes32(block.chainid),
      bytes32(uint256(uint160(address(interfold)))),
      bytes32(e3Id),
      e3.encryptionSchemeId,
      e3.committeePublicKey,
      ciphertextOutputHash,
      ciphertextCommitment,
      paramsHash,
      inputRoot
    );

    risc0Verifier.verify(computeProof.seal, imageId, sha256(journal));
    return true;
  }

  /// @notice Verify availability of an aggregate ciphertext for Interfold.
  /// @dev The same immutable verifier is used for inputs and outputs so one E3 cannot mix trust
  /// roots. Interfold independently checks the returned content hash before recording it.
  function verifyDataAvailability(
    bytes32 expectedContentHash,
    bytes calldata proof
  ) external view returns (IDataAvailabilityVerifier.DataReference memory receipt) {
    receipt = dataAvailabilityVerifier.verifyDataAvailability(expectedContentHash, proof);
    if (receipt.contentHash != expectedContentHash) {
      revert DataAvailabilityHashMismatch(expectedContentHash, receipt.contentHash);
    }
  }

  /// @notice Record one input: append its leaf and remember its commitment for later parents.
  function _processVote(
    uint256 e3Id,
    address slotAddress,
    bytes32 encryptedVoteCommitment,
    bytes32 encryptedVoteHash,
    uint40 parentIndexPlusOne
  ) internal returns (uint40 voteIndex) {
    RoundData storage round = e3Data[e3Id];

    // Append-only. Updating a slot's leaf in place would let anyone who can write to a slot — and
    // the mask path needs no signature — replace the bytes of a vote that was already counted,
    // erasing it. Appending leaves the earlier entry in the tree, so the Secure Process can fall
    // back to it when a later entry is unusable, and nothing is lost.
    uint256 leaf = inputLeaf(encryptedVoteHash, encryptedVoteCommitment, slotAddress, parentIndexPlusOne);

    // Refuse a byte-identical resubmission. Without this the tree is a free growth surface for
    // anyone replaying a committed input, and the round dies at tree capacity rather than at the
    // input deadline.
    if (round.appendedLeaf[leaf]) revert InputAlreadyPublished(leaf);
    round.appendedLeaf[leaf] = true;

    voteIndex = round.votes.numberOfLeaves;
    round.votes._insert(leaf);

    round.voteSlots[slotAddress] = voteIndex + 1;
    round.inputCommitment[slotAddress][voteIndex] = encryptedVoteCommitment;
  }

  /// @notice Builds the input tree leaf for one committed input.
  /// @dev Binds four things the Secure Process must be able to trust:
  ///
  /// - the **bytes**, because the Noir proof constrains the commitment and never sees the
  ///   serialized ciphertext, so the two can disagree and only the guest can tell;
  /// - the **commitment**, so a submitter cannot pair any commitment with any ciphertext;
  /// - the **slot**, because the tree is append-only and the guest tallies one entry per slot.
  ///   Without the slot in the leaf a prover could re-group entries and change which one wins;
  /// - the **parent**, because that is what the guest walks the slot's chain by. An unbound parent
  ///   would let a prover re-point entries and select a different one.
  ///
  /// Keccak hashes the serialized ciphertext into the same content digest that an external data
  /// availability receipt can expose. SHA-256 remains the outer hash because the zkVM accelerates
  /// it inline.
  function inputLeaf(
    bytes32 encryptedVoteHash,
    bytes32 commitment,
    address slotAddress,
    uint40 parentIndexPlusOne
  ) public pure returns (uint256) {
    return uint256(sha256(abi.encodePacked(encryptedVoteHash, commitment, slotAddress, parentIndexPlusOne))) % SNARK_SCALAR_FIELD;
  }

  /// @notice Identifier shared by the proof-commitment and DA-finalization transactions.
  /// @dev Domain-separated by this contract and the E3, so an accepted commitment cannot be
  /// replayed into another CRISP deployment or round.
  function inputId(
    uint256 e3Id,
    bytes32 encryptedVoteHash,
    bytes32 commitment,
    address slotAddress,
    uint40 parentIndexPlusOne
  ) public view returns (bytes32) {
    return keccak256(abi.encode("CRISP_INPUT_V1", address(this), e3Id, encryptedVoteHash, commitment, slotAddress, parentIndexPlusOne));
  }

  /// @notice EIP-712 digest signed after the availability service stores the ciphertext.
  /// @dev Exposed so relays can ask this deployment for the exact chain-bound digest instead of
  /// reproducing its domain separator off chain.
  function inputAvailabilityDigest(uint256 e3Id, bytes32 id, uint64 expiresAt) public view returns (bytes32) {
    return _hashTypedDataV4(keccak256(abi.encode(INPUT_AVAILABILITY_TYPEHASH, e3Id, id, expiresAt)));
  }

  /// @notice Number of committed inputs still waiting for a verified DA receipt.
  function pendingInputCount(uint256 e3Id) external view returns (uint40) {
    return e3Data[e3Id].pendingInputCount;
  }

  /// @notice Whether the Noir proof for this exact input has been accepted.
  /// @dev Remains true after finalization so relays recover idempotently after a restart.
  function isInputCommitted(
    uint256 e3Id,
    bytes32 encryptedVoteHash,
    bytes32 commitment,
    address slotAddress,
    uint40 parentIndexPlusOne
  ) external view returns (bool) {
    bytes32 id = inputId(e3Id, encryptedVoteHash, commitment, slotAddress, parentIndexPlusOne);
    return e3Data[e3Id].inputStatus[id] != InputStatus.NONE;
  }

  /// @notice Whether this exact input has a verified data-availability receipt.
  /// @dev Availability relays use this after a restart to distinguish a transaction that landed
  /// from one that still needs submission. It exposes only the same public fact as InputPublished.
  function isInputPublished(
    uint256 e3Id,
    bytes32 encryptedVoteHash,
    bytes32 commitment,
    address slotAddress,
    uint40 parentIndexPlusOne
  ) external view returns (bool) {
    bytes32 id = inputId(e3Id, encryptedVoteHash, commitment, slotAddress, parentIndexPlusOne);
    return e3Data[e3Id].inputStatus[id] == InputStatus.PUBLISHED;
  }

  /// @notice Decode bytes to uint64 array
  /// @param data The bytes to decode (must be multiple of 8)
  /// @return result Array of uint64 values
  function _decodeBytesToUint64Array(bytes memory data) internal pure returns (uint64[] memory result) {
    if (data.length % 8 != 0) {
      revert InvalidTallyLength();
    }

    uint256 arrayLength = data.length / 8;
    result = new uint64[](arrayLength);

    for (uint256 i = 0; i < arrayLength; i++) {
      uint256 offset = i * 8;
      uint64 value = 0;

      // Read 8 bytes in little-endian order
      for (uint64 j = 0; j < 8; j++) {
        value |= uint64(uint8(data[offset + j])) << (j * 8);
      }

      result[i] = value;
    }

    return result;
  }
}
