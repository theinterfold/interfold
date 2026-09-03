// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import { IHonkVerifier } from "./CkksE3Program.sol";
import { CkksAppE3ProgramBase } from "./CkksAppE3ProgramBase.sol";

/// @title CkksAuctionE3Program
/// @notice Sealed-bid auction (CKKS ParamSet 2). A bid is accepted only
///         with the two Greco legs AND the `ckks_auction_validity_ps2`
///         proof that the encrypted, slot-replicated bid `bid / cap`
///         satisfies `0 <= bid <= balance`, where `(address, balance)` is
///         a leaf of the balance tree under the root published for the E3
///         (CRISP token-holder model: leaf = `poseidon([address, balance])`).
///
///         App-leg public inputs: `[cap, address, merkle_root, m_commitment]`.
///         Sender binding: `address` MUST equal `msg.sender` — the bidder
///         proves a bound on the balance attested to THEIR address and the
///         chain checks they hold it. This is the lighter sound alternative
///         to an in-circuit ECDSA signature (CRISP-style): ownership of the
///         address is exactly what signing the transaction demonstrates.
///
///         The balance root per E3 is set once by the round opener (the
///         contract owner) — for the demo, an admin snapshot of token
///         balances; production would derive it from an on-chain
///         checkpoint. Bids before the root is set revert.
contract CkksAuctionE3Program is CkksAppE3ProgramBase {
    /// @dev `[cap, address, merkle_root, m_commitment]`.
    uint256 internal constant APP_PUBLIC_INPUTS = 4;

    /// @notice The public normalization cap every bid must use.
    uint256 public immutable bidCap;
    /// @notice Round opener allowed to publish balance roots.
    address public immutable owner;
    /// @notice Balance Merkle root per E3 (0 = not set).
    mapping(uint256 => bytes32) public balanceRoots;

    event BalanceRootSet(uint256 indexed e3Id, bytes32 root);

    error NotOwner();
    error InvalidRoot();
    error RootAlreadySet(uint256 e3Id);
    error RootNotSet(uint256 e3Id);
    error WrongRoot(bytes32 got, bytes32 want);
    error WrongCap(uint256 got, uint256 want);
    error WrongSender(address proven, address sender);

    constructor(
        IHonkVerifier ct0Verifier_,
        IHonkVerifier ct1Verifier_,
        IHonkVerifier appVerifier_,
        uint256 bidCap_
    ) CkksAppE3ProgramBase(ct0Verifier_, ct1Verifier_, appVerifier_) {
        bidCap = bidCap_;
        owner = msg.sender;
    }

    /// @notice Publishes the balance root for `e3Id` (once).
    function setBalanceRoot(uint256 e3Id, bytes32 root) external {
        if (msg.sender != owner) revert NotOwner();
        if (root == bytes32(0)) revert InvalidRoot();
        if (balanceRoots[e3Id] != bytes32(0)) revert RootAlreadySet(e3Id);
        balanceRoots[e3Id] = root;
        emit BalanceRootSet(e3Id, root);
    }

    /// @inheritdoc IE3Program
    /// @dev See `CkksAppE3ProgramBase._publishThreeLegInput` for the
    ///      `data` envelope.
    function publishInput(uint256 e3Id, bytes memory data) external {
        _publishThreeLegInput(e3Id, data);
    }

    function _appPublicInputCount() internal pure override returns (uint256) {
        return APP_PUBLIC_INPUTS;
    }

    function _checkAppPublicInputs(
        uint256 e3Id,
        bytes32[] memory appPublicInputs
    ) internal view override {
        uint256 cap = uint256(appPublicInputs[0]);
        if (cap != bidCap) revert WrongCap(cap, bidCap);

        // `address` is a free field element in the circuit, so the whole
        // 256-bit word must equal the sender (no high bits allowed).
        address proven = address(uint160(uint256(appPublicInputs[1])));
        if (uint256(appPublicInputs[1]) >> 160 != 0 || proven != msg.sender) {
            revert WrongSender(proven, msg.sender);
        }

        bytes32 root = balanceRoots[e3Id];
        if (root == bytes32(0)) revert RootNotSet(e3Id);
        if (appPublicInputs[2] != root)
            revert WrongRoot(appPublicInputs[2], root);
    }
}
