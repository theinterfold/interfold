// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import {
    IERC165
} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {
    Attestation
} from "@predicate/contracts/src/interfaces/IPredicateRegistry.sol";
import {
    IPredicateClient
} from "@predicate/contracts/src/interfaces/IPredicateClient.sol";
import {
    BasicPredicateClient
} from "@predicate/contracts/src/mixins/BasicPredicateClient.sol";

interface ICCAValidationHook {
    function validate(
        uint256 maxPrice,
        uint128 amount,
        address owner,
        address sender,
        bytes calldata hookData
    ) external;
}

/**
 * @title PredicateValidationHook
 * @notice CCA validation hook that requires a Predicate attestation before a
 *         bid can be submitted.
 * @dev The auction address is set after the CCA is deployed because the CCA
 *      constructor needs this hook address first. The Safe owns that action.
 */
contract PredicateValidationHook is
    ICCAValidationHook,
    BasicPredicateClient,
    Ownable,
    IERC165
{
    error ZeroAddress();
    error NoContractCode(address target);
    error EmptyPolicyID();
    error CallerMustBeAuction();
    error SenderMustBeOwner();
    error InvalidAttestation();

    address public auction;
    bool public requireSenderIsOwner;

    event AuctionSet(address indexed auction);
    event RequireSenderIsOwnerSet(bool required);
    event AttestationValidated(address indexed sender, string uuid);

    constructor(
        address owner_,
        address registry_,
        string memory policyID_,
        bool requireSenderIsOwner_
    ) Ownable(owner_) {
        if (owner_ == address(0) || registry_ == address(0)) {
            revert ZeroAddress();
        }
        if (registry_.code.length == 0) revert NoContractCode(registry_);
        if (bytes(policyID_).length == 0) revert EmptyPolicyID();
        _initPredicateClient(registry_, policyID_);
        requireSenderIsOwner = requireSenderIsOwner_;
        emit RequireSenderIsOwnerSet(requireSenderIsOwner_);
    }

    function validate(
        uint256,
        uint128,
        address owner,
        address sender,
        bytes calldata hookData
    ) external {
        if (msg.sender != auction) revert CallerMustBeAuction();
        if (requireSenderIsOwner && sender != owner) revert SenderMustBeOwner();

        Attestation memory attestation = abi.decode(hookData, (Attestation));
        if (!_authorizeTransaction(attestation, sender)) {
            revert InvalidAttestation();
        }

        emit AttestationValidated(sender, attestation.uuid);
    }

    function setAuction(address auction_) external onlyOwner {
        if (auction_ == address(0)) revert ZeroAddress();
        if (auction_.code.length == 0) revert NoContractCode(auction_);
        auction = auction_;
        emit AuctionSet(auction_);
    }

    function setRequireSenderIsOwner(bool required) external onlyOwner {
        requireSenderIsOwner = required;
        emit RequireSenderIsOwnerSet(required);
    }

    function setRegistry(address registry_) external onlyOwner {
        if (registry_ == address(0)) revert ZeroAddress();
        if (registry_.code.length == 0) revert NoContractCode(registry_);
        _setRegistry(registry_);
    }

    function setPolicyID(string memory policyID_) external onlyOwner {
        if (bytes(policyID_).length == 0) revert EmptyPolicyID();
        _setPolicyID(policyID_);
    }

    function supportsInterface(bytes4 interfaceId) public pure returns (bool) {
        return
            interfaceId == type(ICCAValidationHook).interfaceId ||
            interfaceId == type(IPredicateClient).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }
}
