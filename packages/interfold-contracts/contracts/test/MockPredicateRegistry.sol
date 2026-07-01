// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {
    Attestation,
    IPredicateRegistry,
    Statement
} from "@predicate/contracts/src/interfaces/IPredicateRegistry.sol";

contract MockPredicateRegistry is IPredicateRegistry {
    bool public shouldValidate = true;
    Statement public lastStatement;
    Attestation public lastAttestation;

    mapping(address client => string policyID) public policyIDs;

    function setShouldValidate(bool shouldValidate_) external {
        shouldValidate = shouldValidate_;
    }

    function setPolicyID(string memory policyID) external {
        policyIDs[msg.sender] = policyID;
    }

    function getPolicyID(
        address client
    ) external view returns (string memory policyID) {
        return policyIDs[client];
    }

    function validateAttestation(
        Statement memory statement,
        Attestation memory attestation
    ) external returns (bool isVerified) {
        lastStatement = statement;
        lastAttestation = attestation;
        return shouldValidate;
    }
}
