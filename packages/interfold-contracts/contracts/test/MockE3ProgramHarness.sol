// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

import { IE3Program } from "../interfaces/IE3Program.sol";
import { IInterfold } from "../interfaces/IInterfold.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {
    IDataAvailabilityVerifier,
    IE3ProgramDataAvailability
} from "../interfaces/IDataAvailabilityVerifier.sol";
import {
    IERC165
} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

interface ISlashExecutor {
    function executeSlash(uint256 proposalId) external;
}

/// @dev Test-only E3 program with controls used to exercise failure and reentrancy paths.
contract MockE3ProgramHarness is IE3Program, IERC165 {
    error InvalidParams(bytes e3ProgramParams, bytes computeProviderParams);
    error E3AlreadyInitialized();
    error InvalidInput();

    bytes32 public constant ENCRYPTION_SCHEME_ID = keccak256("fhe.rs:BFV");

    IInterfold public interfold;
    bool public reenterPlaintextPublication;
    /// @dev When set, `verify` executes this mature slash proposal before it returns true.
    ///      This copies an application callback that expels a committee member.
    address public slashExecutorDuringVerify;
    uint256 public slashProposalDuringVerify;
    bool public returnMismatchedAvailabilityHash;
    bytes public reentrantPlaintext;
    bytes public reentrantProof;
    address public observedTreasury;
    IERC20 public observedFeeToken;
    uint256 public pendingTreasuryDuringValidation;

    mapping(uint256 e3Id => bytes32 paramsHash) public paramsHashes;
    mapping(uint256 e3Id => uint256 requestTime) public validationRequestTimes;
    mapping(uint256 e3Id => bytes32 commitment)
        public expectedCiphertextCommitments;

    /// @inheritdoc IERC165
    /// @dev Interfold probes these interfaces before it registers a program.
    function supportsInterface(
        bytes4 interfaceId
    ) external pure returns (bool) {
        return
            interfaceId == type(IE3Program).interfaceId ||
            interfaceId == type(IE3ProgramDataAvailability).interfaceId ||
            interfaceId == type(IERC165).interfaceId;
    }

    function setInterfold(IInterfold _interfold) external {
        interfold = _interfold;
    }

    function setExpectedCiphertextCommitment(
        uint256 e3Id,
        bytes32 commitment
    ) external {
        expectedCiphertextCommitments[e3Id] = commitment;
    }

    function setReentrantPlaintextPublication(
        bytes calldata plaintext,
        bytes calldata proof
    ) external {
        reenterPlaintextPublication = true;
        reentrantPlaintext = plaintext;
        reentrantProof = proof;
    }

    function setSlashDuringVerify(
        address executor,
        uint256 proposalId
    ) external {
        slashExecutorDuringVerify = executor;
        slashProposalDuringVerify = proposalId;
    }

    function setReturnMismatchedAvailabilityHash(bool enabled) external {
        returnMismatchedAvailabilityHash = enabled;
    }

    function observeTreasuryDuringValidation(
        address treasury,
        IERC20 token
    ) external {
        observedTreasury = treasury;
        observedFeeToken = token;
    }

    function validate(
        uint256 e3Id,
        uint256,
        bytes calldata e3ProgramParams,
        bytes calldata computeProviderParams,
        bytes calldata
    ) external returns (bytes32) {
        require(
            computeProviderParams.length == 32,
            InvalidParams(e3ProgramParams, computeProviderParams)
        );

        require(paramsHashes[e3Id] == bytes32(0), E3AlreadyInitialized());
        if (address(interfold) != address(0)) {
            // Production programs can inspect the provisional E3 while validating the request.
            // This assertion prevents fixtures from hiding a different production call order.
            validationRequestTimes[e3Id] = interfold.getE3(e3Id).requestBlock;
            if (address(observedFeeToken) != address(0)) {
                pendingTreasuryDuringValidation = interfold
                    .pendingTreasuryClaim(observedTreasury, observedFeeToken);
            }
        }
        paramsHashes[e3Id] = keccak256(e3ProgramParams);
        return ENCRYPTION_SCHEME_ID;
    }

    function publishInput(uint256 e3Id, bytes memory data) external {
        _publishInput(e3Id, data, keccak256(data));
    }

    function publishInputWithCommitment(
        uint256 e3Id,
        bytes memory data,
        bytes32 ciphertextCommitment
    ) external {
        _publishInput(e3Id, data, ciphertextCommitment);
    }

    function _publishInput(
        uint256 e3Id,
        bytes memory data,
        bytes32 ciphertextCommitment
    ) internal {
        if (data.length == 3) revert InvalidInput();
        if (address(interfold) != address(0)) {
            interfold.publishCiphertextOutput(
                e3Id,
                abi.encode(
                    IInterfold.CiphertextOutputReference({
                        contentHash: keccak256(data),
                        ciphertextCommitment: ciphertextCommitment,
                        computeProof: data,
                        availabilityProof: data
                    })
                )
            );
        }
    }

    function verify(
        uint256 e3Id,
        bytes32,
        bytes32 ciphertextCommitment,
        bytes memory data
    ) external returns (bool success) {
        bytes32 expected = expectedCiphertextCommitments[e3Id];
        if (expected != bytes32(0) && ciphertextCommitment != expected) {
            return false;
        }
        if (slashExecutorDuringVerify != address(0)) {
            ISlashExecutor(slashExecutorDuringVerify).executeSlash(
                slashProposalDuringVerify
            );
        }
        if (reenterPlaintextPublication) {
            interfold.publishPlaintextOutput(
                e3Id,
                reentrantPlaintext,
                reentrantProof
            );
        }
        return data.length > 0;
    }

    function verifyDataAvailability(
        bytes32 expectedContentHash,
        bytes calldata proof
    )
        external
        view
        returns (IDataAvailabilityVerifier.DataReference memory receipt)
    {
        require(keccak256(proof) == expectedContentHash, InvalidInput());
        return
            IDataAvailabilityVerifier.DataReference({
                contentHash: returnMismatchedAvailabilityHash
                    ? bytes32(uint256(expectedContentHash) ^ 1)
                    : expectedContentHash,
                blockNumber: 1,
                leafIndex: 1
            });
    }
}
