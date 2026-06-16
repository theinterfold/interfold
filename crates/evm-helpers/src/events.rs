// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::sol;

// TODO: extract these from that actual contract

sol! {
    #[derive(Debug)]
    event E3Requested(uint256 e3Id, E3 e3, IE3Program indexed e3Program);

    #[derive(Debug)]
    interface IE3Program {
        function e3Program() external view returns (address);
    }

    #[derive(Debug)]
    interface IDecryptionVerifier {
        function verifyDecryption(bytes data) external view returns (bool);
    }

    #[derive(Debug)]
    interface IPkVerifier {
        function verify(bytes32 pkCommitment, bytes memory proof) external view returns (bool);
    }

    #[derive(Debug)]
    enum CommitteeSize {
        Minimum,
        Micro,
        Small,
    }

    #[derive(Debug)]
    struct E3 {
        uint256 seed;
        CommitteeSize committeeSize;
        uint256 requestBlock;
        uint256[2] inputWindow;
        bytes32 encryptionSchemeId;
        IE3Program e3Program;
        uint8 paramSet;
        bytes customParams;
        IDecryptionVerifier decryptionVerifier;
        IPkVerifier pkVerifier;
        bytes32 committeePublicKey;
        bytes32 ciphertextOutput;
        bytes plaintextOutput;
        address requester;
        bool proofAggregationEnabled;
    }

    #[derive(Debug)]
    event CiphertextOutputPublished(uint256 indexed e3Id, bytes ciphertextOutput);

    #[derive(Debug)]
    event PlaintextOutputPublished(uint256 indexed e3Id, bytes plaintextOutput, bytes proof);

    #[derive(Debug)]
    event CommitteePublished(uint256 indexed e3Id, address[] nodes, bytes publicKey, bytes32 pkCommitment, bytes proof);

    #[derive(Debug)]
    enum E3Stage {
        None,
        Requested,
        CommitteeFinalized,
        KeyPublished,
        CiphertextReady,
        Complete,
        Failed
    }

    #[derive(Debug)]
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
        VerificationFailed
    }

    #[derive(Debug)]
    event CommitteeFinalized(uint256 indexed e3Id);

    #[derive(Debug)]
    event E3StageChanged(uint256 indexed e3Id, E3Stage previousStage, E3Stage newStage);

    #[derive(Debug)]
    event E3Failed(uint256 indexed e3Id, E3Stage failedAtStage, FailureReason reason);
}
