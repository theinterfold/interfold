// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity >=0.4.24;

contract EmitLogs {
  event ValueChanged(address indexed author, uint256 count, string value);

  // These types match IBondingAdmission so the test uses the production event decoder.
  struct AdmissionPolicy {
    bool cooldownEnabled;
    bool admissionsPaused;
    uint48 cooldownDuration;
    uint48 pauseTimepoint;
    bool pauseCooldownEnabled;
    uint48 pauseCooldownDuration;
  }

  event AdmissionStarted(address indexed operator, uint48 timepoint);
  event AdmissionPolicyUpdated(uint48 timepoint, AdmissionPolicy policy);
  event BondOwnerSet(address indexed operator, address indexed bondOwner);
  event CommitteePublicKeyChunkPublished(
    uint256 indexed e3Id,
    address indexed publisher,
    bytes32 indexed candidateHash,
    address[] nodes,
    bytes32 pkCommitment,
    uint16 chunkIndex,
    uint16 chunkCount,
    uint32 totalLength,
    bytes chunk
  );

  string _value;

  uint256 count = 0;

  constructor() {
    _value = "";
  }

  function getValue() public view returns (string memory) {
    return _value;
  }

  function setValue(string memory value) public {
    count++;
    emit ValueChanged(msg.sender, count, value);
    _value = value;
  }

  function emitAdmissionPolicies(address operator, AdmissionPolicy[] calldata policies) external {
    emit AdmissionStarted(operator, uint48(block.timestamp));
    for (uint256 i = 0; i < policies.length; i++) {
      emit AdmissionPolicyUpdated(uint48(block.timestamp), policies[i]);
    }
  }

  function emitBondOwners(address[] calldata operators, address[] calldata owners) external {
    require(operators.length == owners.length);
    for (uint256 i = 0; i < operators.length; i++) {
      emit BondOwnerSet(operators[i], owners[i]);
    }
  }

  function publishCommitteePublicKey(
    uint256 e3Id,
    bytes32 candidateHash,
    uint16 chunkIndex,
    uint16 chunkCount,
    uint32 totalLength,
    bytes calldata chunk
  ) external {
    address[] memory nodes = new address[](1);
    nodes[0] = msg.sender;
    emit CommitteePublicKeyChunkPublished(
      e3Id,
      msg.sender,
      candidateHash,
      nodes,
      bytes32(uint256(9)),
      chunkIndex,
      chunkCount,
      totalLength,
      chunk
    );
  }
}
