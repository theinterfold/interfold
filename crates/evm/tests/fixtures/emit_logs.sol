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
}
