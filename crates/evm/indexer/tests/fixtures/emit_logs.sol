// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

pragma solidity >=0.4.24;

contract EmitLogs {
  event ValueChanged(address indexed author, uint256 count, string value);
  event PublishMessage(string value);

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

  function emitPublishMessage(string memory value) public {
    emit PublishMessage(value);
  }
}
