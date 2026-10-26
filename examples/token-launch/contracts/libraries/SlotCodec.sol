// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.
pragma solidity 0.8.28;

/// @title Decoder of the published plaintext of the `insecure-simd` preset (degree 128, t = 257).
/// @notice The committee publishes the plaintext in the polynomial basis: 128 coefficients, each a
/// little-endian `uint64` (1024 bytes). SIMD slot `j` is the value of that polynomial at the point
/// `POINTS[j]` modulo 257. The table is the slot order of fhe.rs (`matrix_reps_index_map`) over the
/// negacyclic NTT of `fhe-math`: the same map that `simd_decode` in `crates/bfv-client` computes.
/// `sdk/test-vectors/slots.json` holds vectors that the Solidity and the TypeScript decoder share.
library SlotCodec {
  uint256 internal constant DEGREE = 128;
  uint256 internal constant MODULUS = 257;
  uint256 internal constant OUTPUT_BYTES = 1024;

  /// @dev The evaluation point of each slot: 128 big-endian `uint16` values.
  bytes private constant POINTS =
    hex"00b60077000a00e50096004c00140021"
    hex"00d600a300280007005600ee00500038"
    hex"0055009800a000bf00570045003f00f3"
    hex"005300db007e0091005b002f00fc0084"
    hex"004b008a00f7001c006b00b500ed00e0"
    hex"002b005e00d900fa00ab001300b100c9"
    hex"00ac00690061004200aa00bc00c2000e"
    hex"00ae00260083007000a600d20005007d"
    hex"00e9003600b4009c000c00ba005a0094"
    hex"00fb0029002d00930003001b009700b3"
    hex"007f005d00cc00b70041009500660037"
    hex"0060008e0033002700d100af009a0025"
    hex"001800cb004d006500f5004700a7006d"
    hex"000600d800d4006e00fe00e6006a004e"
    hex"008200a40035004a00c0006c009b00ca"
    hex"00a1007300ce00da00300052006700dc";

  error InvalidPlaintextLength(uint256 length);
  error CoefficientOutOfRange(uint256 index);

  /// @notice The 128 coefficients of `plaintext`, each checked to be below 257.
  function coefficients(bytes memory plaintext) internal pure returns (uint256[] memory coeffs) {
    if (plaintext.length != OUTPUT_BYTES) revert InvalidPlaintextLength(plaintext.length);
    uint256 bad;
    (coeffs, bad) = scan(plaintext);
    if (bad != DEGREE) revert CoefficientOutOfRange(bad);
  }

  /// @notice Like `coefficients`, but it does not revert: `bad` is the first coefficient that is not below
  /// 257 (a 64-bit value with other than the two low bytes counts as out of range), or `DEGREE` when all are
  /// valid. `plaintext` must have `OUTPUT_BYTES` bytes.
  function scan(bytes memory plaintext) internal pure returns (uint256[] memory coeffs, uint256 bad) {
    coeffs = new uint256[](DEGREE);
    bad = DEGREE;
    for (uint256 k = 0; k < DEGREE; k++) {
      uint256 value;
      bool valid;
      assembly ("memory-safe") {
        // The 8 bytes of the coefficient, as the top 64 bits of the loaded word.
        let word := shr(192, mload(add(add(plaintext, 32), shl(3, k))))
        // Little endian: byte 0 is the least significant byte. A value below 257 has only bytes 0 and 1.
        let low := shr(56, word)
        let high := and(shr(48, word), 0xff)
        value := add(low, shl(8, high))
        valid := and(iszero(and(word, 0xffffffffffff)), lt(value, 257))
      }
      if (!valid) {
        if (bad == DEGREE) bad = k;
        continue;
      }
      coeffs[k] = value;
    }
  }

  /// @notice The value of slot `slot` of the plaintext with the coefficients `coeffs`.
  function slotAt(uint256[] memory coeffs, uint256 slot) internal pure returns (uint256 acc) {
    bytes memory points = POINTS;
    assembly ("memory-safe") {
      let point := shr(240, mload(add(add(points, 32), shl(1, slot))))
      let base := add(coeffs, 32)
      for {
        let k := 128
      } k {} {
        k := sub(k, 1)
        acc := mod(add(mul(acc, point), mload(add(base, shl(5, k)))), 257)
      }
    }
  }
}
