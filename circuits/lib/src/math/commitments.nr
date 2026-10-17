// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::math::helpers::{compute_safe, flatten, flatten_checked, flatten_with};
use crate::math::polynomial::Polynomial;

/// DOMAIN SEPARATORS

// Domain separator - "PK"
pub global DS_PK: [u8; 64] = [
    0x50, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "PK_GENERATION"
pub global DS_PK_GENERATION: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "PK_GENERATION_LIMB_V1"
pub global DS_PK_GENERATION_LIMB_V1: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x4c, 0x49,
    0x4d, 0x42, 0x5f, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "SHARE_COMPUTATION"
pub global DS_SHARE_COMPUTATION: [u8; 64] = [
    0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x43, 0x4f, 0x4d, 0x50, 0x55, 0x54, 0x41, 0x54, 0x49, 0x4f,
    0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "SHARE_COMPUTATION_CHUNK"
pub global DS_SHARE_COMPUTATION_CHUNK: [u8; 64] = [
    0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x43, 0x4f, 0x4d, 0x50, 0x55, 0x54, 0x41, 0x54, 0x49, 0x4f,
    0x4e, 0x5f, 0x43, 0x48, 0x55, 0x4e, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "SHARE_ENCRYPTION"
pub global DS_SHARE_ENCRYPTION: [u8; 64] = [
    0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "PK_AGGREGATION"
pub global DS_PK_AGGREGATION: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x41, 0x47, 0x47, 0x52, 0x45, 0x47, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "CIPHERTEXT"
pub global DS_CIPHERTEXT: [u8; 64] = [
    0x43, 0x49, 0x50, 0x48, 0x45, 0x52, 0x54, 0x45, 0x58, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "AGGREGATED_SHARES"
pub global DS_AGGREGATED_SHARES: [u8; 64] = [
    0x41, 0x47, 0x47, 0x52, 0x45, 0x47, 0x41, 0x54, 0x45, 0x44, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45,
    0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "VK_HASH"
pub global DS_VK_HASH: [u8; 64] = [
    0x56, 0x4b, 0x5f, 0x48, 0x41, 0x53, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "RECURSIVE_AGGREGATION"
pub global DS_RECURSIVE_AGGREGATION: [u8; 64] = [
    0x52, 0x45, 0x43, 0x55, 0x52, 0x53, 0x49, 0x56, 0x45, 0x5f, 0x41, 0x47, 0x47, 0x52, 0x45, 0x47,
    0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "CLG_PK_GENERATION"
pub global DS_CLG_PK_GENERATION: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x50, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f,
    0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "CLG_LBFV_RLK_GENERATION_ROW_V1"
pub global DS_CLG_LBFV_RLK_GENERATION_ROW_V1: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x4c, 0x42, 0x46, 0x56, 0x5f, 0x52, 0x4c, 0x4b, 0x5f, 0x47, 0x45, 0x4e,
    0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x52, 0x4f, 0x57, 0x5f, 0x56, 0x31, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "CLG_LBFV_PK_GENERATION_ROW_V1"
pub global DS_CLG_LBFV_PK_GENERATION_ROW_V1: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x4c, 0x42, 0x46, 0x56, 0x5f, 0x50, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45,
    0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x52, 0x4f, 0x57, 0x5f, 0x56, 0x31, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "CLG_SHARE_ENCRYPTION"
pub global DS_CLG_SHARE_ENCRYPTION: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50,
    0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "CLG_USER_DATA_ENCRYPTION"
pub global DS_CLG_USER_DATA_ENCRYPTION: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x55, 0x53, 0x45, 0x52, 0x5f, 0x44, 0x41, 0x54, 0x41, 0x5f, 0x45, 0x4e,
    0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "CLG_SHARE_DECRYPTION"
pub global DS_CLG_SHARE_DECRYPTION: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45, 0x5f, 0x44, 0x45, 0x43, 0x52, 0x59, 0x50,
    0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Domain separator - "THRESHOLD_DECRYPTION_SHARE"
pub global DS_THRESHOLD_DECRYPTION_SHARE: [u8; 64] = [
    0x54, 0x48, 0x52, 0x45, 0x53, 0x48, 0x4f, 0x4c, 0x44, 0x5f, 0x44, 0x45, 0x43, 0x52, 0x59, 0x50,
    0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Domain separator - "USER_DATA_ENCRYPTION_COMMITMENT"
pub global DS_USER_DATA_ENCRYPTION_COMMITMENT: [u8; 64] = [
    0x55, 0x53, 0x45, 0x52, 0x5f, 0x44, 0x41, 0x54, 0x41, 0x5f, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50,
    0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x43, 0x4f, 0x4d, 0x4d, 0x49, 0x54, 0x4d, 0x45, 0x4e, 0x54, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "USER_DATA_ENCRYPTION_CHUNK"
pub global DS_USER_DATA_ENCRYPTION_CHUNK: [u8; 64] = [
    0x55, 0x53, 0x45, 0x52, 0x5f, 0x44, 0x41, 0x54, 0x41, 0x5f, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50,
    0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x43, 0x48, 0x55, 0x4e, 0x4b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Domain separator - "RLK_GENERATION"
pub global DS_RLK_GENERATION: [u8; 64] = [
    0x52, 0x4c, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "RLK_GENERATION_LIMB_V1"
pub global DS_RLK_GENERATION_LIMB_V1: [u8; 64] = [
    0x52, 0x4c, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x5f, 0x4c,
    0x49, 0x4d, 0x42, 0x5f, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "RLK_AGGREGATION"
pub global DS_RLK_AGGREGATION: [u8; 64] = [
    0x52, 0x4c, 0x4b, 0x5f, 0x41, 0x47, 0x47, 0x52, 0x45, 0x47, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "LBFV_PUBLIC_KEY_V1"
pub global DS_LBFV_PUBLIC_KEY_V1: [u8; 64] = [
    0x4c, 0x42, 0x46, 0x56, 0x5f, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x5f, 0x4b, 0x45, 0x59, 0x5f,
    0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "LBFV_RLK_V1"
pub global DS_LBFV_RLK_V1: [u8; 64] = [
    0x4c, 0x42, 0x46, 0x56, 0x5f, 0x52, 0x4c, 0x4b, 0x5f, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "LBFV_KEY_ENVELOPE_V1"
pub global DS_LBFV_KEY_ENVELOPE_V1: [u8; 64] = [
    0x4c, 0x42, 0x46, 0x56, 0x5f, 0x4b, 0x45, 0x59, 0x5f, 0x45, 0x4e, 0x56, 0x45, 0x4c, 0x4f, 0x50,
    0x45, 0x5f, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
// Domain separator - "CLG_RLK_GENERATION"
pub global DS_CLG_RLK_GENERATION: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x52, 0x4c, 0x4b, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x52, 0x41, 0x54, 0x49,
    0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// WRAPPERS

pub fn compute_commitment(inputs: [Field], domain_separator: [u8; 64]) -> Field {
    compute_safe(domain_separator, inputs, [0x80000000 | inputs.len(), 1])[0]
}

pub fn compute_single_polynomial_commitment<let N: u32, let BIT: u32>(
    polynomial: Polynomial<N>,
    domain_separator: [u8; 64],
) -> Field {
    let payload = single_polynomial_payload::<N, BIT>([].as_vector(), polynomial);
    compute_commitment(payload, domain_separator)
}

/// [`compute_single_polynomial_commitment`] with the digit asserts, for a polynomial this circuit
/// carries no bound for: the digit asserts make the packing injective, so an opening of a commitment
/// another circuit bounded is forced to be that circuit's polynomial. (ct0 and ct1 no longer need it
/// for `u`: each constrains its `u` to `{-1, 0, 1}`, which already makes the plain packing injective.)
/// Produces the same value as the plain version for any input the plain version could legitimately
/// have committed.
pub fn compute_single_polynomial_commitment_checked<let N: u32, let BIT: u32>(
    polynomial: Polynomial<N>,
    domain_separator: [u8; 64],
) -> Field {
    let payload = single_polynomial_payload_checked::<N, BIT>([].as_vector(), polynomial);
    compute_commitment(payload, domain_separator)
}

pub fn compute_multiple_polynomial_commitment<let N: u32, let L: u32, let BIT: u32>(
    polynomials: [Polynomial<N>; L],
    domain_separator: [u8; 64],
) -> Field {
    let payload = multiple_polynomial_payload::<N, L, BIT>([].as_vector(), polynomials);
    compute_commitment(payload, domain_separator)
}

pub fn compute_challenge<let L: u32>(inputs: [Field], domain_separator: [u8; 64]) -> [Field] {
    compute_safe(domain_separator, inputs, [0x80000000 | inputs.len(), 2 * L])
}

pub fn single_polynomial_payload<let N: u32, let BIT_POLY: u32>(
    payload: [Field],
    input: Polynomial<N>,
) -> [Field] {
    flatten::<_, _, BIT_POLY>(payload, [input])
}

pub fn multiple_polynomial_payload<let N: u32, let L: u32, let BIT_POLY: u32>(
    payload: [Field],
    inputs: [Polynomial<N>; L],
) -> [Field] {
    flatten::<_, _, BIT_POLY>(payload, inputs)
}

pub fn single_polynomial_payload_checked<let N: u32, let BIT_POLY: u32>(
    payload: [Field],
    input: Polynomial<N>,
) -> [Field] {
    flatten_checked::<_, _, BIT_POLY>(payload, [input])
}

pub fn multiple_polynomial_payload_checked<let N: u32, let L: u32, let BIT_POLY: u32>(
    payload: [Field],
    inputs: [Polynomial<N>; L],
) -> [Field] {
    flatten_checked::<_, _, BIT_POLY>(payload, inputs)
}

/// COMMITMENTS

pub fn compute_dkg_pk_commitment<let N: u32, let L: u32, let BIT_PK: u32>(
    pk0: [Polynomial<N>; L],
    pk1: [Polynomial<N>; L],
) -> Field {
    let mut payload = multiple_polynomial_payload::<N, L, BIT_PK>([].as_vector(), pk0);
    payload = multiple_polynomial_payload::<N, L, BIT_PK>(payload, pk1);

    compute_commitment(payload, DS_PK)
}

/// [`compute_dkg_pk_commitment`] for a circuit that **opens** the DKG key commitment rather than
/// creating it (C3). C0 range-checks every key coefficient to its centred window before hashing,
/// so asserting each packed digit fits its slot makes this opening injective and forces the opened
/// key to be the one C0 bounded. Same value as the plain helper.
pub fn compute_dkg_pk_commitment_checked<let N: u32, let L: u32, let BIT_PK: u32>(
    pk0: [Polynomial<N>; L],
    pk1: [Polynomial<N>; L],
) -> Field {
    let mut payload = multiple_polynomial_payload_checked::<N, L, BIT_PK>([].as_vector(), pk0);
    payload = multiple_polynomial_payload_checked::<N, L, BIT_PK>(payload, pk1);

    compute_commitment(payload, DS_PK)
}

pub fn compute_threshold_pk_commitment<let N: u32, let L: u32, let BIT_PK: u32>(
    pk0: [Polynomial<N>; L],
) -> Field {
    let payload = multiple_polynomial_payload::<N, L, BIT_PK>([].as_vector(), pk0);
    compute_commitment(payload, DS_PK_GENERATION)
}

// L-BFV COMMITMENT HELPERS
//
// The `compute_sc_*`, `compute_ude_*`, `compute_lbfv_*` and `compute_rlk_*` helpers below serve
// only the l-BFV path. They pack with checked digits, the semantics `lbfv/chunking` built its
// circuits on, so a circuit that opens one of these commitments without its own range check still
// opens it injectively. Where the creating circuit range-checks the values, the digit check is
// redundant: the `*_bounded` variants drop it and compute the same value.

/// Row commitment over the per-limb `pk0` commitments of one l-BFV public-key row. Same design as
/// [`compute_rlk_row_commitment_from_limbs`]; the leading `2` keeps it apart from the limb payload,
/// which starts `1, 1`.
pub fn compute_lbfv_pk_row_commitment_from_limbs<let L: u32>(
    row_index: u32,
    limb_commitments: [Field; L],
) -> Field {
    let mut payload = [2, row_index as Field, L as Field].as_vector();
    for l in 0..L {
        payload = payload.push_back(limb_commitments[l]);
    }
    compute_commitment(payload, DS_PK_GENERATION_LIMB_V1)
}

/// [`compute_lbfv_pk_limb_commitment`] for the circuit that **creates** it. Its own centered range
/// check already keeps every digit in its slot, so plain packing is injective. Same value.
pub fn compute_lbfv_pk_limb_commitment_bounded<let N: u32, let BIT_PK: u32>(
    row_index: u32,
    limb_index: u32,
    pk0: Polynomial<N>,
) -> Field {
    let mut payload = [1, 1, row_index as Field, limb_index as Field, N as Field].as_vector();
    payload = single_polynomial_payload::<N, BIT_PK>(payload, pk0);
    compute_commitment(payload, DS_PK_GENERATION_LIMB_V1)
}

/// l-BFV public-key row commitment, opened from the coefficients.
pub fn compute_lbfv_pk_row_commitment<let N: u32, let L: u32, let BIT_PK: u32>(
    row_index: u32,
    pk0: [Polynomial<N>; L],
) -> Field {
    let mut limbs: [Field; L] = [0; L];
    for l in 0..L {
        limbs[l] = compute_lbfv_pk_limb_commitment::<N, BIT_PK>(row_index, l, pk0[l]);
    }
    compute_lbfv_pk_row_commitment_from_limbs(row_index, limbs)
}

pub fn compute_lbfv_pk_limb_commitment<let N: u32, let BIT_PK: u32>(
    row_index: u32,
    limb_index: u32,
    pk0: Polynomial<N>,
) -> Field {
    let mut payload = [1, 1, row_index as Field, limb_index as Field, N as Field].as_vector();
    payload = single_polynomial_payload_checked::<N, BIT_PK>(payload, pk0);
    compute_commitment(payload, DS_PK_GENERATION_LIMB_V1)
}

/// [`compute_multiple_polynomial_commitment`] for a circuit that **opens** this commitment.
pub fn compute_multiple_polynomial_commitment_checked<let N: u32, let L: u32, let BIT: u32>(
    polynomials: [Polynomial<N>; L],
    domain_separator: [u8; 64],
) -> Field {
    let payload = multiple_polynomial_payload_checked::<N, L, BIT>([].as_vector(), polynomials);
    compute_commitment(payload, domain_separator)
}

/// [`compute_threshold_pk_commitment`] for a circuit that **opens** this commitment rather than
/// creating it (C5). Asserts each packed digit fits its slot, which makes the opening unique and so
/// forces the opened `pk0` to equal the `pk0` C1 committed. Produces the same value as the plain
/// helper, so C1 needs no change.
pub fn compute_threshold_pk_commitment_checked<let N: u32, let L: u32, let BIT_PK: u32>(
    pk0: [Polynomial<N>; L],
) -> Field {
    let payload = multiple_polynomial_payload_checked::<N, L, BIT_PK>([].as_vector(), pk0);
    compute_commitment(payload, DS_PK_GENERATION)
}

pub fn compute_share_computation_sk_commitment<let N: u32, let BIT_SK: u32>(
    sk: Polynomial<N>,
) -> Field {
    let payload = single_polynomial_payload::<N, BIT_SK>([].as_vector(), sk);
    compute_commitment(payload, DS_SHARE_COMPUTATION)
}

/// [`compute_share_computation_sk_commitment`] for a circuit that **opens** this commitment rather
/// than creating it (C2a). C1 creates it and bounds `sk` to the trinary range, so making the opening
/// unique forces the witness to equal that `sk`.
pub fn compute_share_computation_sk_commitment_checked<let N: u32, let BIT_SK: u32>(
    sk: Polynomial<N>,
) -> Field {
    let payload = single_polynomial_payload_checked::<N, BIT_SK>([].as_vector(), sk);
    compute_commitment(payload, DS_SHARE_COMPUTATION)
}

pub fn compute_share_computation_e_sm_commitment<let N: u32, let L: u32, let BIT_E_SM: u32>(
    e_sm: [Polynomial<N>; L],
) -> Field {
    let payload = multiple_polynomial_payload::<N, L, BIT_E_SM>([].as_vector(), e_sm);
    compute_commitment(payload, DS_SHARE_COMPUTATION)
}

pub fn compute_share_encryption_commitment_from_message<let N: u32, let BIT_MSG: u32>(
    message: Polynomial<N>,
) -> Field {
    let payload = single_polynomial_payload::<N, BIT_MSG>([].as_vector(), message);
    compute_commitment(payload, DS_SHARE_ENCRYPTION)
}

/// Compute a domain-separated commitment for one secret chunk.
pub fn compute_sc_secret_chunk_commitment<let CHUNK_SIZE: u32, let BIT: u32>(
    kind_tag: Field,
    chunk_idx: u32,
    n: u32,
    chunk_poly: Polynomial<CHUNK_SIZE>,
) -> Field {
    let mut payload =
        [0, kind_tag, chunk_idx as Field, n as Field, CHUNK_SIZE as Field].as_vector();
    payload = single_polynomial_payload_checked::<CHUNK_SIZE, BIT>(payload, chunk_poly);
    compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK)
}

/// Compute a domain-separated commitment for one ESM chunk across all CRT limbs.
pub fn compute_sc_esm_secret_chunk_commitment<let CHUNK_SIZE: u32, let L: u32, let BIT: u32>(
    chunk_idx: u32,
    n: u32,
    polynomials: [Polynomial<CHUNK_SIZE>; L],
) -> Field {
    let mut payload = [0, 1, chunk_idx as Field, n as Field, CHUNK_SIZE as Field].as_vector();
    payload = multiple_polynomial_payload_checked::<CHUNK_SIZE, L, BIT>(payload, polynomials);
    compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK)
}

/// Compute a domain-separated commitment for one party share chunk.
pub fn compute_sc_party_share_chunk_commitment<let CHUNK_SIZE: u32, let BIT: u32>(
    party_idx: u32,
    mod_idx: u32,
    chunk_idx: u32,
    n: u32,
    chunk_poly: Polynomial<CHUNK_SIZE>,
) -> Field {
    let mut payload = [
        0,
        2,
        party_idx as Field,
        mod_idx as Field,
        chunk_idx as Field,
        n as Field,
        CHUNK_SIZE as Field,
    ]
        .as_vector();
    payload = single_polynomial_payload_checked::<CHUNK_SIZE, BIT>(payload, chunk_poly);
    compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK)
}

/// [`compute_sc_party_share_chunk_commitment`] for the chunk circuit that **creates** it. The
/// circuit range-checks every share to `[0, q)`, which keeps each packed digit in its slot, so plain
/// packing is injective. Same value.
pub fn compute_sc_party_share_chunk_commitment_bounded<let CHUNK_SIZE: u32, let BIT: u32>(
    party_idx: u32,
    mod_idx: u32,
    chunk_idx: u32,
    n: u32,
    chunk_poly: Polynomial<CHUNK_SIZE>,
) -> Field {
    let mut payload = [
        0,
        2,
        party_idx as Field,
        mod_idx as Field,
        chunk_idx as Field,
        n as Field,
        CHUNK_SIZE as Field,
    ]
        .as_vector();
    payload = single_polynomial_payload::<CHUNK_SIZE, BIT>(payload, chunk_poly);
    compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK)
}

/// Compute the root commitment for secret chunk commitments.
pub fn compute_sc_secret_chunk_root_commitment(
    kind_tag: Field,
    n: u32,
    chunk_size: u32,
    chunk_commitments: [Field],
) -> Field {
    let mut payload = [1, kind_tag, n as Field, chunk_size as Field].as_vector();
    for i in 0..chunk_commitments.len() {
        payload = payload.push_back(chunk_commitments[i]);
    }
    compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK)
}

// Commitment kind tags for user_data_encryption (ct0/ct1). Distinguishes which witness group a
// chunk commitment belongs to so values from different groups/legs never collide under the
// shared DS_USER_DATA_ENCRYPTION_CHUNK domain separator (same purpose as DKG's SK=0/ESM=1
// kind_tag).
//
// `u` deliberately has ONE tag shared by both legs, unlike every other group here. ct0 and ct1
// encrypt under the same randomness `u`, and the `user_data_encryption` wrapper proves that by
// asserting ct0's and ct1's `u` commitments are equal. A per-leg tag would make those two
// commitments differ for one and the same `u`, so that assert could never be satisfied - the
// tag has to be shared for the cross-leg binding to work at all.
pub global UDE_KIND_U: Field = 0;
pub global UDE_KIND_CT0_E0: Field = 1;
pub global UDE_KIND_CT0_K1: Field = 2;
pub global UDE_KIND_CT0_R2: Field = 3;
pub global UDE_KIND_CT0_R1: Field = 4;
pub global UDE_KIND_CT1_E1: Field = 6;
pub global UDE_KIND_CT1_P2: Field = 7;
pub global UDE_KIND_CT1_P1: Field = 8;

/// The leading fields of every user_data_encryption chunk payload. One owner, so the checked and
/// bounded helpers below cannot drift apart: a leaf creates a commitment with one and a parent opens
/// it with the other.
fn ude_chunk_payload_header(kind_tag: Field, chunk_idx: u32, n: u32, chunk_size: u32) -> [Field] {
    [0, kind_tag, chunk_idx as Field, n as Field, chunk_size as Field].as_vector()
}

/// Compute a domain-separated commitment for one user_data_encryption chunk (single polynomial:
/// u, e0, k1, or e1). `kind_tag` is one of the `UDE_KIND_*` constants above.
///
/// For a circuit that **opens** the commitment (the identity's `u`, the top level's `k1`): the
/// checked packing makes the opening unique. The leaf that creates it uses
/// [`compute_ude_chunk_commitment_bounded`], which gives the same value.
pub fn compute_ude_chunk_commitment<let CHUNK_SIZE: u32, let BIT: u32>(
    kind_tag: Field,
    chunk_idx: u32,
    n: u32,
    chunk_poly: Polynomial<CHUNK_SIZE>,
) -> Field {
    let payload = single_polynomial_payload_checked::<CHUNK_SIZE, BIT>(
        ude_chunk_payload_header(kind_tag, chunk_idx, n, CHUNK_SIZE),
        chunk_poly,
    );
    compute_commitment(payload, DS_USER_DATA_ENCRYPTION_CHUNK)
}

/// [`compute_ude_chunk_commitment`] for the circuit that **creates** the commitment over values it
/// has range-checked itself (the chunk leaves). Those bounds already keep every packed digit in its
/// slot, so the per-digit asserts of the checked packing would only repeat them. Same value; a
/// circuit that opens the commitment must use the checked helper.
pub fn compute_ude_chunk_commitment_bounded<let CHUNK_SIZE: u32, let BIT: u32>(
    kind_tag: Field,
    chunk_idx: u32,
    n: u32,
    chunk_poly: Polynomial<CHUNK_SIZE>,
) -> Field {
    let payload = single_polynomial_payload::<CHUNK_SIZE, BIT>(
        ude_chunk_payload_header(kind_tag, chunk_idx, n, CHUNK_SIZE),
        chunk_poly,
    );
    compute_commitment(payload, DS_USER_DATA_ENCRYPTION_CHUNK)
}

/// Commitment for one user_data_encryption chunk across all CRT limbs (`r1is` or `p1is`), for the
/// leaf that creates it over range-checked values; see [`compute_ude_chunk_commitment_bounded`].
/// No circuit opens these commitments, so there is no checked counterpart.
pub fn compute_ude_multi_chunk_commitment_bounded<let CHUNK_SIZE: u32, let L: u32, let BIT: u32>(
    kind_tag: Field,
    chunk_idx: u32,
    n: u32,
    polynomials: [Polynomial<CHUNK_SIZE>; L],
) -> Field {
    let payload = multiple_polynomial_payload::<CHUNK_SIZE, L, BIT>(
        ude_chunk_payload_header(kind_tag, chunk_idx, n, CHUNK_SIZE),
        polynomials,
    );
    compute_commitment(payload, DS_USER_DATA_ENCRYPTION_CHUNK)
}

/// Compute the root commitment for a set of user_data_encryption chunk commitments. Shared by
/// both single-polynomial and multi-limb chunk commitments, the same
/// way `compute_sc_secret_chunk_root_commitment` is shared by SK/ESM in the DKG chunk pipeline.
pub fn compute_ude_chunk_root_commitment(
    kind_tag: Field,
    n: u32,
    chunk_size: u32,
    chunk_commitments: [Field],
) -> Field {
    let mut payload = [1, kind_tag, n as Field, chunk_size as Field].as_vector();
    for i in 0..chunk_commitments.len() {
        payload = payload.push_back(chunk_commitments[i]);
    }
    compute_commitment(payload, DS_USER_DATA_ENCRYPTION_CHUNK)
}

/// Compute the root commitment for one party share and CRT modulus.
pub fn compute_sc_party_share_chunk_root_commitment(
    party_idx: u32,
    mod_idx: u32,
    n: u32,
    chunk_size: u32,
    chunk_commitments: [Field],
) -> Field {
    let mut payload =
        [1, 2, party_idx as Field, mod_idx as Field, n as Field, chunk_size as Field].as_vector();
    for i in 0..chunk_commitments.len() {
        payload = payload.push_back(chunk_commitments[i]);
    }
    compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK)
}

/// Compute the SK root from the C1 polynomial orientation.
pub fn compute_sc_sk_secret_root_from_polynomial<let N: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32, let BIT: u32>(
    sk: Polynomial<N>,
) -> Field {
    // Every coefficient must land in exactly one chunk, or the uncovered ones are never committed.
    assert(N_CHUNKS * CHUNK_SIZE == N);
    let mut chunks: [Field; N_CHUNKS] = [0; N_CHUNKS];
    for chunk_idx in 0..N_CHUNKS {
        let start = N - ((chunk_idx + 1) * CHUNK_SIZE);
        // `compute_sc_secret_chunk_commitment(0, chunk_idx, N, sk[start..start + CHUNK_SIZE])`,
        // packed straight from `sk`; see `flatten_with`.
        let mut payload = [0, 0, chunk_idx as Field, N as Field, CHUNK_SIZE as Field].as_vector();
        payload = flatten_with::<CHUNK_SIZE, BIT, _>(
            payload,
            |offset| sk.coefficients[start + offset],
            true,
        );
        chunks[chunk_idx] = compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK);
    }
    compute_sc_secret_chunk_root_commitment(0, N, CHUNK_SIZE, chunks)
}

/// Compute the ESM root from the C1 polynomial orientation.
pub fn compute_sc_esm_secret_root_from_polynomial<let N: u32, let L: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32, let BIT: u32>(
    e_sm: [Polynomial<N>; L],
) -> Field {
    // Every coefficient must land in exactly one chunk, or the uncovered ones are never committed.
    assert(N_CHUNKS * CHUNK_SIZE == N);
    let mut chunks: [Field; N_CHUNKS] = [0; N_CHUNKS];
    for chunk_idx in 0..N_CHUNKS {
        let start = N - ((chunk_idx + 1) * CHUNK_SIZE);
        // `compute_sc_esm_secret_chunk_commitment` of each limb's `[start, start + CHUNK_SIZE)`
        // slice, packed straight from `e_sm`; see `flatten_with`.
        let mut payload = [0, 1, chunk_idx as Field, N as Field, CHUNK_SIZE as Field].as_vector();
        for mod_idx in 0..L {
            payload = flatten_with::<CHUNK_SIZE, BIT, _>(
                payload,
                |offset| e_sm[mod_idx].coefficients[start + offset],
                true,
            );
        }
        chunks[chunk_idx] = compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK);
    }
    compute_sc_secret_chunk_root_commitment(1, N, CHUNK_SIZE, chunks)
}

/// Compute a share root from a C3/C4 message polynomial.
pub fn compute_sc_party_share_root_from_polynomial<let N: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32, let BIT: u32>(
    party_idx: u32,
    mod_idx: u32,
    message: Polynomial<N>,
) -> Field {
    // Every coefficient must land in exactly one chunk, or the uncovered ones are never committed.
    assert(N_CHUNKS * CHUNK_SIZE == N);
    let mut chunks: [Field; N_CHUNKS] = [0; N_CHUNKS];
    for chunk_idx in 0..N_CHUNKS {
        let start = N - ((chunk_idx + 1) * CHUNK_SIZE);
        chunks[chunk_idx] = party_share_chunk_commitment_with::<CHUNK_SIZE, BIT, _>(
            party_idx,
            mod_idx,
            chunk_idx,
            N,
            |offset| message.coefficients[start + offset],
        );
    }
    compute_sc_party_share_chunk_root_commitment(party_idx, mod_idx, N, CHUNK_SIZE, chunks)
}

/// [`compute_sc_party_share_root_from_polynomial`] of the **reversed** `share`, read in place: the
/// same root C2 commits for a share whose coefficients are lowest-degree-first, without building
/// the reversed polynomial.
pub fn compute_sc_party_share_root_from_reversed<let N: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32, let BIT: u32>(
    party_idx: u32,
    mod_idx: u32,
    share: Polynomial<N>,
) -> Field {
    // Every coefficient must land in exactly one chunk, or the uncovered ones are never committed.
    assert(N_CHUNKS * CHUNK_SIZE == N);
    let mut chunks: [Field; N_CHUNKS] = [0; N_CHUNKS];
    for chunk_idx in 0..N_CHUNKS {
        let start = N - ((chunk_idx + 1) * CHUNK_SIZE);
        chunks[chunk_idx] = party_share_chunk_commitment_with::<CHUNK_SIZE, BIT, _>(
            party_idx,
            mod_idx,
            chunk_idx,
            N,
            |offset| share.coefficients[N - 1 - (start + offset)],
        );
    }
    compute_sc_party_share_chunk_root_commitment(party_idx, mod_idx, N, CHUNK_SIZE, chunks)
}

/// [`compute_sc_party_share_root_from_reversed`] given the share already packed: `carriers[g]` is the
/// carrier C2 hashed for reversed coefficients `4g..4g + 4`, so chunk `c` absorbs carriers
/// `start / 4..(start + CHUNK_SIZE) / 4` with `start = N - (c + 1) * CHUNK_SIZE`. Same root, no
/// per-coefficient work: the carriers are bound by the hash itself, and C2 range-checked every digit
/// in them when it created the commitment. Requires the 4-slot layout (`BIT` 49..=52).
pub fn compute_sc_party_share_root_from_carriers<let N: u32, let N_CHUNKS: u32, let CHUNK_SIZE: u32>(
    party_idx: u32,
    mod_idx: u32,
    carriers: [Field; N / 4],
) -> Field {
    // Every coefficient must land in exactly one chunk, and every chunk must hold whole carriers.
    assert(N_CHUNKS * CHUNK_SIZE == N);
    assert(CHUNK_SIZE % 4 == 0);
    let mut chunks: [Field; N_CHUNKS] = [0; N_CHUNKS];
    for chunk_idx in 0..N_CHUNKS {
        let first = (N - ((chunk_idx + 1) * CHUNK_SIZE)) / 4;
        let mut payload = [
            0,
            2,
            party_idx as Field,
            mod_idx as Field,
            chunk_idx as Field,
            N as Field,
            CHUNK_SIZE as Field,
        ]
            .as_vector();
        for g in 0..(CHUNK_SIZE / 4) {
            payload = payload.push_back(carriers[first + g]);
        }
        chunks[chunk_idx] = compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK);
    }
    compute_sc_party_share_chunk_root_commitment(party_idx, mod_idx, N, CHUNK_SIZE, chunks)
}

/// [`compute_aggregated_shares_commitment`] given each limb already packed in the same 4-slot layout
/// (`carriers[l][g]` holds coefficients `4g..4g + 4` of limb `l`). Same value.
pub fn compute_aggregated_shares_commitment_from_carriers<let N: u32, let L: u32>(
    carriers: [[Field; N / 4]; L],
) -> Field {
    compute_packed_polynomials_commitment::<N / 4, L>(carriers, DS_AGGREGATED_SHARES)
}

/// [`compute_multiple_polynomial_commitment`] given every limb already packed in the 4-slot layout
/// that `multiple_polynomial_payload` builds (`carriers[l][g]` holds coefficients `4g..4g + 4`).
/// Same value.
pub fn compute_packed_polynomials_commitment<let N4: u32, let L: u32>(
    carriers: [[Field; N4]; L],
    domain_separator: [u8; 64],
) -> Field {
    let mut payload: [Field] = [].as_vector();
    for l in 0..L {
        for g in 0..N4 {
            payload = payload.push_back(carriers[l][g]);
        }
    }
    compute_commitment(payload, domain_separator)
}

/// One limb commitment `H(header || carriers)` of a polynomial already packed in the 4-slot layout.
fn packed_limb_commitment<let N4: u32>(
    header: [Field; 5],
    carriers: [Field; N4],
    domain_separator: [u8; 64],
) -> Field {
    let mut payload = header.as_vector();
    for g in 0..N4 {
        payload = payload.push_back(carriers[g]);
    }
    compute_commitment(payload, domain_separator)
}

/// [`compute_lbfv_pk_row_commitment`] given each `pk0` limb as the carriers `lbfv_pk_generation`
/// packed. Same value. The carriers need no digit check: the hash binds them to the creator's,
/// whose digits that circuit range-checked to the centred window.
pub fn compute_lbfv_pk_row_commitment_from_carriers<let N: u32, let L: u32>(
    row_index: u32,
    carriers: [[Field; N / 4]; L],
) -> Field {
    let mut limbs: [Field; L] = [0; L];
    for l in 0..L {
        limbs[l] = packed_limb_commitment::<N / 4>(
            [1, 1, row_index as Field, l as Field, N as Field],
            carriers[l],
            DS_PK_GENERATION_LIMB_V1,
        );
    }
    compute_lbfv_pk_row_commitment_from_limbs(row_index, limbs)
}

/// [`compute_rlk_component_commitment`] given each limb as the carriers `rlk_generation` packed.
/// Same value; as for the PK row, the hash carries the creator's digit bounds.
pub fn compute_rlk_component_commitment_from_carriers<let N: u32, let L: u32>(
    component: u32,
    row_index: u32,
    carriers: [[Field; N / 4]; L],
) -> Field {
    assert(component < 2, "RLK component must be d0 or d2");
    let kind_tag = 2 + component as Field;
    let mut limbs: [Field; L] = [0; L];
    for l in 0..L {
        limbs[l] = packed_limb_commitment::<N / 4>(
            [1, kind_tag, row_index as Field, l as Field, N as Field],
            carriers[l],
            DS_RLK_GENERATION_LIMB_V1,
        );
    }
    compute_rlk_row_commitment_from_limbs(kind_tag, row_index, limbs)
}

/// `compute_sc_party_share_chunk_commitment` (checked) of the chunk whose coefficient `i` is
/// `value_at(i)`.
fn party_share_chunk_commitment_with<let CHUNK_SIZE: u32, let BIT: u32, Env>(
    party_idx: u32,
    mod_idx: u32,
    chunk_idx: u32,
    n: u32,
    value_at: fn[Env](u32) -> Field,
) -> Field {
    let mut payload = [
        0,
        2,
        party_idx as Field,
        mod_idx as Field,
        chunk_idx as Field,
        n as Field,
        CHUNK_SIZE as Field,
    ]
        .as_vector();
    payload = flatten_with::<CHUNK_SIZE, BIT, _>(payload, value_at, true);
    compute_commitment(payload, DS_SHARE_COMPUTATION_CHUNK)
}

/// [`compute_share_encryption_commitment_from_message`] for a circuit that **opens** this
/// commitment rather than creating it (C4). Asserts each packed digit fits its slot, forcing the
/// opened share to equal the share C2 committed. Same value as the plain helper, so C2 and C3 need
/// no change.
pub fn compute_share_encryption_commitment_from_message_checked<let N: u32, let BIT_MSG: u32>(
    message: Polynomial<N>,
) -> Field {
    let payload = single_polynomial_payload_checked::<N, BIT_MSG>([].as_vector(), message);
    compute_commitment(payload, DS_SHARE_ENCRYPTION)
}

pub fn compute_aggregated_shares_commitment<let N: u32, let L: u32, let BIT_MSG: u32>(
    agg_shares: [Polynomial<N>; L],
) -> Field {
    let payload = multiple_polynomial_payload::<N, L, BIT_MSG>([].as_vector(), agg_shares);
    compute_commitment(payload, DS_AGGREGATED_SHARES)
}

/// Commitment to a threshold decryption share: all CRT limbs, first `K` coefficients per limb
/// (same layout as `Polynomial<K>` in decrypted_shares_aggregation).
///
/// `NATIVE_BIT_WIDTH` must cover native coefficients in \([0, q_l)\) per limb (not centered `d` bounds).
pub fn compute_threshold_decryption_share_commitment<let K: u32, let L: u32, let NATIVE_BIT_WIDTH: u32>(
    d_share_limbs: [Polynomial<K>; L],
) -> Field {
    let payload =
        multiple_polynomial_payload::<K, L, NATIVE_BIT_WIDTH>([].as_vector(), d_share_limbs);
    compute_commitment(payload, DS_THRESHOLD_DECRYPTION_SHARE)
}

/// [`compute_threshold_decryption_share_commitment`] for a circuit that **opens** this commitment
/// rather than creating it (C7). C6 creates it and pins each coefficient to a native residue in
/// \([0, q)\) via `verify_d_native_trunc_binding`, so asserting the digits here makes the opening
/// unique and forces the opened share to equal the one C6 committed. Produces the same value as the
/// plain version for any input the plain version could legitimately have committed.
pub fn compute_threshold_decryption_share_commitment_checked<let K: u32, let L: u32, let NATIVE_BIT_WIDTH: u32>(
    d_share_limbs: [Polynomial<K>; L],
) -> Field {
    let payload = multiple_polynomial_payload_checked::<K, L, NATIVE_BIT_WIDTH>(
        [].as_vector(),
        d_share_limbs,
    );
    compute_commitment(payload, DS_THRESHOLD_DECRYPTION_SHARE)
}

/// [`compute_share_computation_e_sm_commitment`] for a circuit that **opens** this commitment rather
/// than creating it (C2b). C1 creates it and bounds each `e_sm` limb to a centered residue.
pub fn compute_share_computation_e_sm_commitment_checked<let N: u32, let L: u32, let BIT_E_SM: u32>(
    e_sm: [Polynomial<N>; L],
) -> Field {
    let payload = multiple_polynomial_payload_checked::<N, L, BIT_E_SM>([].as_vector(), e_sm);
    compute_commitment(payload, DS_SHARE_COMPUTATION)
}

pub fn compute_pk_aggregation_commitment<let N: u32, let L: u32, let BIT_PK: u32>(
    pk0: [Polynomial<N>; L],
    pk1: [Polynomial<N>; L],
) -> Field {
    let commit_pk0 = compute_multiple_polynomial_commitment::<N, L, BIT_PK>(pk0, DS_PK_AGGREGATION);
    let commit_pk1 = compute_multiple_polynomial_commitment::<N, L, BIT_PK>(pk1, DS_PK_AGGREGATION);

    let inputs = [commit_pk0, commit_pk1].as_vector();

    compute_commitment(inputs, DS_PK_AGGREGATION)
}

/// [`compute_pk_aggregation_commitment`] with the `pk1` half supplied as its commitment.
///
/// On the l-BFV path `pk1` is a fixed CRS row, so its commitment is a generated per-row constant
/// (`LBFV_CRS_ROW_COMMITMENTS`) and hashing the row in-circuit is wasted work. The result equals
/// `compute_pk_aggregation_commitment(pk0, row)` exactly.
pub fn compute_pk_aggregation_commitment_with_pk1_commitment<let N: u32, let L: u32, let BIT_PK: u32>(
    pk0: [Polynomial<N>; L],
    commit_pk1: Field,
) -> Field {
    let commit_pk0 = compute_multiple_polynomial_commitment::<N, L, BIT_PK>(pk0, DS_PK_AGGREGATION);
    compute_commitment([commit_pk0, commit_pk1].as_vector(), DS_PK_AGGREGATION)
}

/// Commit to the complete ordered l-BFV public-key row set.
pub fn compute_lbfv_public_key_commitment<let ROWS: u32>(row_commitments: [Field; ROWS]) -> Field {
    let mut payload = [1, ROWS as Field].as_vector();
    for row in 0..ROWS {
        payload = payload.push_back(row_commitments[row]);
    }
    compute_commitment(payload, DS_LBFV_PUBLIC_KEY_V1)
}

/// Commit to the complete ordered l-BFV relinearization-key row set.
pub fn compute_lbfv_rlk_commitment<let ROWS: u32>(
    d0_commitments: [Field; ROWS],
    d2_commitments: [Field; ROWS],
) -> Field {
    let mut payload = [1, ROWS as Field].as_vector();
    for row in 0..ROWS {
        payload = payload.push_back(d0_commitments[row]);
    }
    for row in 0..ROWS {
        payload = payload.push_back(d2_commitments[row]);
    }
    compute_commitment(payload, DS_LBFV_RLK_V1)
}

/// Commit to one versioned l-BFV public-key and relinearization-key pair.
pub fn compute_lbfv_key_envelope_commitment(
    public_key_commitment: Field,
    rlk_commitment: Field,
) -> Field {
    compute_commitment(
        [1, public_key_commitment, rlk_commitment].as_vector(),
        DS_LBFV_KEY_ENVELOPE_V1,
    )
}

#[test]
fn test_lbfv_key_envelope_commitment_matches_rust_vector() {
    let public_key = compute_lbfv_public_key_commitment([11, 22, 33, 44, 55]);
    let rlk = compute_lbfv_rlk_commitment([101, 102, 103, 104, 105], [201, 202, 203, 204, 205]);
    let envelope = compute_lbfv_key_envelope_commitment(public_key, rlk);

    assert(
        public_key == 8794038265432090420098367171184962926773673645207458062703877698737222004818,
    );
    assert(rlk == 8678089263775503676082767397312743320196209264612503417642947968755201858816);
    assert(
        envelope == 18365618805205987395009526854274153391479792244574329633954644120137733297549,
    );
}

/// l-BFV RLK generation: commitment to the ephemeral polynomial shared by all rows.
pub fn compute_rlk_r_commitment<let N: u32, let BIT_R: u32>(r: Polynomial<N>) -> Field {
    let payload = single_polynomial_payload_checked::<N, BIT_R>([0].as_vector(), r);
    compute_commitment(payload, DS_RLK_GENERATION)
}

/// Row commitment over the per-limb commitments of one RLK row component (`kind_tag` 2 = d0,
/// 3 = d2, matching the limb tags).
///
/// The row is committed through its limbs, not its coefficients, so `rlk_generation` and
/// `rlk_aggregation` agree on the value whether they hold the limb commitments or the
/// coefficients. Anyone opening the row recomputes the limb commitments, which pack with checked
/// digits, so the opening is unique and carries the row circuit's centered bound.
pub fn compute_rlk_row_commitment_from_limbs<let L: u32>(
    kind_tag: Field,
    row_index: u32,
    limb_commitments: [Field; L],
) -> Field {
    let mut payload = [3, kind_tag, row_index as Field, L as Field].as_vector();
    for l in 0..L {
        payload = payload.push_back(limb_commitments[l]);
    }
    compute_commitment(payload, DS_RLK_GENERATION)
}

/// l-BFV RLK row commitment to one row's `d0`, opened from the coefficients.
pub fn compute_rlk_d0_commitment<let N: u32, let L: u32, let BIT_D: u32>(
    row_index: u32,
    d0: [Polynomial<N>; L],
) -> Field {
    let mut limbs: [Field; L] = [0; L];
    for l in 0..L {
        limbs[l] = compute_rlk_limb_d0_commitment::<N, BIT_D>(row_index, l, d0[l]);
    }
    compute_rlk_row_commitment_from_limbs(2, row_index, limbs)
}

/// l-BFV RLK row commitment to one row's `d0` (`component == 0`) or `d2` (`component == 1`),
/// opened from the coefficients. Equals [`compute_rlk_d0_commitment`] or
/// [`compute_rlk_d2_commitment`]: the component only selects the kind tag.
pub fn compute_rlk_component_commitment<let N: u32, let L: u32, let BIT_D: u32>(
    component: u32,
    row_index: u32,
    values: [Polynomial<N>; L],
) -> Field {
    assert(component < 2, "RLK component must be d0 or d2");
    let kind_tag = 2 + component as Field;
    let mut limbs: [Field; L] = [0; L];
    for l in 0..L {
        limbs[l] =
            compute_rlk_indexed_limb_commitment::<N, BIT_D>(kind_tag, row_index, l, values[l]);
    }
    compute_rlk_row_commitment_from_limbs(kind_tag, row_index, limbs)
}

/// l-BFV RLK row commitment to one row's `d2`, opened from the coefficients.
pub fn compute_rlk_d2_commitment<let N: u32, let L: u32, let BIT_D: u32>(
    row_index: u32,
    d2: [Polynomial<N>; L],
) -> Field {
    let mut limbs: [Field; L] = [0; L];
    for l in 0..L {
        limbs[l] = compute_rlk_limb_d2_commitment::<N, BIT_D>(row_index, l, d2[l]);
    }
    compute_rlk_row_commitment_from_limbs(3, row_index, limbs)
}

fn compute_rlk_indexed_limb_commitment<let N: u32, let BIT: u32>(
    kind_tag: Field,
    row_index: u32,
    limb_index: u32,
    polynomial: Polynomial<N>,
) -> Field {
    let mut payload =
        [1, kind_tag, row_index as Field, limb_index as Field, N as Field].as_vector();
    payload = single_polynomial_payload_checked::<N, BIT>(payload, polynomial);
    compute_commitment(payload, DS_RLK_GENERATION_LIMB_V1)
}

/// [`compute_rlk_indexed_limb_commitment`] for the circuit that **creates** it. Its own centered
/// range check already keeps every digit in its slot, so plain packing is injective. Same value.
fn compute_rlk_indexed_limb_commitment_bounded<let N: u32, let BIT: u32>(
    kind_tag: Field,
    row_index: u32,
    limb_index: u32,
    polynomial: Polynomial<N>,
) -> Field {
    let mut payload =
        [1, kind_tag, row_index as Field, limb_index as Field, N as Field].as_vector();
    payload = single_polynomial_payload::<N, BIT>(payload, polynomial);
    compute_commitment(payload, DS_RLK_GENERATION_LIMB_V1)
}

/// [`compute_rlk_limb_d0_commitment`] for a creator that range-checked `d0`. Same value.
pub fn compute_rlk_limb_d0_commitment_bounded<let N: u32, let BIT_D: u32>(
    row_index: u32,
    limb_index: u32,
    d0: Polynomial<N>,
) -> Field {
    compute_rlk_indexed_limb_commitment_bounded::<N, BIT_D>(2, row_index, limb_index, d0)
}

/// [`compute_rlk_limb_d2_commitment`] for a creator that range-checked `d2`. Same value.
pub fn compute_rlk_limb_d2_commitment_bounded<let N: u32, let BIT_D: u32>(
    row_index: u32,
    limb_index: u32,
    d2: Polynomial<N>,
) -> Field {
    compute_rlk_indexed_limb_commitment_bounded::<N, BIT_D>(3, row_index, limb_index, d2)
}

pub fn compute_rlk_limb_d0_commitment<let N: u32, let BIT_D: u32>(
    row_index: u32,
    limb_index: u32,
    d0: Polynomial<N>,
) -> Field {
    compute_rlk_indexed_limb_commitment::<N, BIT_D>(2, row_index, limb_index, d0)
}

pub fn compute_rlk_limb_d2_commitment<let N: u32, let BIT_D: u32>(
    row_index: u32,
    limb_index: u32,
    d2: Polynomial<N>,
) -> Field {
    compute_rlk_indexed_limb_commitment::<N, BIT_D>(3, row_index, limb_index, d2)
}

pub fn compute_recursive_aggregation_commitment(payload: [Field]) -> Field {
    compute_commitment(payload, DS_RECURSIVE_AGGREGATION)
}

pub fn compute_vk_hash(vk_hashes: [Field]) -> Field {
    compute_commitment(vk_hashes, DS_VK_HASH)
}

/// [`compute_aggregated_shares_commitment`] for a circuit that **opens** this commitment rather than
/// creating it (C6). C4 creates it after `normalize_aggregated` has reduced and centered the
/// aggregate, so making the opening unique forces the witness to equal that canonical value.
pub fn compute_aggregated_shares_commitment_checked<let N: u32, let L: u32, let BIT_MSG: u32>(
    agg_shares: [Polynomial<N>; L],
) -> Field {
    let payload = multiple_polynomial_payload_checked::<N, L, BIT_MSG>([].as_vector(), agg_shares);
    compute_commitment(payload, DS_AGGREGATED_SHARES)
}

/// [`compute_ciphertext_commitment`] for a circuit that **opens** this commitment rather than
/// creating it (C6). No upstream circuit bounds the ciphertext limbs, so this buys injectivity
/// rather than canonicality — which is the property wanted here: it forces C6 to decrypt exactly
/// the ciphertext that was committed, whatever its representation.
pub fn compute_ciphertext_commitment_checked<let N: u32, let L: u32, let BIT_CT: u32>(
    ct0: [Polynomial<N>; L],
    ct1: [Polynomial<N>; L],
) -> Field {
    let commit_ct0 =
        compute_multiple_polynomial_commitment_checked::<N, L, BIT_CT>(ct0, DS_CIPHERTEXT);
    let commit_ct1 =
        compute_multiple_polynomial_commitment_checked::<N, L, BIT_CT>(ct1, DS_CIPHERTEXT);

    let inputs = [commit_ct0, commit_ct1].as_vector();

    compute_commitment(inputs, DS_CIPHERTEXT)
}

pub fn compute_ciphertext_commitment<let N: u32, let L: u32, let BIT_CT: u32>(
    ct0: [Polynomial<N>; L],
    ct1: [Polynomial<N>; L],
) -> Field {
    let commit_ct0 = compute_multiple_polynomial_commitment::<N, L, BIT_CT>(ct0, DS_CIPHERTEXT);
    let commit_ct1 = compute_multiple_polynomial_commitment::<N, L, BIT_CT>(ct1, DS_CIPHERTEXT);

    let inputs = [commit_ct0, commit_ct1].as_vector();

    compute_commitment(inputs, DS_CIPHERTEXT)
}

/// COMMITMENTS FOR CHALLENGES

pub fn compute_threshold_pk_challenge(payload: [Field]) -> Field {
    compute_commitment(payload, DS_CLG_PK_GENERATION)
}

pub fn compute_lbfv_pk_row_challenge(payload: [Field]) -> Field {
    compute_commitment(payload, DS_CLG_LBFV_PK_GENERATION_ROW_V1)
}

pub fn compute_rlk_generation_challenge(payload: [Field]) -> Field {
    compute_commitment(payload, DS_CLG_RLK_GENERATION)
}

pub fn compute_rlk_row_challenge(payload: [Field]) -> Field {
    compute_commitment(payload, DS_CLG_LBFV_RLK_GENERATION_ROW_V1)
}

pub fn compute_share_encryption_challenge<let L: u32>(payload: [Field]) -> [Field] {
    compute_challenge::<L>(payload, DS_CLG_SHARE_ENCRYPTION)
}

pub fn compute_threshold_share_decryption_challenge<let L: u32>(payload: [Field]) -> Field {
    compute_challenge::<L>(payload, DS_CLG_SHARE_DECRYPTION)[0]
}

pub fn compute_user_data_encryption_ct0_challenge<let L: u32>(payload: [Field]) -> [Field] {
    compute_challenge::<L>(payload, DS_CLG_USER_DATA_ENCRYPTION)
}

pub fn compute_user_data_encryption_ct1_challenge<let L: u32>(payload: [Field]) -> [Field] {
    compute_challenge::<L>(payload, DS_CLG_USER_DATA_ENCRYPTION)
}

// Guards the cross-leg `u` binding: the `user_data_encryption` wrapper proves ct0 and ct1 used
// the same randomness by asserting their `u` commitments are EQUAL. That only works while both
// legs commit `u` under the same kind tag - giving `u` a per-leg tag (as every other witness
// group here correctly has) silently makes the two roots differ for one and the same `u`, and
// the wrapper assert becomes unsatisfiable by any honest prover.
#[test]
fn test_u_commitment_matches_across_ct0_and_ct1_legs() {
    let u_chunk0: Polynomial<2> = Polynomial::new([7, 11]);
    let u_chunk1: Polynomial<2> = Polynomial::new([13, 17]);
    let n: u32 = 4;

    // The same chunk commitments and root that the ct0 leaf and round circuit compute for `u`...
    let ct0_c0 = compute_ude_chunk_commitment::<2, 8>(UDE_KIND_U, 0, n, u_chunk0);
    let ct0_c1 = compute_ude_chunk_commitment::<2, 8>(UDE_KIND_U, 1, n, u_chunk1);
    let ct0_u_root = compute_ude_chunk_root_commitment(UDE_KIND_U, n, 2, [ct0_c0, ct0_c1]);

    // ...and what the ct1 leaf and round circuit compute for the same `u`.
    let ct1_c0 = compute_ude_chunk_commitment::<2, 8>(UDE_KIND_U, 0, n, u_chunk0);
    let ct1_c1 = compute_ude_chunk_commitment::<2, 8>(UDE_KIND_U, 1, n, u_chunk1);
    let ct1_u_root = compute_ude_chunk_root_commitment(UDE_KIND_U, n, 2, [ct1_c0, ct1_c1]);

    assert(ct0_u_root == ct1_u_root, "ct0 and ct1 must agree on u for the wrapper's binding");

    // A different `u` must still give a different root - the binding has to have teeth.
    let other: Polynomial<2> = Polynomial::new([7, 12]);
    let other_c1 = compute_ude_chunk_commitment::<2, 8>(UDE_KIND_U, 1, n, other);
    let other_root = compute_ude_chunk_root_commitment(UDE_KIND_U, n, 2, [ct0_c0, other_c1]);
    assert(ct0_u_root != other_root);
}

/// The chunked roots read their chunks in place (`flatten_with`); they must equal committing each
/// copied chunk, the form C2's chunk circuits produce.
#[test]
fn test_chunked_roots_match_committing_copied_chunks() {
    let sk = Polynomial::new([1, -1, 0, 1, 0, 0, -1, 1]);
    let e0 = Polynomial::new([5, -9, 3, 0, 7, -2, 1, 4]);
    let e1 = Polynomial::new([-3, 2, 8, -6, 0, 1, -7, 9]);
    let share = Polynomial::new([11, 22, 33, 44, 55, 66, 77, 88]);

    let mut sk_chunks: [Field; 2] = [0; 2];
    let mut esm_chunks: [Field; 2] = [0; 2];
    let mut share_chunks: [Field; 2] = [0; 2];
    for chunk_idx in 0..2 {
        let start = 8 - ((chunk_idx + 1) * 4);
        let mut sk_c = [0; 4];
        let mut e0_c = [0; 4];
        let mut e1_c = [0; 4];
        let mut share_c = [0; 4];
        for offset in 0..4 {
            sk_c[offset] = sk.coefficients[start + offset];
            e0_c[offset] = e0.coefficients[start + offset];
            e1_c[offset] = e1.coefficients[start + offset];
            share_c[offset] = share.coefficients[start + offset];
        }
        sk_chunks[chunk_idx] =
            compute_sc_secret_chunk_commitment::<4, 2>(0, chunk_idx, 8, Polynomial::new(sk_c));
        esm_chunks[chunk_idx] = compute_sc_esm_secret_chunk_commitment::<4, 2, 5>(
            chunk_idx,
            8,
            [Polynomial::new(e0_c), Polynomial::new(e1_c)],
        );
        share_chunks[chunk_idx] = compute_sc_party_share_chunk_commitment::<4, 7>(
            1,
            0,
            chunk_idx,
            8,
            Polynomial::new(share_c),
        );
    }
    assert(
        compute_sc_sk_secret_root_from_polynomial::<8, 2, 4, 2>(sk)
            == compute_sc_secret_chunk_root_commitment(0, 8, 4, sk_chunks),
    );
    assert(
        compute_sc_esm_secret_root_from_polynomial::<8, 2, 2, 4, 5>([e0, e1])
            == compute_sc_secret_chunk_root_commitment(1, 8, 4, esm_chunks),
    );
    assert(
        compute_sc_party_share_root_from_polynomial::<8, 2, 4, 7>(1, 0, share)
            == compute_sc_party_share_chunk_root_commitment(1, 0, 8, 4, share_chunks),
    );

    let mut reversed = [0; 8];
    for i in 0..8 {
        reversed[7 - i] = share.coefficients[i];
    }
    assert(
        compute_sc_party_share_root_from_reversed::<8, 2, 4, 7>(1, 0, Polynomial::new(reversed))
            == compute_sc_party_share_root_from_polynomial::<8, 2, 4, 7>(1, 0, share),
    );
}

/// A leaf creates its chunk commitments with the bounded helpers and a parent opens them with the
/// checked ones, so both must give the same value for the same in-range values.
#[test]
fn ude_bounded_chunk_commitments_match_the_checked_packing() {
    let poly = Polynomial::new([3, -5]);
    assert(
        compute_ude_chunk_commitment_bounded::<2, 8>(UDE_KIND_U, 1, 4, poly)
            == compute_ude_chunk_commitment::<2, 8>(UDE_KIND_U, 1, 4, poly),
    );

    let polys = [Polynomial::new([7, -1]), Polynomial::new([0, 12])];
    let checked = compute_commitment(
        multiple_polynomial_payload_checked::<2, 2, 8>(
            ude_chunk_payload_header(UDE_KIND_CT0_R1, 0, 2, 2),
            polys,
        ),
        DS_USER_DATA_ENCRYPTION_CHUNK,
    );
    assert(
        compute_ude_multi_chunk_commitment_bounded::<2, 2, 8>(UDE_KIND_CT0_R1, 0, 2, polys)
            == checked,
    );
}
