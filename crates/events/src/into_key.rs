// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

/// This trait allows our keys to be responsive to multiple inputs
pub trait IntoKey {
    fn into_key(self) -> Vec<u8>;
}

/// Keys can be vectors of String
impl IntoKey for Vec<u8> {
    fn into_key(self) -> Vec<u8> {
        self
    }
}

/// Keys can be references to vectors of bytes (&Vec<u8>)
impl IntoKey for &Vec<u8> {
    fn into_key(self) -> Vec<u8> {
        self.clone()
    }
}

/// Keys can be vectors of String
impl IntoKey for Vec<String> {
    fn into_key(self) -> Vec<u8> {
        self.join("/").into_bytes()
    }
}

/// Keys can be vectors of &str
impl IntoKey for Vec<&str> {
    fn into_key(self) -> Vec<u8> {
        self.join("/").into_bytes()
    }
}

/// Keys can be String
impl IntoKey for String {
    fn into_key(self) -> Vec<u8> {
        self.into_bytes()
    }
}

/// Keys can be &String
impl IntoKey for &String {
    fn into_key(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// Keys can be &str
impl IntoKey for &str {
    fn into_key(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

/// Keys can be u128
impl IntoKey for u128 {
    fn into_key(self) -> Vec<u8> {
        // Ensuring big endian for ordering
        self.to_be_bytes().to_vec()
    }
}
