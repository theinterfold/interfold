// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use core::fmt;

/// Values up to this many bytes are printed in full.
const HEXF_FULL_BYTES: usize = 50;
/// Hex digits kept from each end of a longer value.
const HEXF_EDGE_DIGITS: usize = 25;

/// Formats bytes as hex. A long value prints its byte length and only its first and last
/// digits, so the cost does not depend on the value size.
pub fn hexf(data: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    if data.len() <= HEXF_FULL_BYTES {
        return write!(f, "0x{}", hex_digits(data));
    }
    let edge_bytes = HEXF_EDGE_DIGITS.div_ceil(2);
    let start = hex_digits(&data[..edge_bytes]);
    let end = hex_digits(&data[data.len() - edge_bytes..]);
    write!(
        f,
        "<bytes({}):0x{}..{}>",
        data.len(),
        &start[..HEXF_EDGE_DIGITS],
        &end[end.len() - HEXF_EDGE_DIGITS..]
    )
}

fn hex_digits(bytes: &[u8]) -> String {
    use fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[derive(Clone, Copy)]
pub enum Color {
    Black = 30,
    Red = 31,
    Green = 32,
    Yellow = 33,
    Blue = 34,
    Magenta = 35,
    Cyan = 36,
    White = 37,
    BrightBlack = 90,
    BrightRed = 91,
    BrightGreen = 92,
    BrightYellow = 93,
    BrightBlue = 94,
    BrightMagenta = 95,
    BrightCyan = 96,
    BrightWhite = 97,
}

pub fn colorize<T: std::fmt::Display>(s: T, color: Color) -> String {
    format!("\x1b[{}m{}\x1b[0m", color as u8, s)
}

#[cfg(test)]
mod tests {
    use super::hexf;
    use std::fmt;

    struct Hex<'a>(&'a [u8]);

    impl fmt::Debug for Hex<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            hexf(self.0, f)
        }
    }

    #[test]
    fn short_values_print_in_full() {
        assert_eq!(format!("{:?}", Hex(&[0x0a, 0xff])), "0x0aff");
        let fifty = [0x11u8; 50];
        assert_eq!(
            format!("{:?}", Hex(&fifty)),
            format!("0x{}", "11".repeat(50))
        );
    }

    #[test]
    fn long_values_report_bytes_and_edges() {
        let mut data = vec![0u8; 1_776_213];
        data[0] = 0xab;
        data[1_776_212] = 0xcd;
        assert_eq!(
            format!("{:?}", Hex(&data)),
            format!(
                "<bytes(1776213):0xab{}..{}cd>",
                "0".repeat(23),
                "0".repeat(23)
            )
        );
    }
}
