// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use core::fmt;
use std::sync::LazyLock;

use regex::Regex;

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

// Pre-compile the regex for efficiency
static EVENT_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"EventId\(0x([a-fA-F0-9]+)\)").unwrap());

/// Hashes a string to an ANSI 256 color within `[hue_min, hue_max]` degrees.
///
/// # Examples
/// ```ignore
/// hash_str_to_ansi_color_in_hue_range(s, 30.0, 300.0);   // orange to purple
/// hash_str_to_ansi_color_in_hue_range(s, 30.0, 330.0);   // full spectrum, no red
/// hash_str_to_ansi_color_in_hue_range(s, 0.0, 360.0);    // full spectrum
/// ```
fn hash_str_to_ansi_color_in_hue_range(s: &str, hue_min: f32, hue_max: f32) -> u8 {
    let hash: u32 = s
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));

    let hue = hue_min + (hash as f32 % (hue_max - hue_min));

    let (r, g, b) = hsv_to_rgb(hue, 1.0, 1.0);

    rgb_to_ansi256(r, g, b)
}

fn hsv_to_rgb(h: f32, s: f32, v: f32) -> (f32, f32, f32) {
    let c = v * s;
    let x = c * (1.0 - ((h / 60.0) % 2.0 - 1.0).abs());
    let m = v - c;

    let (r, g, b) = match (h / 60.0) as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };

    (r + m, g + m, b + m)
}

fn rgb_to_ansi256(r: f32, g: f32, b: f32) -> u8 {
    let r6 = (r * 5.0).round() as u8;
    let g6 = (g * 5.0).round() as u8;
    let b6 = (b * 5.0).round() as u8;

    16 + 36 * r6 + 6 * g6 + b6
}

pub fn colorize_event_ids<T: fmt::Debug>(value: &T) -> String {
    let s = format!("{:?}", value);
    let mut result = String::with_capacity(s.len() + 100);
    let mut last_end = 0;
    for cap in EVENT_ID_RE.captures_iter(&s) {
        let full_match = cap.get(0).unwrap();
        let hex_str = cap.get(1).unwrap().as_str();
        result.push_str(&s[last_end..full_match.start()]);
        let color = hash_str_to_ansi_color_in_hue_range(hex_str, 30.0, 330.0); // Avoiding red so
                                                                               // it does not look
                                                                               // like errors
        result.push_str(&format!(
            "\x1b[38;5;{}m{}\x1b[0m",
            color,
            full_match.as_str()
        ));
        last_end = full_match.end();
    }
    result.push_str(&s[last_end..]);
    result
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
