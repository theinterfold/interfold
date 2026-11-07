// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use derivative::Derivative;
use e3_utils::{AsBytesSerde, BytesSerde};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    hash::{DefaultHasher, Hash, Hasher},
    sync::LazyLock,
};

#[derive(Derivative, BytesSerde, Clone, Copy, PartialEq, Eq, Hash)]
#[derivative(Debug)]
pub struct EventId(#[derivative(Debug(format_with = "e3_utils::formatters::hexf"))] pub [u8; 32]);

impl EventId {
    pub fn hash<T: Hash>(value: T) -> Self {
        let mut hasher = Sha256::new();
        let mut std_hasher = DefaultHasher::new();
        value.hash(&mut std_hasher);
        hasher.update(std_hasher.finish().to_le_bytes());
        let result = hasher.finalize();
        EventId(result.into())
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base58_string = bs58::encode(&self.0).into_string();
        write!(f, "evt:{}", &base58_string[0..8])
    }
}

impl AsBytesSerde for EventId {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    fn try_from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        Ok(EventId(
            bytes.try_into().map_err(|_| "EventId requires 32 bytes")?,
        ))
    }
}

/// Matches the derived `Debug` output of `EventId`.
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

/// Formats `value` with `Debug` and colors each `EventId` in it by a hash of its bytes.
pub(crate) fn colorize_event_ids<T: fmt::Debug>(value: &T) -> String {
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
    use super::*;

    #[test]
    fn colorize_event_ids_matches_the_debug_output() {
        let id = EventId([0xab; 32]);
        let colored = colorize_event_ids(&Some(id));
        assert!(colored.starts_with("Some(\x1b[38;5;"), "{colored:?}");
        assert!(
            colored.ends_with(&format!("m{id:?}\x1b[0m)")),
            "{colored:?}"
        );
    }
}
