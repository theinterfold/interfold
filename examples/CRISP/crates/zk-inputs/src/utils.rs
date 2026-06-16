// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use eyre::{Context, Result};

/// JS Number has 53-bit integer precision. Values outside [-2^53+1, 2^53-1] lose precision when parsed.
/// e0_quotients from user_data_encryption_ct0 for example can have values larger than 2^53 - 1.
const JS_SAFE_INT_MAX: i64 = 9007199254740991; // 2^53 - 1

/// Recursively converts JSON numbers that would lose precision in JS to strings.
pub fn numbers_to_strings_for_js(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if !(-JS_SAFE_INT_MAX..=JS_SAFE_INT_MAX).contains(&i) {
                    return serde_json::Value::String(i.to_string());
                }
            } else if let Some(u) = n.as_u64() {
                if u > JS_SAFE_INT_MAX as u64 {
                    return serde_json::Value::String(u.to_string());
                }
            } else if n.as_f64().is_none_or(|f| {
                f < -JS_SAFE_INT_MAX as f64 || f > JS_SAFE_INT_MAX as f64
            }) {
                return serde_json::Value::String(n.to_string());
            }

            serde_json::Value::Number(n)
        }

        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(numbers_to_strings_for_js).collect())
        }

        serde_json::Value::Object(obj) => {
            let converted = obj
                .into_iter()
                .map(|(k, v)| (k, numbers_to_strings_for_js(v)))
                .collect();
            serde_json::Value::Object(converted)
        }

        other => other,
    }
}

/// Merges two JSON objects into one. All keys end up at the same level; keys from `b` overwrite `a` on conflict.
/// Numbers that would lose precision in JS (> 2^53) are converted to strings.
pub fn merge_json_objects(a: serde_json::Value, b: serde_json::Value) -> Result<String> {
    let mut merged: serde_json::Map<String, serde_json::Value> =
        serde_json::from_value(a).with_context(|| "First value is not a JSON object")?;
    let other: serde_json::Map<String, serde_json::Value> =
        serde_json::from_value(b).with_context(|| "Second value is not a JSON object")?;
    merged.extend(other);

    let safe = numbers_to_strings_for_js(serde_json::Value::Object(merged));
    serde_json::to_string(&safe).with_context(|| "Failed to serialize merged JSON")
}
