// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Sample values built from serde layouts, for tests that lock encoded layouts.
//!
//! A node reads bytes that an older release wrote, and peers on two releases exchange messages.
//! bincode writes a value in its serde layout: field order, field types, and variant order.
//! [`sample_rows`] builds sample values of a type from that layout, encodes them, and returns one
//! row per sample. [`assert_fixture`] compares the rows with a checked-in fixture.
//!
//! How the samples are built:
//! - Each enum variant that the type can reach gets its own sample. That sample forces the enum
//!   choices on the path to the variant and takes variant 0 everywhere else.
//! - Each value comes from a hash of its path. Two digests are recorded. The first hashes paths of
//!   field, type, and variant names, so swapping two fields of the same type changes it. The second
//!   hashes paths of positions only, so it changes only when the encoded shape changes, not when
//!   something is renamed.
//! - Some byte fields and sequences accept only one length, for example an `Address` (20 bytes) or
//!   an `EventId` (32). When a deserializer rejects a length, the sample is rebuilt with the next
//!   candidate length for that path.
//! - Past a depth limit, sequences and maps are empty and options are `None`, so recursive types
//!   end.
//!
//! Limits:
//! - A change between a signed and an unsigned integer of 8, 16, 32 or 128 bits is not detected,
//!   because both encode the same sample bytes. A 64-bit change is detected: `i64` samples are
//!   reduced to a range that timestamp fields accept, and `u64` samples are not.
//! - Enums are discovered by serde name. A generic enum used with two type arguments, or two enums
//!   with the same serde name, get per-variant rows only at the first path where they occur.
//! - Formats written by hand instead of through serde are out of scope, and so are values that a
//!   type stores as opaque bytes, such as an encrypted bincode value.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{self, Display};
use std::path::Path;

use serde::de::{
    self, DeserializeOwned, DeserializeSeed, EnumAccess, IntoDeserializer, MapAccess, SeqAccess,
    VariantAccess, Visitor,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Candidate lengths for a byte field.
const BYTE_LENGTHS: &[usize] = &[32, 20, 0, 16, 64, 65, 48, 96, 8, 1];

/// Candidate lengths for a sequence. `EventId` and `Seed` read a `Vec<u8>` of 32 elements.
const SEQ_LENGTHS: &[usize] = &[1, 32, 20, 0, 2, 16, 64, 65, 48, 96, 8];

/// Path depth after which sequences and maps are empty and options are `None`.
const MAX_DEPTH: usize = 48;

/// Rewrites the fixture instead of comparing when set.
const UPDATE_ENV: &str = "LAYOUT_LOCK_UPDATE";

// ── Synthetic deserializer ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct SynthError(String);

impl Display for SynthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SynthError {}

impl de::Error for SynthError {
    fn custom<T: Display>(msg: T) -> Self {
        SynthError(msg.to_string())
    }
}

/// An enum type found while building samples, with the choices that reach it.
#[derive(Clone)]
struct Discovery {
    name: &'static str,
    path: String,
    variants: &'static [&'static str],
    /// The choice of every enclosing enum, as (path, variant index).
    ancestors: Vec<(String, usize)>,
}

#[derive(Default)]
struct Run {
    /// Hash positional paths instead of named paths.
    positional: bool,
    /// Forced variant index by enum path. Other enums take variant 0.
    overrides: HashMap<String, usize>,
    /// Accepted length for each byte field or sequence, as an index into its candidate list.
    lengths: HashMap<String, usize>,
    /// The byte field or sequence served last. A failed build retries it with the next length.
    last_length: Option<(String, &'static [usize])>,
    /// Enum choices on the current path.
    stack: Vec<(String, usize)>,
    /// Enum types in the order they were found.
    discovered: Vec<Discovery>,
    known: HashSet<&'static str>,
}

/// A `Deserializer` that builds a value of any type from its serde layout.
struct Synth<'a> {
    run: &'a RefCell<Run>,
    /// Path of field, type, and variant names.
    path: String,
    /// Path of positions.
    position: String,
}

impl<'a> Synth<'a> {
    fn at(&self, name: impl Display, position: impl Display) -> Synth<'a> {
        Synth {
            run: self.run,
            path: format!("{}/{name}", self.path),
            position: format!("{}/{position}", self.position),
        }
    }

    fn word(&self) -> [u8; 32] {
        let key = if self.run.borrow().positional {
            &self.position
        } else {
            &self.path
        };
        Sha256::digest(key.as_bytes()).into()
    }

    fn u64(&self) -> u64 {
        u64::from_le_bytes(self.word()[..8].try_into().expect("8 bytes"))
    }

    fn u128(&self) -> u128 {
        u128::from_le_bytes(self.word()[..16].try_into().expect("16 bytes"))
    }

    fn deep(&self) -> bool {
        self.path.matches('/').count() > MAX_DEPTH
    }

    /// The length for this byte field or sequence, recorded as the retry candidate.
    fn length(&self, candidates: &'static [usize]) -> usize {
        let mut run = self.run.borrow_mut();
        let index = *run.lengths.get(&self.path).unwrap_or(&0);
        run.last_length = Some((self.path.clone(), candidates));
        candidates[index]
    }

    fn bytes(&self) -> Vec<u8> {
        let len = self.length(BYTE_LENGTHS);
        self.word().iter().copied().cycle().take(len).collect()
    }
}

struct Elements<'a> {
    parent: Synth<'a>,
    names: Option<&'static [&'static str]>,
    len: usize,
    next: usize,
}

impl<'de> SeqAccess<'de> for Elements<'_> {
    type Error = SynthError;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, SynthError> {
        if self.next == self.len {
            return Ok(None);
        }
        let index = self.next;
        self.next += 1;
        let element = match self.names {
            Some(names) => self.parent.at(names[index], index),
            None => self.parent.at(index, index),
        };
        seed.deserialize(element).map(Some)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.len - self.next)
    }
}

struct OneEntry<'a> {
    parent: Synth<'a>,
    done: bool,
}

impl<'de> MapAccess<'de> for OneEntry<'_> {
    type Error = SynthError;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, SynthError> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        seed.deserialize(self.parent.at("key", "k")).map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, SynthError> {
        seed.deserialize(self.parent.at("value", "v"))
    }
}

struct Variant<'a> {
    parent: Synth<'a>,
    index: u32,
}

impl<'de, 'a> EnumAccess<'de> for Variant<'a> {
    type Error = SynthError;
    type Variant = Synth<'a>;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Synth<'a>), SynthError> {
        let value = seed.deserialize(self.index.into_deserializer())?;
        Ok((value, self.parent))
    }
}

impl<'de> VariantAccess<'de> for Synth<'_> {
    type Error = SynthError;

    fn unit_variant(self) -> Result<(), SynthError> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, SynthError> {
        seed.deserialize(self)
    }

    fn tuple_variant<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        visitor.visit_seq(Elements {
            parent: self,
            names: None,
            len,
            next: 0,
        })
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        visitor.visit_seq(Elements {
            parent: self,
            names: Some(fields),
            len: fields.len(),
            next: 0,
        })
    }
}

impl<'de> de::Deserializer<'de> for Synth<'_> {
    type Error = SynthError;

    fn is_human_readable(&self) -> bool {
        false
    }

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, SynthError> {
        Err(SynthError(format!(
            "{}: deserialize_any is not supported by bincode",
            self.path
        )))
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_bool(self.u64() & 1 == 1)
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_i8(self.u64() as i8)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_i16(self.u64() as i16)
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_i32(self.u64() as i32)
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        // Timestamp fields (chrono `ts_seconds`) reject values outside the calendar range.
        visitor.visit_i64((self.u64() % 4_000_000_000) as i64)
    }

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_i128(self.u128() as i128)
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_u8(self.u64() as u8)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_u16(self.u64() as u16)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_u32(self.u64() as u32)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_u64(self.u64())
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_u128(self.u128())
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_f32(f32::from(self.u64() as u16) / 8.0)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_f64(f64::from(self.u64() as u32) / 8.0)
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_char(char::from(b'a' + (self.u64() % 26) as u8))
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_string(format!("s{:016x}", self.u64()))
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_byte_buf(self.bytes())
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_byte_buf(self.bytes())
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        if self.deep() {
            return visitor.visit_none();
        }
        visitor.visit_some(self.at("some", "s"))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        visitor.visit_newtype_struct(self.at(name, "n"))
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        let len = if self.deep() {
            0
        } else {
            self.length(SEQ_LENGTHS)
        };
        visitor.visit_seq(Elements {
            parent: self,
            names: None,
            len,
            next: 0,
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        visitor.visit_seq(Elements {
            parent: self,
            names: None,
            len,
            next: 0,
        })
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        self.at(name, "t").deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        let done = self.deep();
        visitor.visit_map(OneEntry { parent: self, done })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        visitor.visit_seq(Elements {
            parent: self.at(name, "r"),
            names: Some(fields),
            len: fields.len(),
            next: 0,
        })
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        let index = {
            let mut run = self.run.borrow_mut();
            let index = run
                .overrides
                .get(&self.path)
                .copied()
                .unwrap_or(0)
                .min(variants.len() - 1);
            if run.known.insert(name) {
                let ancestors = run.stack.clone();
                run.discovered.push(Discovery {
                    name,
                    path: self.path.clone(),
                    variants,
                    ancestors,
                });
            }
            run.stack.push((self.path.clone(), index));
            index
        };
        let parent = self.at(
            format_args!("{name}::{}", variants[index]),
            format_args!("v{index}"),
        );
        let result = visitor.visit_enum(Variant {
            parent,
            index: u32::try_from(index).expect("variant index fits u32"),
        });
        self.run.borrow_mut().stack.pop();
        result
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, _: V) -> Result<V::Value, SynthError> {
        Err(SynthError(format!(
            "{}: identifiers are only read by self-describing formats",
            self.path
        )))
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        visitor.visit_unit()
    }
}

/// Builds one value of `T` with the given enum choices, retrying byte fields and sequences that
/// reject a length.
fn synthesize<T: DeserializeOwned>(
    run: &RefCell<Run>,
    root: &str,
    overrides: &HashMap<String, usize>,
    positional: bool,
) -> T {
    {
        let mut state = run.borrow_mut();
        state.overrides = overrides.clone();
        state.positional = positional;
    }
    loop {
        {
            let mut state = run.borrow_mut();
            state.last_length = None;
            state.stack.clear();
        }
        let result = T::deserialize(Synth {
            run,
            path: root.to_string(),
            position: root.to_string(),
        });
        match result {
            Ok(value) => return value,
            Err(error) => {
                let mut state = run.borrow_mut();
                let Some((path, candidates)) = state.last_length.take() else {
                    panic!("{root}: cannot build a sample: {error}");
                };
                let index = state.lengths.entry(path.clone()).or_insert(0);
                *index += 1;
                assert!(
                    *index < candidates.len(),
                    "{root}: no candidate length is accepted at {path}: {error}"
                );
            }
        }
    }
}

/// Encodes a sample and checks that the production decoder reads it back to the same bytes.
fn encode<T: Serialize + DeserializeOwned>(sample: &T, root: &str, target: &str) -> Vec<u8> {
    let bytes = bincode::serialize(sample).expect("sample encodes");
    let decoded: T = e3_utils::deserialize_bounded(&bytes, u64::MAX)
        .unwrap_or_else(|error| panic!("{root} {target}: sample does not decode: {error}"));
    assert_eq!(
        bincode::serialize(&decoded).expect("decoded sample encodes"),
        bytes,
        "{root} {target}: sample does not survive a decode and encode"
    );
    bytes
}

fn row<T: Serialize + DeserializeOwned>(
    run: &RefCell<Run>,
    root: &str,
    target: &str,
    overrides: &HashMap<String, usize>,
    extra: &impl Fn(&T) -> String,
) -> String {
    let named: T = synthesize(run, root, overrides, false);
    let named_bytes = encode(&named, root, target);
    let positional: T = synthesize(run, root, overrides, true);
    let positional_bytes = encode(&positional, root, target);
    format!(
        "{root}\t{target}\t{}\t{}\t{}{}",
        named_bytes.len(),
        hex::encode(Sha256::digest(&named_bytes)),
        hex::encode(Sha256::digest(&positional_bytes)),
        extra(&named)
    )
}

/// Returns one fixture row per enum variant that `T` can reach, or a single row when `T` has no
/// enum.
///
/// A row is `root`, the forced `Enum::Variant` (`-` when there is none), the encoded length, the
/// digest of the named sample, the digest of the positional sample, and `extra` of the named
/// sample. `extra` must return an empty string or text that starts with a tab.
pub fn sample_rows<T, F>(root: &str, extra: F) -> Vec<String>
where
    T: Serialize + DeserializeOwned,
    F: Fn(&T) -> String,
{
    let run = RefCell::new(Run::default());
    let base = row(&run, root, "-", &HashMap::new(), &extra);
    if run.borrow().discovered.is_empty() {
        return vec![base];
    }

    let mut rows = Vec::new();
    let mut next = 0;
    loop {
        // Rows for one enum can discover more enums, which extend the list.
        let Some(discovery) = run.borrow().discovered.get(next).cloned() else {
            break;
        };
        next += 1;
        for (index, variant) in discovery.variants.iter().enumerate() {
            let mut overrides: HashMap<String, usize> =
                discovery.ancestors.iter().cloned().collect();
            overrides.insert(discovery.path.clone(), index);
            let target = format!("{}::{variant}", discovery.name);
            rows.push(row(&run, root, &target, &overrides, &extra));
        }
    }
    rows
}

/// Rows are matched by root and target.
fn key(line: &str) -> String {
    let mut parts = line.splitn(3, '\t');
    format!(
        "{}\t{}",
        parts.next().unwrap_or(""),
        parts.next().unwrap_or("")
    )
}

/// Compares `rows` with the fixture at `path`. With `LAYOUT_LOCK_UPDATE` set, rewrites the fixture
/// instead. The rewrite is refused in CI.
pub fn assert_fixture(path: &Path, rows: &[String]) {
    if std::env::var_os(UPDATE_ENV).is_some() {
        assert!(
            std::env::var_os("CI").is_none(),
            "{UPDATE_ENV} is refused in CI. Rewrite the fixture locally and review the diff."
        );
        let mut text = String::from(
            "# root\tforced variant\tbytes\tsha256 (named paths)\tsha256 (positional paths)\textra\n",
        );
        for row in rows {
            text.push_str(row);
            text.push('\n');
        }
        std::fs::write(path, text).expect("write the layout fixture");
        return;
    }

    let fixture = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let expected: BTreeMap<String, &str> = fixture
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| (key(line), line))
        .collect();
    let found: BTreeMap<String, &str> =
        rows.iter().map(|line| (key(line), line.as_str())).collect();

    let mut changes = Vec::new();
    for (key, line) in &expected {
        match found.get(key) {
            None => changes.push(format!("missing: {line}")),
            Some(now) if now != line => {
                changes.push(format!("changed:\n  was {line}\n  now {now}"))
            }
            Some(_) => {}
        }
    }
    for (key, line) in &found {
        if !expected.contains_key(key) {
            changes.push(format!("new: {line}"));
        }
    }
    assert!(
        changes.is_empty(),
        "{} layout rows differ from {}.\n{}\n\n\
         Columns: root, forced variant, bytes, digest of named paths, digest of positional paths, \
         extra.\n\
         - Only the named digest changed: a field, type, or variant was renamed, or two fields of \
         the same type were swapped. A swap changes what stored data means, so check which.\n\
         - The positional digest or the length changed: the encoding changed, and a node on the \
         previous release cannot read it. For a persisted type, increase SCHEMA_VERSION \
         (crates/sync/src/sync/schema_version.rs). For an event or a wire message, also change \
         the wire major (crates/net/src/network.rs) or protocol_version \
         (crates/config/protocol-release.toml), and name the upgrade class in the PR.\n\
         - Only an event ID changed: event identity changed, through a derived Hash or the \
         toolchain's DefaultHasher. Treat it as a protocol change.\n\
         - A new row: a variant, enum, or root was added or renamed. The previous release cannot \
         decode a value that uses a new variant. A stored value then blocks a rollback, and an \
         event or wire message breaks peers on the previous release, so name the upgrade class \
         in the PR. A variant inserted before others also moves the later ones, which shows as \
         changed rows.\n\
         - A missing row: a variant, enum, or root was removed or renamed. Stored data and \
         messages that use it no longer decode. Treat it like a positional change.\n\
         Then rewrite the fixture locally with {UPDATE_ENV}=1 and review the diff.",
        changes.len(),
        path.display(),
        changes.join("\n")
    );
}
