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
//! - Each enum variant that the type can reach gets its own row. That row forces the enum choices
//!   on the path to the variant and takes variant 0 everywhere else.
//! - Each value comes from a hash of its path. A row records two digests:
//!   - The named digest covers a sample whose values come from paths of field, type, and variant
//!     names, and a trace of the layout: the path, the serde kind, and the enum and variant of each
//!     value. A swap of two fields changes it, also of two `bool` or unit-enum fields whose sample
//!     values can be equal. A rename or a newtype wrapper changes it too.
//!   - The positional digest covers two samples whose values come from positions only: a full
//!     sample, and a minimal sample with each option `None`, each sequence and map empty where the
//!     type accepts that, and each `bool` the opposite of the full sample. It changes when the
//!     encoding changes. It does not change for a rename or a newtype wrapper, because bincode
//!     writes neither. The minimal sample shows a `skip_serializing_if` that drops a `None`, an
//!     empty value, or one of the two `bool` values.
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
//! - A fixture covers only the roots that its test lists.

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

/// Candidate lengths for a byte field in a minimal sample: empty where the type accepts that.
const MIN_BYTE_LENGTHS: &[usize] = &[0, 32, 20, 16, 64, 65, 48, 96, 8, 1];

/// Candidate lengths for a sequence in a minimal sample: empty where the type accepts that.
const MIN_SEQ_LENGTHS: &[usize] = &[0, 1, 32, 20, 2, 16, 64, 65, 48, 96, 8];

/// Candidate entry counts for a map in a minimal sample: empty where the type accepts that.
const MIN_MAP_ENTRIES: &[usize] = &[0, 1];

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

/// How a sample takes its values and its optional parts.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Mode {
    /// Values from named paths. The run also records the layout trace.
    #[default]
    Named,
    /// Values from positional paths.
    Positional,
    /// Values from positional paths, with each option `None` and each sequence and map empty where
    /// the type accepts that.
    Minimal,
}

#[derive(Default)]
struct Run {
    mode: Mode,
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
    /// The layout of the named sample: one entry per value, in encoding order.
    trace: Vec<String>,
}

/// A `Deserializer` that builds a value of any type from its serde layout.
struct Synth<'a> {
    run: &'a RefCell<Run>,
    /// Path of field, type, and variant names.
    path: String,
    /// Path of the positions that bincode writes.
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

    /// A step that bincode does not write, such as a struct or a newtype wrapper. Only the named
    /// path changes.
    fn named(&self, name: impl Display) -> Synth<'a> {
        Synth {
            run: self.run,
            path: format!("{}/{name}", self.path),
            position: self.position.clone(),
        }
    }

    fn mode(&self) -> Mode {
        self.run.borrow().mode
    }

    /// Records the serde kind of the value at this path in the layout trace.
    fn trace(&self, kind: impl Display) {
        let mut run = self.run.borrow_mut();
        if run.mode == Mode::Named {
            run.trace.push(format!("{}\t{kind}", self.path));
        }
    }

    fn word(&self) -> [u8; 32] {
        let key = if self.mode() == Mode::Named {
            &self.path
        } else {
            &self.position
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
        // A minimal sample tries other lengths first, so it keeps its own accepted lengths.
        let key = if run.mode == Mode::Minimal {
            format!("min:{}", self.path)
        } else {
            self.path.clone()
        };
        let index = *run.lengths.get(&key).unwrap_or(&0);
        run.last_length = Some((key, candidates));
        candidates[index]
    }

    fn bytes(&self) -> Vec<u8> {
        let candidates = if self.mode() == Mode::Minimal {
            MIN_BYTE_LENGTHS
        } else {
            BYTE_LENGTHS
        };
        let len = self.length(candidates);
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
        self.trace("bool");
        // The full and the minimal sample take opposite values, so a `skip_serializing_if` on
        // either value drops the field from one of them.
        let value = self.u64() & 1 == 1;
        visitor.visit_bool(value != (self.mode() == Mode::Minimal))
    }

    fn deserialize_i8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("i8");
        visitor.visit_i8(self.u64() as i8)
    }

    fn deserialize_i16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("i16");
        visitor.visit_i16(self.u64() as i16)
    }

    fn deserialize_i32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("i32");
        visitor.visit_i32(self.u64() as i32)
    }

    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("i64");
        // Timestamp fields (chrono `ts_seconds`) reject values outside the calendar range.
        visitor.visit_i64((self.u64() % 4_000_000_000) as i64)
    }

    fn deserialize_i128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("i128");
        visitor.visit_i128(self.u128() as i128)
    }

    fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("u8");
        visitor.visit_u8(self.u64() as u8)
    }

    fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("u16");
        visitor.visit_u16(self.u64() as u16)
    }

    fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("u32");
        visitor.visit_u32(self.u64() as u32)
    }

    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("u64");
        visitor.visit_u64(self.u64())
    }

    fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("u128");
        visitor.visit_u128(self.u128())
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("f32");
        visitor.visit_f32(f32::from(self.u64() as u16) / 8.0)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("f64");
        visitor.visit_f64(f64::from(self.u64() as u32) / 8.0)
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("char");
        visitor.visit_char(char::from(b'a' + (self.u64() % 26) as u8))
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("str");
        visitor.visit_string(format!("s{:016x}", self.u64()))
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("bytes");
        visitor.visit_byte_buf(self.bytes())
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        if self.deep() || self.mode() == Mode::Minimal {
            self.trace("option none");
            return visitor.visit_none();
        }
        self.trace("option some");
        visitor.visit_some(self.at("some", "s"))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        self.trace("unit");
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        self.trace(format_args!("unit struct {name}"));
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        self.trace(format_args!("newtype {name}"));
        visitor.visit_newtype_struct(self.named(name))
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        let len = if self.deep() {
            0
        } else if self.mode() == Mode::Minimal {
            self.length(MIN_SEQ_LENGTHS)
        } else {
            self.length(SEQ_LENGTHS)
        };
        self.trace(format_args!("seq {len}"));
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
        self.trace(format_args!("tuple {len}"));
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
        self.trace(format_args!("tuple struct {name} {len}"));
        visitor.visit_seq(Elements {
            parent: self.named(name),
            names: None,
            len,
            next: 0,
        })
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, SynthError> {
        let entries = if self.deep() {
            0
        } else if self.mode() == Mode::Minimal {
            self.length(MIN_MAP_ENTRIES)
        } else {
            1
        };
        self.trace(format_args!("map {entries}"));
        visitor.visit_map(OneEntry {
            parent: self,
            done: entries == 0,
        })
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, SynthError> {
        self.trace(format_args!("struct {name}"));
        visitor.visit_seq(Elements {
            parent: self.named(name),
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
        self.trace(format_args!("enum {name} {index}"));
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
        self.trace("ignored");
        visitor.visit_unit()
    }
}

/// Builds one value of `T` with the given enum choices, retrying byte fields and sequences that
/// reject a length.
fn synthesize<T: DeserializeOwned>(
    run: &RefCell<Run>,
    root: &str,
    overrides: &HashMap<String, usize>,
    mode: Mode,
) -> T {
    {
        let mut state = run.borrow_mut();
        state.overrides = overrides.clone();
        state.mode = mode;
    }
    loop {
        {
            let mut state = run.borrow_mut();
            state.last_length = None;
            state.stack.clear();
            state.trace.clear();
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

/// A digest of several parts, each prefixed with its length so that parts cannot run together.
fn digest(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

fn row<T: Serialize + DeserializeOwned>(
    run: &RefCell<Run>,
    root: &str,
    target: &str,
    overrides: &HashMap<String, usize>,
    extra: &impl Fn(&T) -> String,
) -> String {
    let named: T = synthesize(run, root, overrides, Mode::Named);
    let trace = run.borrow().trace.join("\n");
    let named_bytes = encode(&named, root, target);
    let positional: T = synthesize(run, root, overrides, Mode::Positional);
    let positional_bytes = encode(&positional, root, target);
    let minimal: T = synthesize(run, root, overrides, Mode::Minimal);
    let minimal_bytes = encode(&minimal, root, target);
    format!(
        "{root}\t{target}\t{}\t{}\t{}{}",
        named_bytes.len(),
        digest(&[&named_bytes, trace.as_bytes()]),
        digest(&[&positional_bytes, &minimal_bytes]),
        extra(&named)
    )
}

/// Returns one fixture row per enum variant that `T` can reach, or a single row when `T` has no
/// enum.
///
/// A row is `root`, the forced `Enum::Variant` (`-` when there is none), the encoded length, the
/// named digest, the positional digest, and `extra` of the named sample. `extra` must return an
/// empty string or text that starts with a tab.
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

// ── Fixture comparison ──────────────────────────────────────────────────────────────────────

const HEADER: &str = "# root\tforced variant\tbytes\tsha256 (named sample and layout trace)\t\
                      sha256 (positional and minimal samples)\textra\n";

const GUIDE: &str = "\
Each difference names its kind:
- names or order only: a field, type, or variant was renamed, a value was wrapped in a newtype, or \
two fields with the same encoding were swapped. A rename or a newtype still decodes: re-record the \
fixture. A swap changes what stored data and messages mean: treat it as an encoding change.
- encoding changed: a node on the previous release cannot read the new encoding. For a persisted \
type, increase SCHEMA_VERSION (crates/sync/src/sync/schema_version.rs). For an event or a wire \
message, also change the wire major (crates/net/src/network.rs) or protocol_version \
(crates/config/protocol-release.toml), and name the upgrade class in the PR.
- event ID changed: event identity changed, through a derived Hash or the toolchain's \
DefaultHasher. Treat it as a protocol change.
- renamed or replaced, same encoding: a variant of one enum has a new name, or another variant took \
its index, and the encoding is the same. A rename still decodes: re-record the fixture. A \
replacement changes what stored data and messages mean: treat it as an encoding change.
- new: a variant, enum, or root was added. The previous release cannot decode a value that uses a \
new variant. A stored value then blocks a rollback, and an event or wire message breaks peers on \
the previous release, so name the upgrade class in the PR. A variant inserted before others also \
moves the later ones, which shows as changed rows.
- missing: a variant, enum, or root was removed. Stored data and messages that use it no longer \
decode. Treat it like an encoding change.
Then rewrite the fixture locally with LAYOUT_LOCK_UPDATE=1. The rewrite raises no version: the \
review of the fixture diff checks that each change comes with the version change that it needs.";

/// The columns of a row: root, forced variant, bytes, named digest, positional digest, extra.
fn columns(line: &str) -> Vec<&str> {
    line.split('\t').collect()
}

/// Rows are matched by root and forced variant.
fn key(line: &str) -> String {
    columns(line)[..2].join("\t")
}

/// The rows by key. Two rows with one key would hide each other, so they fail the test.
fn keyed<'a>(lines: impl Iterator<Item = &'a str>, source: &str) -> BTreeMap<String, &'a str> {
    let mut rows = BTreeMap::new();
    for line in lines {
        if let Some(earlier) = rows.insert(key(line), line) {
            panic!(
                "{source} has two rows for {:?}:\n  {earlier}\n  {line}\nGive each root a \
                 distinct name.",
                key(line)
            );
        }
    }
    rows
}

/// Two rows encode the same way when their byte counts and positional digests match.
fn same_encoding(was: &str, now: &str) -> bool {
    let (was, now) = (columns(was), columns(now));
    was.get(2) == now.get(2) && was.get(4) == now.get(4)
}

/// Two rows of one root and one enum that encode the same way and have the same extra columns,
/// for example the event ID.
fn same_variant_slot(was: &str, now: &str) -> bool {
    let (old, new) = (columns(was), columns(now));
    let enum_name = |target: &str| target.split("::").next().unwrap_or(target).to_string();
    old[0] == new[0]
        && enum_name(old[1]) == enum_name(new[1])
        && same_encoding(was, now)
        && old.get(5..) == new.get(5..)
}

/// The differences between the fixture rows and the current rows, each with its kind.
fn compare(expected: &BTreeMap<String, &str>, found: &BTreeMap<String, &str>) -> Vec<String> {
    let mut changes = Vec::new();
    let mut renamed = HashSet::new();
    for (key, was) in expected {
        match found.get(key) {
            Some(now) if now == was => {}
            Some(now) => {
                let (old, new) = (columns(was), columns(now));
                let kind = if old[..5] == new[..5] {
                    "event ID changed"
                } else if same_encoding(was, now) {
                    "names or order only"
                } else {
                    "encoding changed"
                };
                changes.push(format!("{kind}:\n  was {was}\n  now {now}"));
            }
            None => {
                // A renamed variant keeps its encoding, and so does another variant that takes the
                // index of a removed one. Pair the row with a new row of the same root and enum
                // that encodes the same way and has the same extra columns.
                let pair = found.iter().find(|(new_key, now)| {
                    !expected.contains_key(*new_key)
                        && !renamed.contains(*new_key)
                        && same_variant_slot(was, now)
                });
                match pair {
                    Some((new_key, now)) => {
                        renamed.insert(new_key.clone());
                        changes.push(format!(
                            "renamed or replaced, same encoding:\n  was {was}\n  now {now}"
                        ));
                    }
                    None => changes.push(format!("missing: {was}")),
                }
            }
        }
    }
    for (key, now) in found {
        if !expected.contains_key(key) && !renamed.contains(key) {
            changes.push(format!("new: {now}"));
        }
    }
    changes
}

/// Compares `rows` with the fixture at `path`. With `LAYOUT_LOCK_UPDATE` set, rewrites the fixture
/// instead. The rewrite is refused in CI.
pub fn assert_fixture(path: &Path, rows: &[String]) {
    let found = keyed(rows.iter().map(String::as_str), "the current rows");
    if std::env::var_os(UPDATE_ENV).is_some() {
        assert!(
            std::env::var_os("CI").is_none(),
            "{UPDATE_ENV} is refused in CI. Rewrite the fixture locally and review the diff."
        );
        let mut text = String::from(HEADER);
        for row in rows {
            text.push_str(row);
            text.push('\n');
        }
        std::fs::write(path, text).expect("write the layout fixture");
        return;
    }

    let fixture = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let expected = keyed(
        fixture
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty()),
        &path.display().to_string(),
    );
    let changes = compare(&expected, &found);
    assert!(
        changes.is_empty(),
        "{} layout rows differ from {}.\n{}\n\nColumns: root, forced variant, bytes, named digest, \
         positional digest, extra.\n{GUIDE}",
        changes.len(),
        path.display(),
        changes.join("\n")
    );
}

#[cfg(test)]
mod tests {
    //! Each pair of types below has one serde name and differs in one layout detail. The digests of
    //! the two types must differ in the column that the detail belongs to.

    use super::*;
    use serde::Deserialize;

    fn rows<T: Serialize + DeserializeOwned>() -> Vec<String> {
        sample_rows::<T, _>("root", |_| String::new())
    }

    fn named(row: &str) -> &str {
        columns(row)[3]
    }

    fn positional(row: &str) -> &str {
        columns(row)[4]
    }

    /// The only row of a type without enums.
    fn only<T: Serialize + DeserializeOwned>() -> String {
        let mut rows = rows::<T>();
        assert_eq!(rows.len(), 1);
        rows.remove(0)
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Numbers")]
    struct Numbers {
        first: u64,
        second: u64,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Numbers")]
    struct NumbersSwapped {
        second: u64,
        first: u64,
    }

    /// The control: sample values of two `u64` fields differ, so a swap shows in the sample alone.
    #[test]
    fn swapped_integer_fields_change_the_named_digest() {
        let (plain, swapped) = (only::<Numbers>(), only::<NumbersSwapped>());
        assert_ne!(named(&plain), named(&swapped));
        assert_eq!(positional(&plain), positional(&swapped));
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Flags")]
    struct Flags {
        enabled: bool,
        paused: bool,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Flags")]
    struct FlagsSwapped {
        paused: bool,
        enabled: bool,
    }

    #[test]
    fn swapped_bool_fields_change_the_named_digest() {
        assert_ne!(named(&only::<Flags>()), named(&only::<FlagsSwapped>()));
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Stage")]
    enum Stage {
        Requested,
        Complete,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "StageChanged")]
    struct StageChanged {
        previous: Stage,
        new: Stage,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "StageChanged")]
    struct StageChangedSwapped {
        new: Stage,
        previous: Stage,
    }

    #[test]
    fn swapped_unit_enum_fields_change_the_named_digest() {
        let (plain, swapped) = (rows::<StageChanged>(), rows::<StageChangedSwapped>());
        assert_eq!(plain.len(), swapped.len());
        for (plain, swapped) in plain.iter().zip(&swapped) {
            assert_ne!(named(plain), named(swapped), "{plain}");
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Preset")]
    enum Preset {
        Small,
        Large,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Size")]
    enum Size {
        Micro,
        Full,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Params")]
    struct Params {
        preset: Preset,
        size: Size,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Params")]
    struct ParamsSwapped {
        size: Size,
        preset: Preset,
    }

    /// Two unit enums of different types encode the same variant index, so neither sample shows
    /// the swap. The layout trace does.
    #[test]
    fn swapped_fields_of_two_enum_types_change_the_named_digest() {
        let plain = rows::<Params>();
        let swapped = rows::<ParamsSwapped>();
        let plain_base = plain
            .iter()
            .find(|row| row.contains("\tPreset::Small\t"))
            .unwrap();
        let swapped_base = swapped
            .iter()
            .find(|row| row.contains("\tPreset::Small\t"))
            .unwrap();
        assert_ne!(named(plain_base), named(swapped_base));
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Changed")]
    struct Changed {
        id: u64,
        party: Option<u64>,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Changed")]
    struct ChangedSkipping {
        id: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        party: Option<u64>,
    }

    /// bincode cannot decode a value whose `None` was skipped. The minimal sample shows it: its
    /// build fails, or its encoding differs.
    #[test]
    fn skipping_none_is_not_the_same_layout() {
        let plain = only::<Changed>();
        match std::panic::catch_unwind(only::<ChangedSkipping>) {
            Err(_) => {}
            Ok(skipping) => assert_ne!(positional(&plain), positional(&skipping)),
        }
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Version")]
    struct Version(u32);

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "State")]
    struct State {
        version: u32,
        count: u64,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "State")]
    struct StateWrapped {
        version: Version,
        count: u64,
    }

    /// bincode writes nothing for a newtype wrapper, so the encoding stays the same.
    #[test]
    fn a_newtype_wrapper_keeps_the_positional_digest() {
        let (plain, wrapped) = (only::<State>(), only::<StateWrapped>());
        assert_eq!(positional(&plain), positional(&wrapped));
        assert_ne!(named(&plain), named(&wrapped));
        assert_eq!(
            compare(
                &keyed([plain.as_str()].into_iter(), "fixture"),
                &keyed([wrapped.as_str()].into_iter(), "rows"),
            )[0]
            .lines()
            .next(),
            Some("names or order only:")
        );
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Event")]
    enum Event {
        Started(u64),
        Stopped,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Event")]
    enum EventRenamed {
        Started(u64),
        Halted,
    }

    /// bincode writes the variant index, so a renamed variant still decodes.
    #[test]
    fn a_renamed_variant_is_reported_as_a_rename() {
        let plain = rows::<Event>();
        let renamed = rows::<EventRenamed>();
        let changes = compare(
            &keyed(plain.iter().map(String::as_str), "fixture"),
            &keyed(renamed.iter().map(String::as_str), "rows"),
        );
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(
            changes[0].starts_with("renamed or replaced, same encoding:"),
            "{changes:?}"
        );
    }

    /// Rows of two different enums are never paired, even when they encode the same way.
    #[test]
    fn rows_of_two_enums_are_not_paired() {
        let fixture = "root\tFirst::A\t4\tn1\tp\nroot\tFirst::B\t4\tn2\tq";
        let rows = "root\tFirst::B\t4\tn2\tq\nroot\tSecond::A\t4\tn3\tp";
        let changes = compare(
            &keyed(fixture.lines(), "fixture"),
            &keyed(rows.lines(), "rows"),
        );
        assert_eq!(changes.len(), 2, "{changes:?}");
        assert!(changes[0].starts_with("missing:"), "{changes:?}");
        assert!(changes[1].starts_with("new:"), "{changes:?}");
    }

    fn is_true(value: &bool) -> bool {
        *value
    }

    fn is_false(value: &bool) -> bool {
        !*value
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Flags")]
    struct FlagsSkippingTrue {
        enabled: bool,
        #[serde(skip_serializing_if = "is_true")]
        paused: bool,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(rename = "Flags")]
    struct FlagsSkippingFalse {
        enabled: bool,
        #[serde(skip_serializing_if = "is_false")]
        paused: bool,
    }

    /// The full and the minimal sample give each `bool` both values, so a skip on either value
    /// shows, whatever value the path gives: the build fails, or the encoding differs.
    #[test]
    fn skipping_either_bool_value_is_not_the_same_layout() {
        let plain = only::<Flags>();
        for skipping in [
            std::panic::catch_unwind(only::<FlagsSkippingTrue>),
            std::panic::catch_unwind(only::<FlagsSkippingFalse>),
        ] {
            match skipping {
                Err(_) => {}
                Ok(skipping) => assert_ne!(positional(&plain), positional(&skipping)),
            }
        }
    }

    /// A map that must not be empty.
    #[derive(Serialize)]
    struct NonEmpty(BTreeMap<u64, u64>);

    impl<'de> Deserialize<'de> for NonEmpty {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let map = BTreeMap::<u64, u64>::deserialize(deserializer)?;
            if map.is_empty() {
                return Err(serde::de::Error::custom("the map is empty"));
            }
            Ok(Self(map))
        }
    }

    #[derive(Serialize, Deserialize)]
    struct Holder {
        entries: NonEmpty,
    }

    /// The minimal sample falls back to one entry for a map that rejects an empty one.
    #[test]
    fn a_map_that_rejects_empty_still_builds() {
        only::<Holder>();
    }

    #[test]
    #[should_panic(expected = "two rows for")]
    fn two_rows_with_one_key_fail() {
        keyed(["root\t-\t1\ta\tb", "root\t-\t1\tc\td"].into_iter(), "rows");
    }
}
