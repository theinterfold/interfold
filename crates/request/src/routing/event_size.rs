// SPDX-License-Identifier: LGPL-3.0-only

use e3_events::InterfoldEvent;
use serde::{ser, Serialize};
use std::mem::{size_of, size_of_val};

// Covers Arc counters, Vec/String headers, alignment, and allocator metadata on 64-bit nodes.
const ALLOCATION_OVERHEAD: usize = 64;

pub(crate) fn event_bytes(event: &InterfoldEvent) -> Option<usize> {
    // A growing queue can reserve nearly twice its occupied inline storage.
    let mut size = EventSize(2 * size_of::<InterfoldEvent>());
    event.serialize(&mut size).ok()?;
    Some(size.0)
}

// Counts fixed-integer bincode bytes and allocation candidates in one traversal.
// Collection elements and fields also reserve their inline storage. Shared payloads
// count in full, and compact deferred copies retain no spare nested Vec capacity.
struct EventSize(usize);

impl EventSize {
    fn add(&mut self, bytes: usize) -> bincode::Result<()> {
        self.0 = self
            .0
            .checked_add(bytes)
            .ok_or(bincode::ErrorKind::SizeLimit)?;
        Ok(())
    }

    fn allocation(&mut self) -> bincode::Result<()> {
        self.add(ALLOCATION_OVERHEAD)
    }

    fn value<T: Serialize + ?Sized>(&mut self, value: &T) -> bincode::Result<()> {
        self.allocation()?;
        self.add(size_of_val(value))?;
        value.serialize(self)
    }
}

struct Compound<'a> {
    size: &'a mut EventSize,
    allocated: bool,
}

impl Compound<'_> {
    fn value<T: Serialize + ?Sized>(&mut self, value: &T) -> bincode::Result<()> {
        if self.allocated {
            self.size.value(value)
        } else {
            value.serialize(&mut *self.size)
        }
    }
}

macro_rules! scalar {
    ($($method:ident($ty:ty)),* $(,)?) => {
        $(fn $method(self, _: $ty) -> bincode::Result<()> {
            self.add(size_of::<$ty>())
        })*
    };
}

impl<'a> ser::Serializer for &'a mut EventSize {
    type Ok = ();
    type Error = bincode::Error;
    type SerializeSeq = Compound<'a>;
    type SerializeTuple = Compound<'a>;
    type SerializeTupleStruct = Compound<'a>;
    type SerializeTupleVariant = Compound<'a>;
    type SerializeMap = Compound<'a>;
    type SerializeStruct = Compound<'a>;
    type SerializeStructVariant = Compound<'a>;

    scalar! {
        serialize_bool(bool), serialize_i8(i8), serialize_i16(i16), serialize_i32(i32),
        serialize_i64(i64), serialize_i128(i128), serialize_u8(u8), serialize_u16(u16),
        serialize_u32(u32), serialize_u64(u64), serialize_u128(u128),
        serialize_f32(f32), serialize_f64(f64),
    }

    fn serialize_char(self, value: char) -> bincode::Result<()> {
        self.add(value.len_utf8())
    }

    fn serialize_str(self, value: &str) -> bincode::Result<()> {
        self.serialize_bytes(value.as_bytes())
    }

    fn serialize_bytes(self, value: &[u8]) -> bincode::Result<()> {
        self.allocation()?;
        self.add(8)?;
        self.add(value.len())
    }

    fn serialize_none(self) -> bincode::Result<()> {
        self.add(1)
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> bincode::Result<()> {
        self.add(1)?;
        self.value(value)
    }

    fn serialize_unit(self) -> bincode::Result<()> {
        Ok(())
    }

    fn serialize_unit_struct(self, _: &'static str) -> bincode::Result<()> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
    ) -> bincode::Result<()> {
        self.add(4)
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> bincode::Result<()> {
        self.value(value)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        value: &T,
    ) -> bincode::Result<()> {
        self.add(4)?;
        self.value(value)
    }

    fn serialize_seq(self, len: Option<usize>) -> bincode::Result<Self::SerializeSeq> {
        len.ok_or(bincode::ErrorKind::SequenceMustHaveLength)?;
        self.add(8)?;
        self.allocation()?;
        Ok(Compound {
            size: self,
            allocated: true,
        })
    }

    fn serialize_tuple(self, _: usize) -> bincode::Result<Self::SerializeTuple> {
        Ok(Compound {
            size: self,
            allocated: false,
        })
    }

    fn serialize_tuple_struct(
        self,
        _: &'static str,
        len: usize,
    ) -> bincode::Result<Self::SerializeTupleStruct> {
        self.serialize_tuple(len)
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        _: &'static str,
        len: usize,
    ) -> bincode::Result<Self::SerializeTupleVariant> {
        self.add(4)?;
        self.serialize_tuple(len)
    }

    fn serialize_map(self, len: Option<usize>) -> bincode::Result<Self::SerializeMap> {
        self.serialize_seq(len)
    }

    fn serialize_struct(self, _: &'static str, _: usize) -> bincode::Result<Self::SerializeStruct> {
        self.allocation()?;
        Ok(Compound {
            size: self,
            allocated: true,
        })
    }

    fn serialize_struct_variant(
        self,
        name: &'static str,
        _: u32,
        _: &'static str,
        len: usize,
    ) -> bincode::Result<Self::SerializeStructVariant> {
        self.add(4)?;
        self.serialize_struct(name, len)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

macro_rules! compound {
    ($($trait:ident::$method:ident),* $(,)?) => {
        $(impl ser::$trait for Compound<'_> {
            type Ok = ();
            type Error = bincode::Error;

            fn $method<T: Serialize + ?Sized>(&mut self, value: &T) -> bincode::Result<()> {
                self.value(value)
            }

            fn end(self) -> bincode::Result<()> {
                Ok(())
            }
        })*
    };
}

compound! {
    SerializeSeq::serialize_element, SerializeTuple::serialize_element,
    SerializeTupleStruct::serialize_field, SerializeTupleVariant::serialize_field,
}

impl ser::SerializeMap for Compound<'_> {
    type Ok = ();
    type Error = bincode::Error;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> bincode::Result<()> {
        self.value(key)
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> bincode::Result<()> {
        self.value(value)
    }

    fn end(self) -> bincode::Result<()> {
        Ok(())
    }
}

macro_rules! fields {
    ($($trait:ident),* $(,)?) => {
        $(impl ser::$trait for Compound<'_> {
            type Ok = ();
            type Error = bincode::Error;

            fn serialize_field<T: Serialize + ?Sized>(
                &mut self, _: &'static str, value: &T,
            ) -> bincode::Result<()> {
                self.value(value)
            }

            fn end(self) -> bincode::Result<()> {
                Ok(())
            }
        })*
    };
}

fields! { SerializeStruct, SerializeStructVariant }
