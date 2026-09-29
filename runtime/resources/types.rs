//! `Res_value` and the typed values it encodes.
//!
//! A `Res_value` is eight bytes on disk — a `u16` size, a `u8` that is always
//! zero, a `u8` type tag, and a `u32` of data whose meaning the tag selects.
//! This module turns that tag-plus-data pair into something a caller can use
//! without knowing the encoding.
//!
//! Reference: `ResourceTypes.h` (`struct Res_value`) in AOSP.

use crate::resources::error::{ResourceError, Result};

/// `Res_value.dataType` — the value is explicitly `null` or empty.
pub const TYPE_NULL: u8 = 0x00;
/// `Res_value.dataType` — `data` is a `ResTable_ref`, i.e. `0xPPTTEEEE`.
pub const TYPE_REFERENCE: u8 = 0x01;
/// `Res_value.dataType` — `data` is an attribute resource id.
pub const TYPE_ATTRIBUTE: u8 = 0x02;
/// `Res_value.dataType` — `data` is an index into the table's global string pool.
pub const TYPE_STRING: u8 = 0x03;
/// `Res_value.dataType` — `data` is `f32::to_bits`.
pub const TYPE_FLOAT: u8 = 0x04;
/// `Res_value.dataType` — `data` is a complex dimension, see [`Dimension`].
pub const TYPE_DIMENSION: u8 = 0x05;
/// `Res_value.dataType` — `data` is a complex fraction, see [`Fraction`].
pub const TYPE_FRACTION: u8 = 0x06;
/// `Res_value.dataType` — `data` is a `DynamicRefTable`-relative reference.
pub const TYPE_DYNAMIC_REFERENCE: u8 = 0x07;
/// `Res_value.dataType` — `data` is a `DynamicRefTable`-relative attribute.
pub const TYPE_DYNAMIC_ATTRIBUTE: u8 = 0x08;

/// First integer flavour.
pub const TYPE_FIRST_INT: u8 = 0x10;
/// `Res_value.dataType` — a signed decimal integer.
pub const TYPE_INT_DEC: u8 = 0x10;
/// `Res_value.dataType` — a hexadecimal integer.
pub const TYPE_INT_HEX: u8 = 0x11;
/// `Res_value.dataType` — `false` or `true`.
pub const TYPE_INT_BOOLEAN: u8 = 0x12;
/// First colour flavour.
pub const TYPE_FIRST_COLOR_INT: u8 = 0x1c;
/// `Res_value.dataType` — `0xAARRGGBB` from `#aarrggbb`.
pub const TYPE_INT_COLOR_ARGB8: u8 = 0x1c;
/// `Res_value.dataType` — `0xFFRRGGBB` from `#rrggbb`.
pub const TYPE_INT_COLOR_RGB8: u8 = 0x1d;
/// `Res_value.dataType` — `0xAARRGGBB` from `#argb`, nibbles already expanded.
pub const TYPE_INT_COLOR_ARGB4: u8 = 0x1e;
/// `Res_value.dataType` — `0xFFRRGGBB` from `#rgb`, nibbles already expanded.
pub const TYPE_INT_COLOR_RGB4: u8 = 0x1f;
/// Last colour flavour.
pub const TYPE_LAST_COLOR_INT: u8 = 0x1f;
/// Last integer flavour.
pub const TYPE_LAST_INT: u8 = 0x1f;

/// `data` for a `TYPE_NULL` that is merely undefined.
pub const DATA_NULL_UNDEFINED: u32 = 0;
/// `data` for a `TYPE_NULL` that is explicitly empty.
pub const DATA_NULL_EMPTY: u32 = 1;

// --- complex encoding ------------------------------------------------------
//
// A dimension or fraction packs a signed fixed-point mantissa and a radix into
// one `u32`. The mantissa occupies bits 8..=31 (23 bits of magnitude plus a
// sign bit), the radix occupies bits 4..=5, and the unit occupies bits 0..=3.

/// Where the unit field starts.
pub const COMPLEX_UNIT_SHIFT: u32 = 0;
/// Mask selecting the unit field.
pub const COMPLEX_UNIT_MASK: u32 = 0xf;
/// Raw device pixels.
pub const COMPLEX_UNIT_PX: u32 = 0;
/// Density-independent pixels.
pub const COMPLEX_UNIT_DIP: u32 = 1;
/// Scale-independent pixels.
pub const COMPLEX_UNIT_SP: u32 = 2;
/// Points (1/72 inch).
pub const COMPLEX_UNIT_PT: u32 = 3;
/// Inches.
pub const COMPLEX_UNIT_IN: u32 = 4;
/// Millimetres.
pub const COMPLEX_UNIT_MM: u32 = 5;

/// Where the radix field starts.
pub const COMPLEX_RADIX_SHIFT: u32 = 4;
/// Mask selecting the radix field.
pub const COMPLEX_RADIX_MASK: u32 = 0x3;
/// `0xnnnnnn.0` — the mantissa magnitude is 16 bits.
pub const COMPLEX_RADIX_23P0: u32 = 0;
/// `0xnnnn.nn` — the mantissa magnitude is 8 bits.
pub const COMPLEX_RADIX_16P7: u32 = 1;
/// `0xnn.nnnn` — the mantissa magnitude is 4 bits.
pub const COMPLEX_RADIX_8P15: u32 = 2;
/// `0x0.nnnnnn` — the mantissa magnitude is 0 bits.
pub const COMPLEX_RADIX_0P23: u32 = 3;

/// Where the mantissa field starts.
pub const COMPLEX_MANTISSA_SHIFT: u32 = 8;
/// Mask selecting the mantissa's 23 bits of magnitude.
pub const COMPLEX_MANTISSA_MASK: u32 = 0x00ff_ffff;
/// The full mantissa field, sign bit included, in place.
pub const COMPLEX_MANTISSA_FIELD: u32 = COMPLEX_MANTISSA_MASK << COMPLEX_MANTISSA_SHIFT;

/// Decode the mantissa/radix pair of a complex value to a float.
///
/// This is a direct port of `TypedValue::complexToFloat`. The multiplier table
/// is *not* a guess: it is `1/2^8` divided by a further `2^0`, `2^7`, `2^15` or
/// `2^23` depending on the radix, which is what makes `COMPLEX_RADIX_16P7`
/// mean "eight integer bits, seven fractional bits". Getting this wrong is
/// silent — the number is merely off by a power of 256 — so the unit tests
/// check it against values printed by `aapt2`, not against this function.
///
/// The sign is taken from bit 31: the masked field is reinterpreted as a
/// [`i32`], matching AOSP's `(float)(int32_t)(complex & 0xffffff00)`.
pub fn complex_to_float(complex: u32) -> f32 {
    const MANTISSA_MULT: f32 = 1.0 / (1u32 << COMPLEX_MANTISSA_SHIFT) as f32;
    const RADIX_MULTS: [f32; 4] = [
        1.0 * MANTISSA_MULT,
        1.0 / (1u32 << 7) as f32 * MANTISSA_MULT,
        1.0 / (1u32 << 15) as f32 * MANTISSA_MULT,
        1.0 / (1u32 << 23) as f32 * MANTISSA_MULT,
    ];
    let radix = (complex >> COMPLEX_RADIX_SHIFT) & COMPLEX_RADIX_MASK;
    let mantissa = (complex & COMPLEX_MANTISSA_FIELD) as i32;
    mantissa as f32 * RADIX_MULTS[radix as usize]
}

/// Encode a float into the mantissa/radix pair, the inverse of
/// [`complex_to_float`].
///
/// The decode is `value = mantissa * 2^(-8 * radix)`, so an encoding has to
/// pick a `radix` and then a `mantissa` that is an integer small enough to
/// live in 23 bits plus a sign. AAPT2 picks the *narrowest* radix that
/// represents the value, which is why `16dp` is stored with radix 0 and `0.5`
/// with radix 1: a wider radix would be more precise, and aapt2 only spends
/// that precision when the value needs it.
///
/// This is only used to build test tables; the read path never calls it.
pub fn float_to_complex(value: f32) -> u32 {
    if value == 0.0 {
        return 0;
    }
    for radix in 0u32..4 {
        let fractional = COMPLEX_RADIX_FRACTIONAL_BITS[radix as usize];
        let scaled = value * 2f32.powi(fractional as i32);
        // 23 bits of magnitude, so anything at or above 2^23 would not fit.
        if scaled.abs() >= 2f32.powi(23) {
            continue;
        }
        let mantissa = scaled.round();
        // Accept only a last-bit rounding error, so the radix chosen is the
        // narrowest one that is still lossless.
        if (scaled - mantissa).abs() > scaled.abs() * 1e-6 {
            continue;
        }
        let field = ((mantissa as i64) << COMPLEX_MANTISSA_SHIFT) as i32;
        return (radix << COMPLEX_RADIX_SHIFT) | ((field as u32) & COMPLEX_MANTISSA_FIELD);
    }
    // Not representable at all; the widest radix with a clamped mantissa is the
    // least-wrong answer, and it shows up as a lossy round trip.
    let mantissa = (value * 2f32.powi(23)).clamp(-(2f32.powi(23)), 2f32.powi(23) - 1.0).round();
    let field = ((mantissa as i64) << COMPLEX_MANTISSA_SHIFT) as i32;
    (COMPLEX_RADIX_0P23 << COMPLEX_RADIX_SHIFT) | ((field as u32) & COMPLEX_MANTISSA_FIELD)
}

/// How many *fractional* bits each radix carries.
///
/// This is the meaning behind the `COMPLEX_RADIX_*` names: `16P7` is sixteen
/// integer bits and seven fractional bits, `8P15` is eight and fifteen,
/// `0P23` is zero and twenty-three, and `23P0` is the same twenty-three bits
/// with none of them fractional. It is also what `RADIX_MULTS` in
/// [`complex_to_float`] encodes: `2^-0`, `2^-7`, `2^-15`, `2^-23`.
///
/// The gaps (7, 15 and then 23, not 8, 16, 24) are not a typo in this module;
/// they are the gaps in AOSP, and the mantissa is 23 bits plus a sign, so
/// `0P23` is the only radix that can use all of them.
pub const COMPLEX_RADIX_FRACTIONAL_BITS: [u32; 4] = [0, 7, 15, 23];

/// The unit of a [`Dimension`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unit {
    /// Raw device pixels, `COMPLEX_UNIT_PX`.
    Px,
    /// Density-independent pixels, `COMPLEX_UNIT_DIP`.
    Dip,
    /// Scale-independent pixels, `COMPLEX_UNIT_SP`.
    Sp,
    /// Points, `COMPLEX_UNIT_PT`.
    Pt,
    /// Inches, `COMPLEX_UNIT_IN`.
    Inches,
    /// Millimetres, `COMPLEX_UNIT_MM`.
    Millimetres,
}

impl Unit {
    /// The `COMPLEX_UNIT_*` constant this unit came from.
    pub fn code(self) -> u32 {
        match self {
            Unit::Px => COMPLEX_UNIT_PX,
            Unit::Dip => COMPLEX_UNIT_DIP,
            Unit::Sp => COMPLEX_UNIT_SP,
            Unit::Pt => COMPLEX_UNIT_PT,
            Unit::Inches => COMPLEX_UNIT_IN,
            Unit::Millimetres => COMPLEX_UNIT_MM,
        }
    }

    /// The unit for a `COMPLEX_UNIT_*` constant, if it is one of the six.
    pub fn from_code(code: u32) -> Option<Unit> {
        match code & COMPLEX_UNIT_MASK {
            COMPLEX_UNIT_PX => Some(Unit::Px),
            COMPLEX_UNIT_DIP => Some(Unit::Dip),
            COMPLEX_UNIT_SP => Some(Unit::Sp),
            COMPLEX_UNIT_PT => Some(Unit::Pt),
            COMPLEX_UNIT_IN => Some(Unit::Inches),
            COMPLEX_UNIT_MM => Some(Unit::Millimetres),
            _ => None,
        }
    }

    /// The suffix `aapt2` prints for this unit, e.g. `dp`.
    pub fn suffix(self) -> &'static str {
        match self {
            Unit::Px => "px",
            Unit::Dip => "dp",
            Unit::Sp => "sp",
            Unit::Pt => "pt",
            Unit::Inches => "in",
            Unit::Millimetres => "mm",
        }
    }
}

/// A `TYPE_DIMENSION`: a float plus the unit it was written in.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Dimension {
    /// The decoded value, e.g. `16.0` for `16dp`.
    pub value: f32,
    /// The unit the value was written in.
    pub unit: Unit,
}

impl Dimension {
    /// Decode a complex-encoded dimension.
    ///
    /// A unit code outside the six `COMPLEX_UNIT_*` values is an error rather
    /// than a guess: AOSP prints `(unknown unit)` and `TypedValue` callers
    /// would see a nonsense magnitude.
    pub fn decode(complex: u32) -> Result<Dimension> {
        let unit = Unit::from_code(complex >> COMPLEX_UNIT_SHIFT).ok_or(ResourceError::UnknownValueType {
            data_type: TYPE_DIMENSION,
            at: complex,
        })?;
        Ok(Dimension { value: complex_to_float(complex), unit })
    }

    /// The value in pixels, given the device density in dpi.
    ///
    /// `dp`, `sp`, `pt` and the absolute units all scale by `dpi / 160`; `px`
    /// does not scale at all.
    pub fn to_px(self, density_dpi: u16) -> f32 {
        if self.unit == Unit::Px {
            self.value
        } else {
            self.value * (density_dpi as f32) / 160.0
        }
    }
}

/// A `TYPE_FRACTION`: a float plus whether it is of the parent or of the whole.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fraction {
    /// The decoded fraction, e.g. `0.5` for `50%`.
    pub value: f32,
    /// `true` for `50%p` (parent), `false` for `50%` (whole).
    pub parent: bool,
}

impl Fraction {
    /// Decode a complex-encoded fraction.
    pub fn decode(complex: u32) -> Result<Fraction> {
        let unit = (complex >> COMPLEX_UNIT_SHIFT) & COMPLEX_UNIT_MASK;
        let parent = match unit {
            0 => false,
            1 => true,
            // AOSP defines only COMPLEX_UNIT_FRACTION and _PARENT. Aapt2 has
            // never emitted another, but a table that does is malformed rather
            // than merely unusual, and silently treating it as "whole" would
            // produce a wrong layout.
            _ => {
                return Err(ResourceError::UnknownValueType { data_type: TYPE_FRACTION, at: complex })
            }
        };
        Ok(Fraction { value: complex_to_float(complex), parent })
    }
}

/// A `TYPE_NULL`: the distinction between "no value" and "deliberately empty".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Null {
    /// `DATA_NULL_UNDEFINED` — the resource is not defined.
    Undefined,
    /// `DATA_NULL_EMPTY` — the resource is explicitly the empty value.
    Empty,
}

impl Null {
    /// Whether this is [`Null::Empty`].
    pub fn is_empty(self) -> bool {
        matches!(self, Null::Empty)
    }
}

/// Which of the four colour encodings a colour was written in.
///
/// All four store a fully expanded `0xAARRGGBB` in `Res_value.data`; the tag
/// records which source syntax produced it, which matters only when a value has
/// to be written back out. AAPT2's encoder (`ResourceTypes.cpp`,
/// `ResTable_ref::coerce` and the `#` parser above it) expands the nibbles and
/// forces alpha to `0xFF` for the RGB forms *at encode time*, so no expansion
/// is needed or correct at decode time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ColorFormat {
    /// `#aarrggbb` — `TYPE_INT_COLOR_ARGB8`.
    Argb8,
    /// `#rrggbb` — `TYPE_INT_COLOR_RGB8`, alpha forced opaque.
    Rgb8,
    /// `#argb` — `TYPE_INT_COLOR_ARGB4`, nibbles expanded.
    Argb4,
    /// `#rgb` — `TYPE_INT_COLOR_RGB4`, nibbles expanded, alpha forced opaque.
    Rgb4,
}

impl ColorFormat {
    /// The `TYPE_INT_COLOR_*` constant for this format.
    pub fn data_type(self) -> u8 {
        match self {
            ColorFormat::Argb8 => TYPE_INT_COLOR_ARGB8,
            ColorFormat::Rgb8 => TYPE_INT_COLOR_RGB8,
            ColorFormat::Argb4 => TYPE_INT_COLOR_ARGB4,
            ColorFormat::Rgb4 => TYPE_INT_COLOR_RGB4,
        }
    }

    /// The format for a `TYPE_INT_COLOR_*` constant, if it is one of the four.
    pub fn from_data_type(data_type: u8) -> Option<ColorFormat> {
        match data_type {
            TYPE_INT_COLOR_ARGB8 => Some(ColorFormat::Argb8),
            TYPE_INT_COLOR_RGB8 => Some(ColorFormat::Rgb8),
            TYPE_INT_COLOR_ARGB4 => Some(ColorFormat::Argb4),
            TYPE_INT_COLOR_RGB4 => Some(ColorFormat::Rgb4),
            _ => None,
        }
    }

    /// The number of hex digits `#aarrggbb`-style source text has.
    pub fn hex_digits(self) -> usize {
        match self {
            ColorFormat::Argb8 => 8,
            ColorFormat::Rgb8 => 6,
            ColorFormat::Argb4 => 4,
            ColorFormat::Rgb4 => 3,
        }
    }
}

/// A decoded `Res_value`.
///
/// The variants are the `Res_value` type tags this reader models. Anything else
/// becomes [`Value::Raw`] rather than a guess, so an unmodelled tag is
/// observable at the call site instead of silently becoming a zero.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `TYPE_NULL`.
    Null(Null),
    /// `TYPE_REFERENCE`: a `0xPPTTEEEE` resource id.
    Reference(u32),
    /// `TYPE_ATTRIBUTE`: an attribute resource id.
    Attribute(u32),
    /// `TYPE_STRING`: an index into the table's *global* string pool.
    String(u32),
    /// `TYPE_FLOAT`.
    Float(f32),
    /// `TYPE_DIMENSION`.
    Dimension(Dimension),
    /// `TYPE_FRACTION`.
    Fraction(Fraction),
    /// `TYPE_DYNAMIC_REFERENCE`, unresolved against a `DynamicRefTable`.
    DynamicReference(u32),
    /// `TYPE_DYNAMIC_ATTRIBUTE`, unresolved against a `DynamicRefTable`.
    DynamicAttribute(u32),
    /// `TYPE_INT_DEC`.
    Int(i32),
    /// `TYPE_INT_HEX`.
    Hex(u32),
    /// `TYPE_INT_BOOLEAN`. AAPT2 stores `0xFFFFFFFF` for `true`.
    Boolean(bool),
    /// One of the four `TYPE_INT_COLOR_*` encodings.
    Color {
        /// Which encoding the value was written in.
        format: ColorFormat,
        /// The `0xAARRGGBB` value.
        argb: u32,
    },
    /// A type tag this reader does not model.
    Raw {
        /// The `Res_value.dataType` tag.
        data_type: u8,
        /// The raw `Res_value.data`.
        data: u32,
    },
}

impl Value {
    /// The `TYPE_INT_BOOLEAN` payload AAPT2 writes for `true`.
    ///
    /// Both `0xFFFFFFFF` and `1` occur in the wild; [`Value::Boolean`] is built
    /// with `data != 0`, matching AOSP's `Res_value` handling, so this
    /// constant is documentation rather than a decoding rule.
    pub const TRUE_BITS: u32 = 0xffff_ffff;

    /// A short, stable name for the value's type, for diagnostics and for the
    /// [`ResourceError::ValueTypeMismatch`] payload.
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null(_) => "null",
            Value::Reference(_) => "reference",
            Value::Attribute(_) => "attribute",
            Value::String(_) => "string",
            Value::Float(_) => "float",
            Value::Dimension(_) => "dimension",
            Value::Fraction(_) => "fraction",
            Value::DynamicReference(_) => "dynamic-reference",
            Value::DynamicAttribute(_) => "dynamic-attribute",
            Value::Int(_) => "int",
            Value::Hex(_) => "hex",
            Value::Boolean(_) => "boolean",
            Value::Color { .. } => "color",
            Value::Raw { .. } => "raw",
        }
    }

    /// The colour as `0xAARRGGBB`, if this is a colour.
    pub fn as_argb(&self) -> Option<u32> {
        match self {
            Value::Color { argb, .. } => Some(*argb),
            _ => None,
        }
    }

    /// The boolean payload, if this is a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// The integer payload, if this is any of the integer flavours.
    ///
    /// Colours are integers too and are included here; ask for [`Value::as_argb`]
    /// when the colour-ness matters.
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Hex(v) => Some(*v as i32),
            Value::Boolean(b) => Some(i32::from(*b)),
            Value::Color { argb, .. } => Some(*argb as i32),
            _ => None,
        }
    }

    /// The reference target, for [`Value::Reference`] and
    /// [`Value::DynamicReference`].
    pub fn as_reference(&self) -> Option<u32> {
        match self {
            Value::Reference(r) | Value::DynamicReference(r) => Some(*r),
            _ => None,
        }
    }

    /// The dimension, if this is one.
    pub fn as_dimension(&self) -> Option<Dimension> {
        match self {
            Value::Dimension(d) => Some(*d),
            _ => None,
        }
    }

    /// A textual rendering, matching what `aapt2 dump resources` prints for the
    /// common cases. Used by tests and diagnostics, not on any hot path.
    pub fn to_display(&self) -> String {
        match self {
            Value::Null(Null::Empty) => "@empty".to_string(),
            Value::Null(Null::Undefined) => "@null".to_string(),
            Value::Reference(r) => format!("@0x{r:08x}"),
            Value::Attribute(r) => format!("?0x{r:08x}"),
            Value::String(i) => format!("@string/{i}"),
            Value::Float(f) => format!("{f}"),
            Value::Dimension(d) => format!("{:.6}{}", d.value, d.unit.suffix()),
            Value::Fraction(fr) => {
                if fr.parent {
                    format!("{:.6}%p", fr.value * 100.0)
                } else {
                    format!("{:.6}%", fr.value * 100.0)
                }
            }
            Value::DynamicReference(r) => format!("@dynamic/0x{r:08x}"),
            Value::DynamicAttribute(r) => format!("?dynamic/0x{r:08x}"),
            Value::Int(i) => i.to_string(),
            Value::Hex(v) => format!("0x{v:x}"),
            Value::Boolean(b) => b.to_string(),
            Value::Color { argb, .. } => format!("#{argb:08x}"),
            Value::Raw { data_type, data } => format!("(type 0x{data_type:02x}) 0x{data:08x}"),
        }
    }
}

/// A `Res_value` exactly as stored, before decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawValue {
    /// The `Res_value.size` field. AAPT2 writes 8.
    pub size: u8,
    /// The `Res_value.res0` field. Always 0 in real tables.
    pub res0: u8,
    /// The `Res_value.dataType` tag.
    pub data_type: u8,
    /// The `Res_value.data` field.
    pub data: u32,
}

impl RawValue {
    /// Decode to a typed [`Value`].
    ///
    /// String values keep their pool index; the caller substitutes the text,
    /// because only the table knows which pool the index refers to.
    pub fn decode(&self) -> Value {
        match self.data_type {
            TYPE_NULL => match self.data {
                DATA_NULL_EMPTY => Value::Null(Null::Empty),
                _ => Value::Null(Null::Undefined),
            },
            TYPE_REFERENCE => Value::Reference(self.data),
            TYPE_ATTRIBUTE => Value::Attribute(self.data),
            TYPE_STRING => Value::String(self.data),
            TYPE_FLOAT => Value::Float(f32::from_bits(self.data)),
            TYPE_DIMENSION => match Dimension::decode(self.data) {
                Ok(d) => Value::Dimension(d),
                // A unit code AOSP does not define. Keeping the tag visible is
                // better than dropping the value.
                Err(_) => Value::Raw { data_type: self.data_type, data: self.data },
            },
            TYPE_FRACTION => match Fraction::decode(self.data) {
                Ok(f) => Value::Fraction(f),
                Err(_) => Value::Raw { data_type: self.data_type, data: self.data },
            },
            TYPE_DYNAMIC_REFERENCE => Value::DynamicReference(self.data),
            TYPE_DYNAMIC_ATTRIBUTE => Value::DynamicAttribute(self.data),
            TYPE_INT_DEC => Value::Int(self.data as i32),
            TYPE_INT_HEX => Value::Hex(self.data),
            // AAPT2 writes 0xFFFFFFFF for `true`, but 1 is also seen; treating
            // any non-zero as true matches AOSP and is the only reading that
            // cannot be wrong for one of the two encodings.
            TYPE_INT_BOOLEAN => Value::Boolean(self.data != 0),
            _ => match ColorFormat::from_data_type(self.data_type) {
                Some(format) => Value::Color { format, argb: self.data },
                None => Value::Raw { data_type: self.data_type, data: self.data },
            },
        }
    }

    /// Read a `Res_value` from `b` at `off`, or report truncation.
    pub fn read(b: &[u8], off: usize) -> Result<RawValue> {
        if off + 8 > b.len() {
            return Err(ResourceError::Truncated { what: "Res_value", need: off + 8, have: b.len() });
        }
        Ok(RawValue {
            size: b[off],
            res0: b[off + 1],
            data_type: b[off + 3],
            data: u32::from_le_bytes([b[off + 4], b[off + 5], b[off + 6], b[off + 7]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Transcribed from the real `resources.arsc` inside the F-Droid APK
    // `com.dosse.clock31_5` (see `FIXTURES.md`). These are the `Res_value.data`
    // words of three `ResTable_map_entry`s inside `style/Theme.Clock31.*`, at
    // the byte offsets the arsc actually stores them at:
    //
    //   0x7f010001 appWidgetPadding     data=0x00001001  aapt2 prints 16.000000dp
    //   0x7f010000 appWidgetInnerRadius data=0x00000801  aapt2 prints  8.000000dp
    //   0x7f010002 appWidgetRadius      data=0x00001001  aapt2 prints 16.000000dp
    //
    // These are *read* from the file, not derived from the decode below. That
    // distinction is load-bearing: deriving them as "mantissa = 16 * 2^8, then
    // OR in the unit" gives 0x00001100, which sets radix 1 (16p7) and decodes
    // to 2dp — wrong by a factor of eight, with no error anywhere. The
    // difference is that the radix field is already in the file and aapt2
    // chose radix 0, so the mantissa is 4096 and the whole low byte is the
    // unit.
    const APP_WIDGET_PADDING_16DP: u32 = 0x0000_1001;
    const APP_WIDGET_INNER_RADIUS_8DP: u32 = 0x0000_0801;

    #[test]
    fn radix_23_matches_aapt2_printout_for_real_dimensions() {
        let d = Dimension::decode(APP_WIDGET_PADDING_16DP).unwrap();
        assert_eq!(d.unit, Unit::Dip);
        assert_eq!(d.value, 16.0, "aapt2 prints 16.000000dp for this value");
        assert_eq!(Value::Dimension(d).to_display(), "16.000000dp");

        let d = Dimension::decode(APP_WIDGET_INNER_RADIUS_8DP).unwrap();
        assert_eq!(d.unit, Unit::Dip);
        assert_eq!(d.value, 8.0, "aapt2 prints 8.000000dp for this value");
    }

    #[test]
    fn the_radix_field_is_not_derivable() {
        // The guard against re-introducing the derivation above: reading the
        // mantissa without honouring the radix field that aapt2 wrote.
        assert_eq!(0x0000_1001u32 >> COMPLEX_RADIX_SHIFT & COMPLEX_RADIX_MASK, COMPLEX_RADIX_23P0);
        // Two plausible re-derivations of the real value, both silent:
        //   shifting the mantissa up by 4 bits instead of 8 gives
        //     256 * 2^-8 == 1dp, a factor of 16;
        //   not shifting it at all puts the whole mantissa in the unit
        //     nibble and the value comes out as zero;
        //   adding a radix the file does not have gives
        //     4096 * 2^-8 * 2^-7 == 32dp, a factor of two.
        let misaligned_shift = (16u32 << 4) | COMPLEX_UNIT_DIP;
        assert_eq!(Dimension::decode(misaligned_shift).unwrap().value, 1.0, "16x off, no error raised");
        let no_shift = 16u32 | COMPLEX_UNIT_DIP;
        assert_eq!(Dimension::decode(no_shift).unwrap().value, 0.0, "value vanishes, no error raised");
        let invented_a_radix = (4096u32 << COMPLEX_MANTISSA_SHIFT)
            | (COMPLEX_RADIX_16P7 << COMPLEX_RADIX_SHIFT)
            | COMPLEX_UNIT_DIP;
        assert_eq!(Dimension::decode(invented_a_radix).unwrap().value, 32.0, "2x off, no error raised");
        // The real bytes, which are the only thing that settles it.
        assert_eq!(Dimension::decode(0x0000_1001).unwrap().value, 16.0);
    }

    #[test]
    fn every_radix_decodes_to_the_same_value() {
        // 16.0 expressed in each of the four radices must decode identically.
        // This is the test that would fail if the multipliers were off by a
        // factor of 256 — a failure that is otherwise completely silent.
        // The multiplier table is the thing that would be wrong by a power of
        // two, so pin it directly: the smallest positive mantissa, 1, decodes
        // to 2^(-fractional bits) for each radix.
        for radix in 0u32..4 {
            let fractional = COMPLEX_RADIX_FRACTIONAL_BITS[radix as usize];
            let complex = (radix << COMPLEX_RADIX_SHIFT)
                | (1u32 << COMPLEX_MANTISSA_SHIFT)
                | COMPLEX_UNIT_DIP;
            let d = Dimension::decode(complex).unwrap();
            assert_eq!(
                d.value,
                2f32.powi(-(fractional as i32)),
                "radix {radix} decoded wrongly from 0x{complex:08x}"
            );
        }
        // And 16.0 — the value the real fixture holds — round-trips through the
        // narrowest radix that can express it.
        assert_eq!(float_to_complex(16.0) >> COMPLEX_RADIX_SHIFT & COMPLEX_RADIX_MASK, COMPLEX_RADIX_23P0);
        assert_eq!(complex_to_float(float_to_complex(16.0)), 16.0);
        // The fractional-bit widths are 0, 7, 15 and 23 — not 0, 8, 16, 24.
        // Getting that wrong is a factor-of-two error on every non-integral
        // dimension, and it is invisible in a self-consistent round trip.
        assert_eq!(COMPLEX_RADIX_FRACTIONAL_BITS, [0, 7, 15, 23]);
        let half = float_to_complex(0.5);
        assert_eq!(half >> COMPLEX_RADIX_SHIFT & COMPLEX_RADIX_MASK, COMPLEX_RADIX_16P7);
        assert_eq!(complex_to_float(half), 0.5);
    }

    #[test]
    fn radix_shifts_the_binary_point_not_the_magnitude() {
        // A value below 1 must survive the 0p23 radix, which is the one aapt2
        // chooses for fractional values like 0.5.
        let encoded = float_to_complex(0.5);
        assert_eq!(complex_to_float(encoded), 0.5);
        assert_eq!(Dimension::decode(encoded | COMPLEX_UNIT_DIP).unwrap().value, 0.5);
    }

    #[test]
    fn complex_round_trips() {
        for v in [0.0_f32, 1.0, -1.0, 0.5, -0.5, 16.0, -16.0, 100.0, 0.25, 4096.0] {
            let encoded = float_to_complex(v);
            assert_eq!(complex_to_float(encoded), v, "{v} did not round trip through 0x{encoded:08x}");
        }
    }

    #[test]
    fn negative_mantissas_decode_negative() {
        // Bit 31 is the sign, and the decode casts to i32 so that it survives.
        let complex = COMPLEX_RADIX_23P0 | ((-16.0 * 256.0) as i32 as u32) | COMPLEX_UNIT_DIP;
        assert_eq!(Dimension::decode(complex).unwrap().value, -16.0);
    }

    #[test]
    fn all_six_units_round_trip() {
        // The brief for this work said `TYPE_DIMENSION` has five units.
        // `ResourceTypes.h` defines six, and the real `com.dosse.clock31`
        // table uses two of them (dp and sp) with the unit in the low nibble.
        for unit in [Unit::Px, Unit::Dip, Unit::Sp, Unit::Pt, Unit::Inches, Unit::Millimetres] {
            let d = Dimension { value: 42.0, unit };
            let complex = float_to_complex(d.value) | unit.code();
            assert_eq!(Dimension::decode(complex).unwrap(), d, "{unit:?} did not round trip");
            assert_eq!(complex & COMPLEX_UNIT_MASK, unit.code(), "{unit:?} did not land in the unit nibble");
        }
    }

    #[test]
    fn unknown_unit_is_an_error_not_a_guess() {
        // COMPLEX_UNIT_* has exactly six members; 6..=15 is undefined.
        let complex = COMPLEX_RADIX_23P0 | (6 << COMPLEX_UNIT_SHIFT) | 4096;
        assert!(Dimension::decode(complex).is_err());
    }

    #[test]
    fn fraction_decodes_parent_and_whole() {
        let base = float_to_complex(0.5);
        let whole = base;
        let parent = base | 1;
        let f = Fraction::decode(whole).unwrap();
        assert!((f.value - 0.5).abs() < 1e-6);
        assert!(!f.parent);
        let f = Fraction::decode(parent).unwrap();
        assert!((f.value - 0.5).abs() < 1e-6);
        assert!(f.parent);
        assert!(Fraction::decode(2).is_err());
    }

    #[test]
    fn booleans_accept_both_encodings() {
        // aapt2 writes 0xFFFFFFFF; some older tables write 1. Both are true.
        let v = RawValue { size: 8, res0: 0, data_type: TYPE_INT_BOOLEAN, data: 0xFFFF_FFFF };
        assert_eq!(v.decode().as_bool(), Some(true));
        let v = RawValue { size: 8, res0: 0, data_type: TYPE_INT_BOOLEAN, data: 1 };
        assert_eq!(v.decode().as_bool(), Some(true));
        let v = RawValue { size: 8, res0: 0, data_type: TYPE_INT_BOOLEAN, data: 0 };
        assert_eq!(v.decode().as_bool(), Some(false));
    }

    #[test]
    fn null_distinguishes_empty_from_undefined() {
        let v = RawValue { size: 8, res0: 0, data_type: TYPE_NULL, data: DATA_NULL_EMPTY };
        assert_eq!(v.decode(), Value::Null(Null::Empty));
        assert!(v.decode().as_bool().is_none());
        let v = RawValue { size: 8, res0: 0, data_type: TYPE_NULL, data: 0 };
        assert_eq!(v.decode(), Value::Null(Null::Undefined));
    }

    #[test]
    fn unknown_tags_survive_as_raw() {
        // 0x20 is past TYPE_LAST_INT. It must be visible, not become zero.
        let v = RawValue { size: 8, res0: 0, data_type: 0x20, data: 0xABCD };
        assert_eq!(v.decode(), Value::Raw { data_type: 0x20, data: 0xABCD });
    }

    #[test]
    fn every_colour_format_decodes_to_argb() {
        for (data_type, format) in [
            (TYPE_INT_COLOR_ARGB8, ColorFormat::Argb8),
            (TYPE_INT_COLOR_RGB8, ColorFormat::Rgb8),
            (TYPE_INT_COLOR_ARGB4, ColorFormat::Argb4),
            (TYPE_INT_COLOR_RGB4, ColorFormat::Rgb4),
        ] {
            assert_eq!(ColorFormat::from_data_type(data_type), Some(format));
            // AAPT2 stores all four already expanded, so `data` *is* the ARGB.
            let v = RawValue { size: 8, res0: 0, data_type, data: 0x8012_3456 };
            assert_eq!(v.decode().as_argb(), Some(0x8012_3456));
        }
        assert_eq!(ColorFormat::from_data_type(TYPE_FIRST_INT), None);
    }

    #[test]
    fn reading_past_the_end_is_a_typed_error() {
        let b = [0u8; 4];
        assert!(matches!(
            RawValue::read(&b, 0),
            Err(ResourceError::Truncated { what: "Res_value", need: 8, have: 4 })
        ));
    }

    #[test]
    fn display_matches_aapt2_for_the_common_shapes() {
        assert_eq!(Value::Dimension(Dimension { value: 16.0, unit: Unit::Dip }).to_display(), "16.000000dp");
        assert_eq!(Value::Reference(0x7f03_0000).to_display(), "@0x7f030000");
        assert_eq!(Value::Attribute(0x0101_00d0).to_display(), "?0x010100d0");
        assert_eq!(Value::Int(-1).to_display(), "-1");
    }
}
