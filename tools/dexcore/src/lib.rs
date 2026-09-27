//! # dexcore
//!
//! A DEX container reader, Dalvik bytecode decoder, DEX writer/assembler and
//! Android binary XML parser, targeting `wasm32-unknown-unknown` so it can run
//! inside a browser with no server.
//!
//! ## Why reading *and* writing
//!
//! Most DEX tooling stops at reading. andro-substrate cannot: the runtime has
//! to fabricate synthetic classes for its `android.*` framework shim and have
//! them resolve in the same classloader as the untrusted app's own code, which
//! means emitting a `classes.dex` that a real Android loader will accept. The
//! writer in [`writer`] is the component that makes the architecture possible.
//!
//! ## Module map
//!
//! | module | role |
//! |---|---|
//! | [`header`] | `header_item` parse/serialise, Adler-32, SHA-1 |
//! | [`opcodes`] | the 256-entry Dalvik opcode table, formats and widths |
//! | [`mutf8`] | MUTF-8 codec and ULEB128/SLEB128 primitives |
//! | [`model`] | resolved pool and class structures |
//! | [`insn`] | the decoded `Instruction` enum |
//! | [`reader`] | bounds-checked reader over a `classes.dex` |
//! | [`asm`] | instruction encoder, producing `code_item` byte streams |
//! | [`writer`] | DEX builder: pools, class defs, `map_list` |
//! | [`axml`] | Android binary XML, for reading `AndroidManifest.xml` |
//! | [`wasm`] | `#[wasm_bindgen]` surface (wasm target only) |
//!
//! ## Safety posture
//!
//! Every fallible operation returns [`error::Result`]. The parsing path never
//! indexes a byte slice before a bounds check, and the wasm layer converts any
//! error into a JSON object with a stable `kind` discriminant, so a malformed
//! or hostile APK degrades to a typed error rather than a panic or a hang.
//!
//! ## Example
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let bytes: Vec<u8> = std::fs::read("classes.dex")?;
//! let dex = dexcore::DexReader::open(&bytes)?;
//! for class in dex.classes()? {
//!     println!("{} extends {}", class.descriptor, class.superclass);
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod asm;
pub mod axml;
pub mod error;
pub mod header;
pub mod insn;
pub mod model;
pub mod mutf8;
pub mod opcodes;
pub mod reader;
pub mod writer;

/// The browser-facing JSON surface: `parse_dex`, `list_classes`,
/// `decode_method` and `parse_axml`.
///
/// The module is compiled for every target so that its logic is covered by
/// `cargo test` on the host; only the four `#[wasm_bindgen]` wrappers are
/// gated on `wasm32`.
pub mod wasm;

pub use error::{Error, Result};
pub use header::DexHeader;
pub use insn::Instruction;
pub use model::{
    ClassData, CodeItem, DexClass, DexField, DexMethod, DexProto, DexString, DexType, MapItem,
};
pub use reader::{decode_all, decode_one, DexReader, Located};
pub use writer::{CatchHandler, ClassDef, CodeBody, DexWriter, FieldDef, MethodDef, TryCatch};
