//! The try/catch table.
//!
//! # `dexcore` hands the handler list over as bytes, and the offsets are
//! relative to a prefix the decoder did not hand back
//!
//! A `try_item` is `start_addr`, `insn_count` and `handler_off`, and
//! `handler_off` is measured **from the start of the `encoded_catch_handler_list`
//! including its own `uleb128` size prefix**. `dexcore::CodeItem` exposes
//! `try_items` already decoded and the handler list as raw bytes, and decoding
//! the list needs a `DexReader` because the type descriptors inside it are
//! `type_list` offsets into the file.
//!
//! So the prefix width is recovered here by re-reading it, rather than assumed to
//! be one byte — which it is **not** for a list with more than 127 handlers. A
//! method with 128 catch clauses has every one of its `try_item`s resolve to the
//! wrong handler, silently, and a list that long is not exotic. This is the same
//! recovery the oracle performs, and it is one of the places where `dexcore` is
//! incomplete for a compiler's purposes; it is reported rather than patched,
//! because the study's numbers are taken against the oracle as it stands.
//!
//! # What is refused, and what is merely checked
//!
//! A `handler_off` that is smaller than the prefix width is **refused**: the
//! offset points *inside* the prefix, which no encoding can mean. Everything else
//! — a range running past the end of the code item, a catch-all that is not last,
//! a handler address that is not the start of an instruction — is **checked** by
//! [`crate::ir::Function::new`], which is the layer that knows what a coherent
//! frame is. Splitting it that way keeps each rule in one place and means the IR
//! does not have to re-state a rule the function builder already owns.

use dexcore::model::{CodeItem, TryItem};
use dexcore::mutf8;
use dexcore::reader::DexReader;

use crate::ir::{CatchClause, TryRegion};

use super::{LowerError, LowerResult};

/// Decode a code item's try table and its catch-handler list.
pub fn decode_tries(dex: &DexReader<'_>, item: &CodeItem) -> LowerResult<Vec<TryRegion>> {
    if item.tries_size == 0 {
        return Ok(Vec::new());
    }
    let tries: Vec<TryItem> = dex
        .try_items(item.offset)
        .map_err(|e| LowerError::Undecodable { at: 0, detail: format!("try items: {e}") })?;
    let body = item.encoded_catch_handler_list.as_slice();

    // The list's own `uleb128` size prefix — the byte `handler_off` counts from.
    // Recovered, not assumed.
    let (list_size, prefix) =
        mutf8::read_uleb128(body, 0).map_err(|_| LowerError::BadPayload {
            at: 0,
            why: "the catch-handler list's uleb128 size prefix does not decode".to_string(),
        })?;
    if list_size == 0 || list_size as usize > tries.len() {
        return Err(LowerError::BadPayload {
            at: 0,
            why: format!(
                "the catch-handler list declares {list_size} handlers for {} try items",
                tries.len()
            ),
        });
    }

    let mut out = Vec::with_capacity(tries.len());
    for t in &tries {
        // `handler_off` is measured from the start of the list *including* the
        // prefix, so it is already an offset into `body` and needs no adjustment.
        // The prefix is used for the one check that needs it: an offset that
        // lands inside the prefix is unrepresentable, because the prefix is not
        // an `encoded_catch_handler`.
        let Some(at) = usize::try_from(t.handler_off).ok().filter(|h| *h >= prefix) else {
            return Err(LowerError::BadPayload {
                at: 0,
                why: format!(
                    "try_item at {} has handler_off {}, which is inside the handler list's \
                     own {prefix}-byte size prefix",
                    t.start_addr, t.handler_off
                ),
            });
        };
        let end = t.start_addr.saturating_add(t.insn_count);
        out.push(TryRegion {
            start: t.start_addr,
            // Inclusive, as the input's range is: the last covered unit is
            // `start + count - 1`, and a zero-length range is refused rather
            // than wrapped by the `saturating_sub`.
            end: end.saturating_sub(1),
            handlers: decode_handler(dex, body, at, t.handler_off)?,
        });
    }
    Ok(out)
}

/// Decode one `encoded_catch_handler` at byte `at` within the list body.
///
/// `label` is the `try_item`'s own `handler_off`, quoted verbatim in any error:
/// it is the value a reader of a disassembly has to work from, and it is the only
/// thing that distinguishes two failures this function reports identically.
fn decode_handler(
    dex: &DexReader<'_>,
    body: &[u8],
    at: usize,
    label: u32,
) -> LowerResult<Vec<CatchClause>> {
    let bad = |what: &str| LowerError::BadPayload {
        at: 0,
        why: format!("catch handler at handler_off {label}: {what}"),
    };

    let (size, n) = mutf8::read_sleb128(body, at).map_err(|_| bad("clause count does not decode"))?;
    let mut at = at + n;

    // The clause count is *signed* and its sign carries the catch-all flag, so
    // `unsigned_abs` gives the typed-clause count and `size <= 0` the catch-all.
    let typed = size.unsigned_abs();
    let mut handlers = Vec::new();

    for _ in 0..typed {
        let (type_idx, tn) =
            mutf8::read_uleb128(body, at).map_err(|_| bad("a clause's type index does not decode"))?;
        at += tn;
        let (addr, an) =
            mutf8::read_uleb128(body, at).map_err(|_| bad("a clause's address does not decode"))?;
        at += an;
        // A `type_idx` of `NO_INDEX` is the alternative spelling of a catch-all.
        // Both spellings exist and both are accepted, because a file that uses
        // one and a reader that assumes the other fails in the direction of
        // "no handler matched", which is a silent miscompile.
        if type_idx == dexcore::header::NO_INDEX {
            handlers.push(CatchClause { type_descriptor: None, address: addr });
        } else {
            let descriptor = dex.type_name(type_idx).map_err(|_| bad("a clause names a type that does not exist"))?;
            handlers.push(CatchClause { type_descriptor: Some(descriptor), address: addr });
        }
    }
    if size <= 0 {
        let (addr, an) = mutf8::read_uleb128(body, at).map_err(|_| bad("the catch-all address does not decode"))?;
        handlers.push(CatchClause { type_descriptor: None, address: addr });
        let _ = an;
    }
    if handlers.is_empty() {
        return Err(bad("the handler has no clauses, which no encoding permits"));
    }
    Ok(handlers)
}
