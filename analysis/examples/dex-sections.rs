//! Print the `map_list` section inventory of every `classes*.dex` in an APK,
//! with the DEX version string.
//!
//! This exists because of a specific finding: DEX version 039 (emitted by d8 for
//! `targetSdk >= 30`) has **no** `call_site_id_item` and **no**
//! `method_handle_item` section, even in files that contain thousands of
//! `const-method-handle` instructions and hundreds of `invoke-custom` sites. The
//! `method@` operand of `invoke-polymorphic` is written as the `NO_INDEX`
//! sentinel `0xffff`.
//!
//! The consequence for a substrate is concrete: the invokedynamic dependency
//! cannot be enumerated from the pool. It can only be *counted*, from the
//! opcodes. `analysis/prediction.md` reports it that way, and this example
//! exists so a reader can check the structural claim in one command.
//!
//! ```text
//! cargo run --release --example dex-sections -- <apk>
//! ```

use substrate_predictor::zip::Archive;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: dex-sections <apk>")?;
    let archive = Archive::open(std::fs::read(path)?)?;
    for entry in archive.entries() {
        if !entry.name.ends_with(".dex") {
            continue;
        }
        let dex = archive.read_entry(entry)?;
        let reader = dexcore::DexReader::open(&dex)?;
        let h = reader.header();
        println!(
            "{}  version={}{}{}  method_ids={}  call_sites={}  method_handles={}",
            entry.name,
            h.version[0] as char,
            h.version[1] as char,
            h.version[2] as char,
            reader.method_count(),
            reader
                .map_list()?
                .iter()
                .find(|m| m.item_type == dexcore::model::map_type::CALL_SITE_ID_ITEM)
                .map_or(0, |m| m.size),
            reader
                .map_list()?
                .iter()
                .find(|m| m.item_type == dexcore::model::map_type::METHOD_HANDLE_ITEM)
                .map_or(0, |m| m.size),
        );
    }
    Ok(())
}
