//! Report which `code_item`s fail to decode and why. Used to establish that
//! `methods_undecodable` is a real, bounded property of real DEX and not a
//! defect in the walk.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: why-undecodable <apk>")?;
    let archive = substrate_predictor::zip::Archive::open(std::fs::read(path)?)?;
    for entry in archive.entries() {
        if !entry.name.ends_with(".dex") {
            continue;
        }
        let dex = archive.read_entry(entry)?;
        let r = dexcore::DexReader::open(&dex)?;
        let mut by_reason: std::collections::BTreeMap<String, (usize, String)> = Default::default();
        for ci in 0..r.class_def_count() {
            let Ok(c) = r.class_def(ci) else { continue };
            let Some(cd) = c.class_data else { continue };
            for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
                if m.code_off == 0 {
                    continue;
                }
                let units_bytes = match r.code_units(m.code_off) {
                    Ok(b) => b,
                    Err(e) => {
                        let e = by_reason
                            .entry(format!("code_units: {e}"))
                            .or_insert((0, String::new()));
                        e.0 += 1;
                        continue;
                    }
                };
                let units: Vec<u16> = units_bytes
                    .chunks_exact(2)
                    .map(|x| u16::from_le_bytes([x[0], x[1]]))
                    .collect();
                let mut at = 0usize;
                while at < units.len() {
                    match dexcore::reader::decode_one(&units, at) {
                        Ok((_, n)) => at += n.max(1),
                        Err(e) => {
                            let name = r
                                .method_at(m.method_idx)
                                .map(|x| format!("{}.{}", c.descriptor, x.name))
                                .unwrap_or_default();
                            let e2 = by_reason
                                .entry(format!("decode_one@{at}u: {e}"))
                                .or_insert((0, name.clone()));
                            e2.0 += 1;
                            break;
                        }
                    }
                }
            }
        }
        println!(
            "{}: {} distinct failure reasons",
            entry.name,
            by_reason.len()
        );
        for (reason, (n, sample)) in by_reason.iter().take(20) {
            println!("  {n:6}  {reason}   e.g. {sample}");
        }
    }
    Ok(())
}
