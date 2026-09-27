//! Print the raw `u16` code units of the first method whose decode fails in a
//! DEX, so the byte-level cause can be read off directly.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: streambytes <apk> <class-descriptor> <method-name>")?;
    let want_class = std::env::args().nth(2).unwrap_or_default();
    let want_method = std::env::args().nth(3).unwrap_or_default();
    let archive = substrate_predictor::zip::Archive::open(std::fs::read(path)?)?;
    for entry in archive.entries() {
        if !entry.name.ends_with(".dex") {
            continue;
        }
        let dex = archive.read_entry(entry)?;
        let r = dexcore::DexReader::open(&dex)?;
        for ci in 0..r.class_def_count() {
            let Ok(c) = r.class_def(ci) else { continue };
            if !want_class.is_empty() && c.descriptor != want_class {
                continue;
            }
            let Some(cd) = c.class_data else { continue };
            for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
                if m.code_off == 0 {
                    continue;
                }
                let mname = r
                    .method_at(m.method_idx)
                    .map(|x| x.name.clone())
                    .unwrap_or_default();
                if !want_method.is_empty() && mname != want_method {
                    continue;
                }
                let Ok(hdr) = r.code_item(m.code_off) else {
                    println!(
                        "{} .{} code_item header unreadable (tries_size parse)",
                        c.descriptor, mname
                    );
                    continue;
                };
                println!(
                    "{} .{} insns_size={} bytes={}",
                    c.descriptor,
                    mname,
                    hdr.insns_size,
                    hdr.insns_size * 2
                );
                let bytes = r.bytes();
                let base = hdr.insns_off as usize;
                for i in 0..hdr.insns_size as usize {
                    let b = &bytes[base + i * 2..base + i * 2 + 2];
                    if i % 8 == 0 {
                        print!("\n  {:4}:", i);
                    }
                    print!(" {:02x}{:02x}", b[0], b[1]);
                }
                println!();
                return Ok(());
            }
        }
    }
    Ok(())
}
