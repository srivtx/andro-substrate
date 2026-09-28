//! Print the decoded instruction stream of one method. A debugging aid, not part
//! of the deliverable; it exists because "the interpreter said it could not
//! resolve X" is only actionable if you can see what X's call site looks like.
use std::process::ExitCode;
fn main() -> ExitCode {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.len() < 2 {
        eprintln!("usage: insn-dump <apk> <Lcls;.name(sig)>");
        return ExitCode::from(1);
    }
    let apk = match substrate_harness::open_apk(std::path::Path::new(&a[0])) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let dex = match apk.classes_dex() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let sig = &a[1];
    let (class, rest) = match sig.split_once(';') {
        Some(x) => x,
        None => {
            eprintln!("bad target");
            return ExitCode::from(1);
        }
    };
    let (name, proto) = match rest.split_once('(') {
        Some(x) => x,
        None => {
            eprintln!("bad target");
            return ExitCode::from(1);
        }
    };
    let signature = format!("({proto}");
    let r = dexcore::DexReader::open(&dex).unwrap();
    let mut p = dexinterp::Program::build(&r).unwrap();
    for i in 0..r.method_count() {
        let m = r.method_at(i).unwrap();
        let s = format!("({}){}", m.parameters.join(""), m.return_type);
        if m.class == class && m.name == name && s == signature {
            let off = p.method_code_offset(class, name, &signature);
            println!("method #{i} {class}.{name}{signature} code_off={off:?}");
            if let Some(off) = off {
                let code = p.code(&r, off).unwrap();
                println!(
                    "units={} regs={} ins={}",
                    code.units, code.registers_size, code.ins_size
                );
                for ins in &code.insns {
                    println!("  u{:4}  {:?}", ins.unit, ins.instruction);
                }
            }
            return ExitCode::SUCCESS;
        }
    }
    eprintln!("no such method in the file");
    ExitCode::from(1)
}
