//! The DEX round-trip: the shim emits a `classes.dex`, and `dexcore`'s reader
//! reads it back.
//!
//! The writer is the component the whole architecture rests on
//! (`docs/decisions/0002-dex-toolchain.md`), and a writer that is only ever
//! exercised through a file with no instructions in it is not tested. So the
//! checks here are deliberately layered:
//!
//! 1. the file opens, the header is self-consistent, and the checksums verify;
//! 2. every registry class is present with the right superclass;
//! 3. every registry method is present with the right prototype and is
//!    `ACC_NATIVE` with **no** `code_item` — the safety property, checked as a
//!    test rather than asserted in a document;
//! 4. the bridge's real code items survive, including a `try` block whose handler
//!    list has a typed clause followed by a catch-all, in that order;
//! 5. every instruction decodes, and a `native`-method call the loader could not
//!    satisfy is a *loud* failure rather than a silent zero.

use shim::registry::{self, Behaviour};
use shim::{emit, ShimCaller, Value};

/// The emitted DEX, built once. Emitting is deterministic, so sharing it across
/// tests costs nothing and makes the suite fast.
fn emitted() -> &'static emit::EmittedShim {
    use std::sync::OnceLock;
    static ONCE: OnceLock<emit::EmittedShim> = OnceLock::new();
    ONCE.get_or_init(|| emit::emit().expect("emit the shim dex"))
}

fn reader() -> &'static (dexcore::DexReader<'static>, Vec<u8>) {
    use std::sync::OnceLock;
    // The reader borrows the bytes, so the bytes have to outlive it. A leaked
    // Vec in a test binary is the right trade: it is bounded and it removes an
    // entire class of lifetime noise from every test below.
    static ONCE: OnceLock<(dexcore::DexReader<'static>, Vec<u8>)> = OnceLock::new();
    ONCE.get_or_init(|| {
        let leaked: &'static [u8] = Box::leak(emitted().bytes.clone().into_boxed_slice());
        (
            dexcore::DexReader::open(leaked).expect("emitted dex must parse"),
            leaked.to_vec(),
        )
    })
}

#[test]
fn the_emitted_file_is_a_valid_dex() {
    let e = emitted();
    assert_eq!(&e.bytes[0..4], b"dex\n", "magic");
    assert_eq!(
        dexcore::DexReader::open(&e.bytes)
            .expect("open")
            .header()
            .endian_tag,
        dexcore::header::ENDIAN_CONSTANT,
        "endian tag"
    );
    assert_eq!(e.dex_version, "035");
    assert!(e.bytes.len() > 112, "a header alone is 112 bytes");
    let (d, _) = reader();
    d.verify_integrity().expect("integrity");
    assert_eq!(d.header().file_size as usize, e.bytes.len());
    assert_eq!(d.class_def_count() as usize, e.class_count);
    assert_eq!(d.method_count() as usize, e.method_count);
    assert_eq!(d.field_count() as usize, e.field_count);
    assert_eq!(d.string_count() as usize, e.string_count);
    // A digest a recording can pin, so a capture is tied to the exact instrument.
    assert_eq!(e.digest.len(), 64);
    assert!(e
        .digest
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
}

#[test]
fn every_registry_class_is_in_the_file_with_its_real_superclass() {
    let (d, _) = reader();
    for def in registry::CLASSES {
        let idx = d
            .find_class(def.descriptor)
            .unwrap_or_else(|_| panic!("{} must be defined", def.descriptor))
            .expect("not found");
        let c = d.class_def(idx).expect("class def");
        // `class_def` reports an absent superclass as an empty string, because
        // the field is `NO_INDEX` in the file.
        let want = def.superclass.unwrap_or("");
        assert_eq!(c.superclass.as_str(), want, "{}", def.descriptor);
    }
    assert!(
        d.find_class("Ljava/lang/Object;")
            .expect("lookup")
            .is_some(),
        "the shim is hermetic: java.lang.Object is in the shim DEX, because a \
         substrate classloader owns the whole java.* surface"
    );
    // The bridge, which is not an android.* class and must not shadow anything.
    assert!(d.find_class(emit::BRIDGE).expect("lookup").is_some());
}

#[test]
fn every_method_is_native_and_has_no_code() {
    // The safety property: a shim method with no registration throws
    // UnsatisfiedLinkError, so a misplaced DEX fails loudly instead of returning
    // zero and letting an app produce wrong results.
    let (d, _) = reader();
    let mut checked = 0usize;
    for def in registry::CLASSES {
        let idx = d
            .find_class(def.descriptor)
            .expect("lookup")
            .expect("class");
        let cd = d
            .class_data(d.class_def(idx).expect("def").class_data_off)
            .expect("data");
        let mut seen: Vec<String> = Vec::new();
        for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
            let md = d.method_at(m.method_idx).expect("method");
            assert_eq!(
                m.access_flags & dexcore::model::access::ACC_NATIVE,
                dexcore::model::access::ACC_NATIVE,
                "{} must be native",
                md.signature()
            );
            assert_eq!(
                m.code_off,
                0,
                "{} must have no code item; behaviour lives in the dispatcher",
                md.signature()
            );
            // And no two methods of one name, which the writer cannot express
            // without an overload-aware rewrite.
            // Uniqueness is per (class, name, prototype): two constructors with
            // different parameter lists are distinct methods in a DEX and are
            // used that way by the table.
            let key = md.signature();
            assert!(!seen.contains(&key), "duplicate method {key}");
            seen.push(key);
            checked += 1;
        }
    }
    assert_eq!(checked, registry::method_count());
}

#[test]
fn prototypes_survive_the_pool_sort() {
    // dexcore's writer renumbers every pool at `freeze()`, so a prototype that
    // comes back with a different parameter list is the single most likely
    // silent corruption in a DEX writer. Check the signatures that exercise
    // arrays, longs, returns and overloads.
    let (d, _) = reader();
    for (class, name, want_sig) in [
        (
            "Landroid/content/Context;",
            "getSystemService",
            "Landroid/content/Context;.getSystemService(Ljava/lang/String;)Ljava/lang/Object;",
        ),
        (
            "Ljava/io/OutputStream;",
            "write",
            "Ljava/io/OutputStream;.write([BII)V",
        ),
        (
            "Ljava/lang/Class;",
            "forName",
            "Ljava/lang/Class;.forName(Ljava/lang/String;)Ljava/lang/Class;",
        ),
        (
            "Ljava/net/URLConnection;",
            "connect",
            "Ljava/net/URLConnection;.connect()V",
        ),
        (
            "Ljava/net/HttpURLConnection;",
            "getResponseCode",
            "Ljava/net/HttpURLConnection;.getResponseCode()I",
        ),
        (
            "Landroid/content/Intent;",
            "<init>",
            "Landroid/content/Intent;.<init>(Ljava/lang/String;)V",
        ),
        (
            "Landroid/os/Handler;",
            "postDelayed",
            "Landroid/os/Handler;.postDelayed(Ljava/lang/Object;J)Z",
        ),
    ] {
        let found = (0..d.method_count())
            .filter_map(|i| d.method_at(i).ok())
            .filter(|m| m.class == class && m.name == name)
            .find(|m| m.signature() == want_sig)
            .unwrap_or_else(|| {
                let all: Vec<String> = (0..d.method_count())
                    .filter_map(|i| d.method_at(i).ok())
                    .filter(|m| m.class == class && m.name == name)
                    .map(|m| m.signature())
                    .collect();
                panic!("{class}.{name} {want_sig} not in the method pool; the pool has {all:?}")
            });
        assert_eq!(found.signature(), want_sig);
    }
    // Both `Intent` constructors are present: an overload is two method ids, and
    // the writer must not collapse them.
    let intents: Vec<String> = (0..d.method_count())
        .filter_map(|i| d.method_at(i).ok())
        .filter(|m| m.class == "Landroid/content/Intent;" && m.name == "<init>")
        .map(|m| m.signature())
        .collect();
    assert_eq!(intents.len(), 2, "{intents:?}");
}

#[test]
fn the_bridge_carries_real_code_with_a_typed_handler_then_a_catch_all() {
    let (d, _) = reader();
    let idx = d.find_class(emit::BRIDGE).expect("lookup").expect("class");
    let cd = d
        .class_data(d.class_def(idx).expect("def").class_data_off)
        .expect("data");
    let with_code: Vec<_> = cd
        .virtual_methods
        .iter()
        .filter(|m| m.code_off != 0)
        .collect();
    assert_eq!(
        with_code.len(),
        3,
        "the bridge exists precisely so the writer's code_item path is exercised"
    );

    let ns = d.class_def(idx).expect("def").class_data_off;
    let _ = ns;
    let code_offs: Vec<u32> = with_code.iter().map(|m| m.code_off).collect();
    for off in code_offs {
        let code = d.code_item(off).expect("code item");
        assert!(code.insns_size > 0, "a bridge body must have instructions");
        assert_eq!(code.debug_info_off, 0, "the writer emits no debug info");
        // Every instruction decodes. A stream that does not decode is a stream a
        // real loader would reject.
        let units = d.code_units(off).expect("units");
        let as_u16: Vec<u16> = units
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded = dexcore::decode_all(&as_u16).expect("every bridge instruction decodes");
        assert!(!decoded.is_empty());
    }

    // The try table: exactly one method has one, and its handler list is a
    // typed clause followed by a catch-all, which is the ordering the encoding
    // requires and the thing a naive writer gets wrong.
    let with_tries: Vec<&dexcore::model::EncodedMethod> = with_code
        .iter()
        .copied()
        .filter(|m| d.code_item(m.code_off).map(|c| c.tries_size).unwrap_or(0) > 0)
        .collect();
    assert_eq!(with_tries.len(), 1, "one bridge method carries a try table");
    let code = d.code_item(with_tries[0].code_off).expect("code");
    assert_eq!(code.tries_size, 1);
    let items = d.try_items(with_tries[0].code_off).expect("try items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].start_addr, 0);
    assert_eq!(items[0].insn_count, code.insns_size);
    // The handler list is opaque to the reader by design, so the invariant is
    // checked on the bytes: a negative count means "N typed clauses then a
    // catch-all", which is what the writer was asked to emit.
    assert!(
        !code.encoded_catch_handler_list.is_empty(),
        "the encoded_catch_handler_list must survive the round trip"
    );
    // `encoded_catch_handler_list` is the whole list *including* its ULEB128
    // size prefix, so the SLEB128 signed count starts after it. Here there is
    // exactly one handler list, so the prefix is one byte.
    let list = &code.encoded_catch_handler_list;
    assert_eq!(list[0], 1, "one unique handler list");
    let raw = list[1];
    // A single-byte SLEB128 with bit 0x40 set is negative; -1 encodes as 0x7F. A
    // naive `as i8` reads 0x7F as 127, which is exactly the sign slip that
    // makes a handler list decode as a positive count, so decode it properly.
    let count = (raw & 0x7f) as i32 - if raw & 0x40 != 0 { 0x80 } else { 0 };
    assert!(
        count < 0,
        "a handler list ending in a catch-all encodes a negative typed count; got {count} from byte {raw:#x}"
    );
    assert_eq!(-count, 1, "exactly one typed clause");
    // And the typed clause's type index must resolve to the exception class, with
    // the catch-all address after it. This is the ordering the encoding mandates.
    // Layout: size, sleb count, then (typed type_idx, typed addr) pairs, then the
    // catch-all address. So the typed clause occupies bytes 2 and 3.
    let typed_type = list[2] as u32;
    let catch_all_addr = list[4] as u32;
    assert_eq!(list[3] as u32, 0, "the typed clause's handler address");
    assert_eq!(
        d.type_name(typed_type).unwrap_or_default(),
        "Ljava/lang/Throwable;",
        "the typed clause must name the exception class"
    );
    assert_eq!(
        catch_all_addr, 1,
        "the catch-all address follows the clause"
    );
}

#[test]
fn a_disassembled_bridge_method_matches_the_bytes_we_assembled() {
    // Cross-check rather than restate: the string constant must be the taxonomy
    // ID the emitter interned, addressed by a `const-string` in the stream.
    let (d, _) = reader();
    let idx = d.find_class(emit::BRIDGE).expect("lookup").expect("class");
    let cd = d
        .class_data(d.class_def(idx).expect("def").class_data_off)
        .expect("data");
    let m = cd
        .virtual_methods
        .iter()
        .find(|m| {
            d.method_at(m.method_idx)
                .map(|x| x.name.clone())
                .ok()
                .as_deref()
                == Some("nativeUnsatisfied")
        })
        .expect("nativeUnsatisfied");
    let units = d.code_units(m.code_off).expect("units");
    let as_u16: Vec<u16> = units
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let decoded = dexcore::decode_all(&as_u16).expect("decode");
    let found = decoded.iter().any(|loc| {
        matches!(
            &loc.instruction,
            dexcore::Instruction::F21C { index, .. } if d
                .string(u32::from(*index))
                .map(|s| s.value == emit::UNSATISFIED_MARKER)
                .unwrap_or(false)
        )
    });
    assert!(
        found,
        "the bridge's bytecode must carry the taxonomy ID as a const-string: {decoded:?}"
    );
}

#[test]
fn emission_is_deterministic() {
    // A recording pins the shim DEX by digest, so two runs of the same build
    // must produce the same bytes. A pool ordering that depended on a hash seed
    // would break the reproducibility the study depends on.
    let a = emit::emit().expect("first");
    let b = emit::emit().expect("second");
    assert_eq!(a.digest, b.digest);
    assert_eq!(a.bytes, b.bytes);
}

#[test]
fn the_table_and_the_dex_agree_on_what_is_observation_bearing() {
    // A method the table marks `Dispatch` must be invokable, and one marked
    // `Inert` must return a value of the right shape rather than an error, or an
    // app would fail in a way a device would not.
    let mut shim = shim::Shim::new("a.b", vec![]).expect("shim");
    let mut probes = 0usize;
    for def in registry::CLASSES {
        for m in def.methods() {
            match m.behaviour {
                Behaviour::Dispatch(key) => {
                    probes += 1;
                    // The handler must exist: an unknown key is a hard error, and
                    // a hard error is exactly what a test should turn into a
                    // failure rather than a silent fallthrough.
                    let args: Vec<Value> = m
                        .params
                        .iter()
                        .map(|p| match *p {
                            "I" | "S" | "B" | "C" => Value::Int(0),
                            "Z" => Value::Int(0),
                            "J" => Value::Long(0),
                            _ => Value::Str(String::new()),
                        })
                        .collect();
                    let with_recv = if m.access_flags & dexcore::model::access::ACC_STATIC != 0 {
                        args
                    } else {
                        let mut v = vec![Value::Ref(def.descriptor.to_string(), 9999)];
                        v.extend(args);
                        v
                    };
                    let r = shim.invoke(def.descriptor, m.name, "", &with_recv);
                    if let Err(e) = &r {
                        assert!(
                            !e.to_string().contains("has no handler"),
                            "{}.{} ({key}) has no handler: {e}",
                            def.descriptor,
                            m.name
                        );
                    }
                }
                Behaviour::Inert => {
                    let args: Vec<Value> = m
                        .params
                        .iter()
                        .map(|p| match *p {
                            "I" | "S" | "B" | "C" => Value::Int(0),
                            "J" => Value::Long(0),
                            _ => Value::Str(String::new()),
                        })
                        .collect();
                    let with_recv = if m.access_flags & dexcore::model::access::ACC_STATIC != 0 {
                        args
                    } else {
                        let mut v = vec![Value::Ref(def.descriptor.to_string(), 9999)];
                        v.extend(args);
                        v
                    };
                    shim.invoke(def.descriptor, m.name, "", &with_recv)
                        .unwrap_or_else(|e| {
                            panic!(
                                "{} .{} is Inert and must not error: {e}",
                                def.descriptor, m.name
                            )
                        });
                }
                _ => {}
            }
        }
    }
    assert!(probes > 50, "the table should hold a real dispatch surface");
}

/// Keeps a `dexcore` defect visible without failing the suite.
///
/// `dexcore::writer::intern_type_list` allocates `4 + 2n` bytes — showing 2 bytes
/// per element was the intent — and then appends `u32::to_le_bytes()`, writing 4
/// bytes per element. Every `type_list` with two or more elements is therefore
/// mis-encoded, and a loader resolves a different prototype from the one the call
/// site encoded.
///
/// `shim::emit::repair_type_lists` corrects the emitted bytes in place and reseals
/// the file, so the shim is not affected. This test reports whether the repair
/// was still needed, which is how the defect stays visible in the test output
/// after `tools/dexcore` is fixed rather than being quietly forgotten.
///
/// **It asserts nothing.** When `dexcore` is repaired, the repair becomes a no-op,
/// this test reports `no`, and deleting the workaround in `src/emit.rs` is then a
/// two-line change.
#[test]
fn dexcore_still_widens_type_lists() {
    let e = emitted();
    if e.dexcore_type_lists_repaired {
        eprintln!(
            "NOTE  tools/dexcore {}/src/writer.rs `intern_type_list` still writes each \
type index as 4 bytes instead of 2. shim::emit::repair_type_lists corrected the output; \
please fix the writer and delete the workaround.",
            env!("CARGO_MANIFEST_DIR")
        );
    } else {
        eprintln!(
            "NOTE  dexcore emits correctly-sized type_lists; shim::emit::repair_type_lists is \
now a no-op and can be deleted."
        );
    }
}
