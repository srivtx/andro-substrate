//! The hostgen test suite.
//!
//! | module | what it defends |
//! |---|---|
//! | [`taxonomy_registry`] | the 145-ID registry matches `docs/divergence-taxonomy.md` in both directions |
//! | [`hostgen_closure`] | a real DEX closure produces a host, and the table is complete |
//! | [`hostile_apk`] | an app that declares framework classes cannot take them over; shadowing is counted |
//! | [`redaction`] | no recording type can hold a body, a header value, a query value, or an argument value |
//! | [`egress_denial`] | no policy combination reaches a socket |
//! | [`synthesis_policy`] | the default-answer tables are the declared ones |
//! | [`no_panic`] | hostile input is refused, never panicked on |

pub mod egress_denial;
pub mod hostile_apk;
pub mod hostgen_closure;
pub mod no_panic;
pub mod redaction;
pub mod synthesis_policy;
pub mod taxonomy_registry;

#[cfg(test)]
mod probe_report {
    use crate::hostgen::answer::{DeclaredEnv, StructuralAnswer};
    use crate::hostgen::emit::emit;
    use crate::hostgen::policy::HostPolicy;
    use crate::hostgen::tests::hostgen_closure::{FIXTURES, closure_from_dex};

    #[test]
    fn print_reports() {
        for (name, bytes) in FIXTURES {
            let (c, pkg) = match closure_from_dex(bytes) {
                Ok(v) => v,
                Err(e) => {
                    println!("{name}: ERR {e}");
                    continue;
                }
            };
            let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            println!(
                "===== {name} pkg={pkg} members={} classes={} entries={} fab={} denied={}",
                c.len(),
                c.class_count(),
                h.entries.len(),
                h.ledger.total(),
                h.ledger.denials()
            );
            for f in [
                StructuralAnswer::Void,
                StructuralAnswer::Null,
                StructuralAnswer::Zero,
            ] {
                println!("   struct {:?} = {}", f, h.ledger.count_of(f));
            }
            for e in h
                .entries
                .iter()
                .filter(|e| {
                    matches!(e, crate::hostgen::emit::HostEntry::Method(m) if m.is_fabrication())
                })
                .take(3)
            {
                println!("   fab: {}", e.key().unwrap_or_default());
            }
        }
    }
}
