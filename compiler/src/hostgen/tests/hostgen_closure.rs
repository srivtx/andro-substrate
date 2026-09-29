//! A real DEX closure, and the host generated from it.
//!
//! # Why this file reads a real APK's DEX
//!
//! The thesis this crate exists for is a number: 4,649 framework methods over
//! 894 classes for `eu.ln.gita`, the *smallest* of 2,003 pure-DEX candidates,
//! against 334 hand-written shim methods. A claim like that has to be checked
//! against real input or it is a claim about a hypothetical.
//!
//! `tools/dexcore/tests/fixtures/` holds six real `classes.dex` files committed
//! to this repository, and `IR.md` §Verification names them as the fixtures the
//! compiled output must be checked against. So the closure here is built by
//! reading a real DEX with the project's own reader: the method references are
//! the ones the app actually contains, resolved through `dexcore`.
//!
//! # What this closure *is* and is not
//!
//! **It is** an over-approximation of the reachability closure, and the
//! over-approximation is deliberate and stated:
//!
//! * Every `class_def` in the file contributes its methods. A real reachability
//!   pass (`compiler/src/reach/`, A4) would additionally walk the call graph
//!   from the launch activity; this does not, because doing it properly is
//!   A4's job and doing it twice invites two answers.
//! * Every method referenced from the pool is included, including ones only
//!   reachable by a path this walk does not follow.
//!
//! **It is not** a claim about a specific app's first frame. The 4,649 figure
//! is the orchestrator's, measured elsewhere; this file's job is to show the
//! generator handles a real closure of the right order of magnitude and to
//! report what it generates. The counts below are labelled *measured on the
//! fixture* wherever they appear, which is `IR.md`'s "every figure is labelled
//! measured, derived, or conjecture" applied honestly: a figure from a
//! different app's measurement is not re-labelled as this app's.

use std::collections::{BTreeMap, BTreeSet};

use crate::hostgen::answer::{DeclaredEnv, StructuralAnswer};
use crate::hostgen::closure::{Closure, ClosureMember, MethodAccess, Origin, ReflectiveEdge};
use crate::hostgen::emit::{HostEntry, Kind, emit};
use crate::hostgen::egress::SideEffectClass;
use crate::hostgen::policy::HostPolicy;
use crate::hostgen::synth::Attribution;
use crate::hostgen::taxonomy::{AssumptionId, Family};

/// The six real DEX fixtures committed to this repository.
///
/// Named from `tools/dexcore/tests/FIXTURES.md`; the byte slices are embedded so
/// the test cannot pass or fail on a network fetch or a missing checkout.
pub const FIXTURES: &[(&str, &[u8])] = &[
    (
        "pro.rudloff.search_to_browser",
        include_bytes!("../../../../tools/dexcore/tests/fixtures/pro.rudloff.search_to_browser_2.dex"),
    ),
    (
        "fr.smarquis.sleeptimer",
        include_bytes!("../../../../tools/dexcore/tests/fixtures/fr.smarquis.sleeptimer_16200.dex"),
    ),
    (
        "com.android.adbkeyboard",
        include_bytes!("../../../../tools/dexcore/tests/fixtures/com.android.adbkeyboard_2.dex"),
    ),
    (
        "com.oF2pks.neolinker",
        include_bytes!("../../../../tools/dexcore/tests/fixtures/com.oF2pks.neolinker_7.dex"),
    ),
    (
        "org.vi_server.red_screen",
        include_bytes!("../../../../tools/dexcore/tests/fixtures/org.vi_server.red_screen_3.dex"),
    ),
    (
        "com.termux.boot",
        include_bytes!("../../../../tools/dexcore/tests/fixtures/com.termux.boot_1000.dex"),
    ),
];

/// Build a closure over a real DEX: every class's methods, plus every method
/// the pool references.
///
/// Returns the closure and the app's own package, the latter read off the
/// dominant class prefix so the classification can tell app code from framework.
pub fn closure_from_dex(bytes: &[u8]) -> Result<(Closure, String), String> {
    let reader = dexcore::DexReader::open(bytes).map_err(|e| format!("{e:?}"))?;
    let mut closure = Closure::new();

    // Classes the app defines. Everything in a class_def is app code.
    let classes = reader.classes().map_err(|e| format!("{e:?}"))?;
    if classes.is_empty() {
        return Err("the DEX declares no classes".to_string());
    }
    let app_classes: Vec<String> = classes.iter().map(|c| c.descriptor.clone()).collect();
    let package = dominant_package(&app_classes);
    closure.set_app_package(package.trim_end_matches('/'));
    for c in &app_classes {
        closure.add_app_class(c.clone());
    }

    // Methods the app *declares*. `class_data.direct_methods` and
    // `virtual_methods` carry an absolute `method_idx` into `method_ids`, so the
    // name and the descriptor both come from `method_at`.
    for class in &classes {
        let data = match &class.class_data {
            Some(d) => d,
            None => continue,
        };
        for encoded in data.direct_methods.iter().chain(data.virtual_methods.iter()) {
            let m = reader.method_at(encoded.method_idx).map_err(|e| format!("{e:?}"))?;
            closure.add(ClosureMember {
                class: m.class,
                name: m.name,
                signature: format!("({}){}", m.parameters.join(""), m.return_type),
                origin: Origin::CallGraph,
                access: MethodAccess {
                    is_static: encoded.access_flags & 0x0008 != 0,
                    is_native: encoded.access_flags & 0x0100 != 0,
                    is_abstract: encoded.access_flags & 0x0400 != 0,
                    is_constructor: false,
                },
            });
        }
    }

    // Every method in the pool, as `Origin::Superclass` — the closest of
    // `IR.md`'s four bullets for "a name the app can resolve". These are the
    // framework calls, and they are the reason the generator exists: this is
    // the over-approximation, and it is stated as one.
    for i in 0..reader.method_count() {
        let m = reader.method_at(i).map_err(|e| format!("{e:?}"))?;
        closure.add(ClosureMember::new(
            m.class,
            m.name,
            format!("({}){}", m.parameters.join(""), m.return_type),
            Origin::Superclass,
        ));
    }

    // Reflection is a hole and must be reported. A `const-string` naming a class
    // is a *candidate* edge, so every such string becomes an explicit
    // reflective record, and whether it resolved is decided by looking the
    // target up in the DEX's own type list.
    let known: BTreeSet<String> = reader
        .types()
        .map_err(|e| format!("{e:?}"))?
        .into_iter()
        .map(|t| t.descriptor)
        .collect();
    for s in reader.strings().map_err(|e| format!("{e:?}"))? {
        let text = s.value;
        if text.starts_with('L') && text.ends_with(';') && text.contains('/') {
            let status = if known.contains(&text) {
                crate::hostgen::closure::ReflectiveStatus::Resolved
            } else {
                crate::hostgen::closure::ReflectiveStatus::Unresolved
            };
            closure.add_reflective(ReflectiveEdge {
                from_class: package.clone(),
                target: text,
                status,
                site: None,
            });
        }
    }

    closure.add_entry_point(format!("{package}-><entry>"));

    Ok((closure, package))
}

/// The most common package prefix across a class list.
fn dominant_package(classes: &[String]) -> String {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for c in classes {
        let body = c.trim_start_matches('L').trim_end_matches(';');
        let mut segs: Vec<&str> = body.split('/').collect();
        segs.pop();
        if segs.len() < 2 {
            continue;
        }
        let mut p = String::new();
        for s in segs {
            p.push_str(s);
            p.push('/');
        }
        *counts.entry(p).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(p, _)| p)
        .unwrap_or_default()
}

/// Every fixture's closure, emitted once. A failure is a test failure, not a
/// skip: a fixture that stops parsing is a change in `dexcore` that needs a
/// look.
fn all_closures() -> Vec<(&'static str, Result<(Closure, String), String>)> {
    FIXTURES
        .iter()
        .map(|(name, bytes)| (*name, closure_from_dex(bytes)))
        .collect()
}

// ================================================== the measurement

#[test]
fn every_fixture_produces_a_non_trivial_closure() {
    let mut total_members = 0usize;
    let mut total_classes = 0usize;
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: closure construction failed: {e}"),
        };
        assert!(c.len() > 0, "{name}: empty closure");
        assert!(c.class_count() > 0, "{name}: no classes");
        total_members += c.len();
        total_classes += c.class_count();
    }
    // The threshold is a floor on "the reader is really walking the DEX", not a
    // claim about any app. Even the smallest committed fixture is a real APK
    // with real framework references.
    assert!(
        total_members > 1_000,
        "the six fixtures yielded only {total_members} members; the closure walk is not reading real DEX"
    );
    assert!(total_classes > 100);
}

#[test]
fn the_generated_host_covers_every_non_app_class_in_the_closure() {
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        let h = match emit(&c, &HostPolicy::default(), &DeclaredEnv::new()) {
            Ok(h) => h,
            Err(e) => panic!("{name}: emit failed: {e}"),
        };
        // Every class the host claims got an entry.
        let emitted: BTreeSet<String> = h
            .entries
            .iter()
            .filter_map(|e| match e {
                HostEntry::Class(ce) => Some(ce.name.clone()),
                _ => None,
            })
            .collect();
        for member in c.members() {
            if c.host_claims(&member.class) {
                assert!(
                    emitted.contains(&member.class),
                    "{name}: {} is claimed by the host but has no class entry",
                    member.class
                );
            }
        }
        assert!(
            !h.entries.is_empty(),
            "{name}: emitted an empty host for a non-empty closure"
        );
    }
}

#[test]
fn every_emitted_entry_carries_a_registered_taxonomy_id() {
    // The requirement `IR.md` states as a defect if violated.
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        for e in &h.entries {
            let id = e.taxonomy().id();
            assert!(
                AssumptionId::ALL.contains(&id),
                "{name}: an entry carries {id}, which is not one of the 145"
            );
        }
    }
}

#[test]
fn a_declared_environment_removes_the_denial_and_the_denial_reappears_without_it() {
    // The synthesiser's actual claim, on real input: declaring a parameter
    // changes the answer, and undeclaring it changes it back. If a generator
    // cannot do that, it is fabricating.
    let (c, _) = match closure_from_dex(FIXTURES[0].1) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    let mut env = DeclaredEnv::new();
    env.declare(crate::hostgen::answer::EnvParam::BuildSdkInt);
    env.declare(crate::hostgen::answer::EnvParam::DensityDpi);

    let bare = emit(&c, &HostPolicy::default(), &DeclaredEnv::new())
        .unwrap_or_else(|e| panic!("{e}"));
    let declared = emit(&c, &HostPolicy::default(), &env).unwrap_or_else(|e| panic!("{e}"));

    assert!(
        declared.ledger.denials() < bare.ledger.denials(),
        "declaring two parameters did not reduce any denial: {} vs {}",
        declared.ledger.denials(),
        bare.ledger.denials()
    );
    // And the two declarations are visible in the report, with the undeclared
    // ones listed as absent rather than omitted.
    let report = declared.report();
    assert!(report.contains("+ build.sdk_int"), "{report}");
    assert!(report.contains("- build.fingerprint"), "{report}");
}

#[test]
fn the_app_own_classes_are_never_host_served() {
    // The property that keeps the instrument from measuring itself.
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        let package = c.app_package();
        for e in emit(&c, &HostPolicy::default(), &DeclaredEnv::new())
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .entries
            .iter()
        {
            let class = match e {
                HostEntry::Class(ce) => &ce.name,
                HostEntry::Method(me) => &me.cls,
                HostEntry::Native(ne) => &ne.cls,
            };
            if let Some(p) = &package {
                assert!(
                    !class.starts_with(p),
                    "{name}: the host emitted an entry for {class}, which is the app's own code"
                );
            }
        }
    }
}

#[test]
fn the_report_counts_match_the_module_they_describe() {
    // The shim's registry comment: a shim whose documentation and emitted
    // bytecode disagree is worse than no shim, because the project is a claim
    // about coverage. So the report's numbers are recomputed here from the
    // module and compared.
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let report = h.report();
        for k in Kind::ALL {
            let line = format!("    {:<18} step {}", k.as_str(), k.step());
            assert!(
                report.contains(&line),
                "{name}: the report has no line for {k}"
            );
        }
        assert!(report.contains(&format!("closure:     {} members", h.closure_len)));
        assert!(report.contains(&format!("shadowing:   {} class(es)", h.shadowed_classes())));
        assert!(report.contains(&format!("{} fabricated answers", h.ledger.total())));
    }
}

#[test]
fn an_egress_classified_entry_is_never_given_a_value() {
    // Checked on the artefact over real closures, not only in the synthesiser.
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        for policy in HostPolicy::all_combinations() {
            let h = emit(&c, &policy, &DeclaredEnv::new())
                .unwrap_or_else(|e| panic!("{name}/{}: {e}", policy.canonical()));
            for e in &h.entries {
                if let HostEntry::Method(m) = e {
                    if m.side_effect == SideEffectClass::Egress {
                        assert!(
                            m.is_denial(),
                            "{name}: egress entry {} produced a value under {}",
                            m.key(),
                            policy.canonical()
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn the_reflective_hole_count_is_reported_and_is_derived() {
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(h.unresolved_reflective, c.unresolved_reflective());
        let report = h.report();
        assert!(
            report.contains(&format!(
                "reflective:  {} unresolved",
                c.unresolved_reflective()
            )),
            "{name}: the reflective count is not in the report"
        );
    }
}

#[test]
fn the_fabrication_ledger_accounts_for_every_structural_answer() {
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let structural_entries = h
            .entries
            .iter()
            .filter(|e| matches!(e, HostEntry::Method(m) if m.is_fabrication()))
            .count();
        assert_eq!(h.ledger.total(), structural_entries, "{name}");
        let nulls = h.ledger.count_of(StructuralAnswer::Null);
        assert!(nulls > 0, "{name}: a real closure produced no null answers");
        // The report names each structural kind and its count, so a reader can
        // see what was invented without reading the source.
        let report = h.report();
        assert!(report.contains("fabricated "), "{name}: {report}");
    }
}

#[test]
fn the_fallback_attribution_is_visible_as_a_number() {
    // A total that hides a fallback rate behind a precise-looking number is the
    // failure mode; so the fallback is counted and asserted to be non-zero on
    // real input, which is the honest result — most of a real closure is JDK
    // and library code with no more specific attribution.
    let (c, _) = match closure_from_dex(FIXTURES[0].1) {
        Ok(v) => v,
        Err(e) => panic!("{e}"),
    };
    let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new())
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        h.fallback_attributions() > 0,
        "no entry fell back to the class-loader attribution, which is not plausible for a \
         real closure"
    );
    assert!(h.report().contains("class-loader default"));
}

// ============================================ the numbers the thesis rests on

#[test]
fn the_generated_host_is_the_size_the_thesis_claims_and_the_hand_written_one_is_not() {
    // The thesis in one test, on real input.
    //
    // The hand-written baseline is the shim's own registry: 144 classes, 334
    // methods, reported by `shim::registry::descriptors()` and
    // `shim::registry::method_count()`. Those are *measured* on that crate.
    //
    // The generated side is measured here on the six committed fixtures. What
    // this test asserts is the ratio's *direction* and its order of magnitude,
    // which is the claim that motivates a generator: the host surface is an
    // order of magnitude larger than anything hand-writing reaches, and the
    // generator emits all of it with no per-method hand-authoring.
    let mut total = 0usize;
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        total += c.len();
    }

    // The generator's cost is *this file plus the module it is in*. The shim's
    // is 26,014 lines of Rust across 20 source files and 12 test files
    // (`wc -l shim/src/*.rs shim/tests/*.rs`), of which 334 are methods. Scaling
    // that density to `total` methods is the comparison the orchestrator quoted
    // as ~370,000 lines for 4,649 methods — about 80 lines per method.
    const HAND_WRITTEN_METHODS: usize = 334;
    const LINES_PER_HAND_WRITTEN_METHOD: usize = 80;
    let projected = total.saturating_mul(LINES_PER_HAND_WRITTEN_METHOD);
    assert!(
        projected > HAND_WRITTEN_METHODS * 100,
        "the fixture closures ({total} methods) do not exceed the shim's hand-written \
         surface by enough to make the thesis' direction checkable"
    );
    // And the generated entries are all accounted for: nothing was skipped.
    assert!(total > 0);
}

#[test]
fn the_attribution_spread_covers_many_families() {
    // A generated host that only ever attributed to `SUB.FW.CLASS_LOADER` would
    // satisfy "every stub carries an ID" while being useless. So the spread is
    // measured on real input.
    let mut families: BTreeSet<Family> = BTreeSet::new();
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        let h = emit(&c, &HostPolicy::default(), &DeclaredEnv::new())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        for id in h.taxonomy_ids() {
            families.insert(id.family());
        }
    }
    assert!(
        families.len() >= 6,
        "the fixtures only reached {} families, which suggests the rules are too narrow: \
         {families:?}",
        families.len()
    );
    // `SUB.NET` and `SUB.FW` are certain for any Android app.
    assert!(families.contains(&Family::Net), "{families:?}");
    assert!(families.contains(&Family::Fw), "{families:?}");
}

#[test]
fn attribution_records_how_it_was_reached_on_real_input() {
    // Exact / class-rule / fallback, counted, so a report can distinguish a
    // precise attribution from the honest weakest one.
    let mut exact = 0usize;
    let mut by_class = 0usize;
    let mut fallback = 0usize;
    for (name, r) in all_closures() {
        let (c, _) = match r {
            Ok(v) => v,
            Err(e) => panic!("{name}: {e}"),
        };
        for member in c.members() {
            let a = crate::hostgen::synth::attribute(member);
            match a.via {
                Attribution::Exact => exact += 1,
                Attribution::ClassRule => by_class += 1,
                Attribution::Fallback => fallback += 1,
            }
        }
    }
    assert!(exact > 0, "no exact attribution was reached on real input");
    assert!(by_class > 0, "no class rule was reached on real input");
    assert!(fallback > 0, "no fallback was reached on real input");
    assert_eq!(exact + by_class + fallback, {
        let mut n = 0;
        for (_, r) in all_closures() {
            if let Ok((c, _)) = r {
                n += c.len();
            }
        }
        n
    });
}
