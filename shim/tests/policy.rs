//! The substrate-policy family: does the parameter actually do the work?
//!
//! # What this file is for
//!
//! The shim's author identified the flaw that would sink the project: the layer
//! observes a *different program*, and the difference is invisible in the
//! output. Everything downstream is a joint property of app and shim. The fix
//! is a **family** of substrates, each with a declared policy, plus a harness
//! that shows the dependency is measurable.
//!
//! So this file is not a unit-test file for a type. It is the evidence for a
//! design claim, and it is organised as the claim:
//!
//! | claim | tests |
//! |---|---|
//! | the policy is a real parameter, applied to every fabricated value | [`every_fabricated_value_is_produced_by_the_policy`] and the rest of the uniformity section |
//! | **no policy value can reach a real socket** | [`no_policy_value_can_reach_a_real_socket`], plus the `egress_denial` suite which now scans `src/policy.rs` |
//! | **no policy value can cause a redaction violation** | [`no_policy_value_can_capture_a_body_a_header_or_a_query_value`], [`the_policy_type_holds_no_field_that_could_carry_one`] |
//! | recordings round-trip the policy | [`a_recording_round_trips_its_policy`] and the byte-identity checks |
//! | the differential separates the substrate from the app | the whole differential section, and `differential::tests` in the library |

use std::collections::BTreeSet;

use shim::event::{Detail, Group, NetPresentation};
use shim::policy::{
    Axis, FactClass, IdentityMode, NetworkMode, PackageMode, SubstratePolicy, SystemFsMode,
    TimeMode,
};
use shim::ShimCaller;

fn shim_with(policy: SubstratePolicy) -> shim::Shim {
    shim::Shim::with_policy("org.substrate.policy.test", Vec::new(), policy).expect("shim")
}

fn shim() -> shim::Shim {
    shim_with(SubstratePolicy::default())
}

/// Every event's rendered summary, for whole-state assertions.
fn blob(s: &shim::Shim) -> String {
    s.events()
        .iter()
        .map(|e| e.summary())
        .collect::<Vec<_>>()
        .join("\n")
}

// =====================================================================
// 1. The policy is a parameter, and it is applied to every fabricated value
// =====================================================================

#[test]
fn the_default_is_the_pre_existing_behaviour_and_the_pre_existing_tests_mean_it() {
    // If the default were not the pre-existing substrate, every other test in
    // this suite would be testing a shim nobody has. So: the default must
    // reproduce the old answers exactly.
    let mut s = shim();
    assert_eq!(
        s.read_static("Landroid/os/Build;", "FINGERPRINT").unwrap(),
        shim::Value::Str("andro-substrate/shim/0.1.0:substrate/0.1.0:user/release-keys".into())
    );
    let b = s.read_path_public("/proc/self/status").expect("modelled");
    assert!(String::from_utf8_lossy(&b).contains("TracerPid:\t0"));
    let url = s
        .invoke(
            "Ljava/net/URL;",
            "<init>",
            "(Ljava/lang/String;)V",
            &[shim::Value::Str("https://x.invalid/a".into())],
        )
        .expect("URL");
    let conn = s
        .invoke(
            "Ljava/net/URL;",
            "openConnection",
            "()Ljava/net/URLConnection;",
            &[url],
        )
        .expect("openConnection");
    assert!(
        s.invoke("Ljava/net/URLConnection;", "connect", "()V", &[conn])
            .is_err(),
        "egress is denied under the default, as it always was"
    );
    assert_eq!(s.substrate_policy(), &SubstratePolicy::default());
}

#[test]
fn every_fabricated_value_is_produced_by_the_policy() {
    // The load-bearing uniformity claim. For each axis: read the answer under two
    // different values of that axis and nothing else, and require the answer to
    // differ. If a fabricated value were hard-coded, this fails.
    //
    // `identity`: the fabricated fingerprint versus the withheld one.
    {
        let mut a = shim_with(SubstratePolicy::default());
        let mut b = shim_with(
            SubstratePolicy::default()
                .with(Axis::Identity, "withheld")
                .unwrap(),
        );
        let fa = a.read_static("Landroid/os/Build;", "FINGERPRINT").unwrap();
        let fb = b.read_static("Landroid/os/Build;", "FINGERPRINT").unwrap();
        assert_ne!(fa, fb, "Build.FINGERPRINT is not policy-governed");
        assert_eq!(fb, shim::Value::Null);
        // And the *question* is recorded identically under both: the field name
        // is the app's, and the value is not.
        assert_eq!(a.events().len(), b.events().len());
        assert_eq!(
            a.events()[0].assumption,
            b.events()[0].assumption,
            "the taxonomy ID belongs to the question, not the answer"
        );
    }
    // `system_fs`: fabricated content versus an empty file versus ENOENT.
    {
        let modes = ["fabricated", "empty", "absent"];
        let answers: Vec<String> = modes
            .iter()
            .map(|m| {
                let mut s = shim_with(SubstratePolicy::default().with(Axis::SystemFs, m).unwrap());
                match s.read_path_public("/proc/self/status") {
                    Ok(b) => format!("ok:{}", b.len()),
                    Err(_) => "enoent".to_string(),
                }
            })
            .collect();
        assert_eq!(
            answers,
            vec!["ok:86", "ok:0", "enoent"],
            "three values, three distinct answers, and the middle one is a third answer \
             rather than a variant of the first"
        );
    }
    // `cross_app_packages`: null versus a PackageInfo versus a throw.
    {
        let mut outcomes: Vec<String> = Vec::new();
        for m in ["subject_only", "all_present", "error"] {
            let mut s = shim_with(
                SubstratePolicy::default()
                    .with(Axis::CrossAppPackages, m)
                    .unwrap(),
            );
            let pm = shim::Value::Ref("Landroid/content/pm/PackageManager;".into(), 1);
            let r = s.invoke(
                "Landroid/content/pm/PackageManager;",
                "getPackageInfo",
                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
                &[
                    pm,
                    shim::Value::Str("com.other.app".into()),
                    shim::Value::Int(0),
                ],
            );
            outcomes.push(match r {
                Ok(shim::Value::Null) => "null".to_string(),
                Ok(_) => "installed".to_string(),
                Err(_) => "threw".to_string(),
            });
        }
        assert_eq!(outcomes, vec!["null", "installed", "threw"]);
    }
    // `network`: a refusal versus a synthesised response.
    {
        let mut codes: Vec<String> = Vec::new();
        for m in ["record_and_deny", "synthetic_loopback"] {
            let mut s = shim_with(SubstratePolicy::default().with(Axis::Network, m).unwrap());
            let u = s
                .invoke(
                    "Ljava/net/URL;",
                    "<init>",
                    "(Ljava/lang/String;)V",
                    &[shim::Value::Str("https://x.invalid/a".into())],
                )
                .unwrap();
            let c = s
                .invoke(
                    "Ljava/net/URL;",
                    "openConnection",
                    "()Ljava/net/URLConnection;",
                    &[u],
                )
                .unwrap();
            let connected = s
                .invoke(
                    "Ljava/net/URLConnection;",
                    "connect",
                    "()V",
                    std::slice::from_ref(&c),
                )
                .is_ok();
            let code = s
                .invoke(
                    "Ljava/net/HttpURLConnection;",
                    "getResponseCode",
                    "()I",
                    &[c],
                )
                .ok()
                .map(|v| format!("{v:?}"))
                .unwrap_or_else(|| "threw".to_string());
            codes.push(format!("connect={connected} code={code}"));
        }
        assert_eq!(
            codes,
            vec!["connect=false code=threw", "connect=true code=Int(200)"]
        );
    }
    // `time`: virtual, scaled, frozen and host.
    {
        let mut reads: Vec<String> = Vec::new();
        for t in [
            TimeMode::Virtual,
            TimeMode::Scaled {
                numerator: 3,
                denominator: 1,
            },
            TimeMode::Frozen,
        ] {
            let mut s = shim_with(SubstratePolicy {
                time: t,
                ..SubstratePolicy::default()
            });
            s.clock_mut().advance(100);
            let r = s
                .invoke("Landroid/os/SystemClock;", "elapsedRealtime", "()J", &[])
                .unwrap();
            let w = s
                .invoke("Ljava/lang/System;", "currentTimeMillis", "()J", &[])
                .unwrap();
            reads.push(format!("{r:?}/{w:?}"));
        }
        assert_eq!(
            reads,
            vec!["Long(100)/Long(0)", "Long(300)/Long(0)", "Long(0)/Long(0)"],
            "a scaled clock scales elapsed and not wall, and a frozen clock freezes both"
        );
    }
}

#[test]
fn every_fabricated_value_says_which_axis_answered_it() {
    // Emission-time attribution. One shim, one run, one of each answer type, and
    // every fabricated probe must name its axis.
    let mut s = shim();
    s.clock_mut().advance(7);
    let _ = s.read_static("Landroid/os/Build;", "FINGERPRINT");
    let _ = s.read_path_public("/proc/self/status");
    let _ = s.read_path_public("/proc/self/exe");
    let _ = s.invoke(
        "Ljava/lang/System;",
        "getProperty",
        "(Ljava/lang/String;)Ljava/lang/String;",
        &[shim::Value::Str("ro.kernel.qemu".into())],
    );
    let _ = s.invoke("Landroid/os/SystemClock;", "elapsedRealtime", "()J", &[]);
    let pm = shim::Value::Ref("Landroid/content/pm/PackageManager;".into(), 1);
    let _ = s.invoke(
        "Landroid/content/pm/PackageManager;",
        "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        &[
            pm,
            shim::Value::Str("com.other.app".into()),
            shim::Value::Int(0),
        ],
    );

    let labelled: BTreeSet<Axis> = s
        .events()
        .iter()
        .filter_map(|e| match &e.detail {
            Detail::Probes { axis, .. } => *axis,
            _ => None,
        })
        .collect();
    assert_eq!(
        labelled,
        BTreeSet::from([
            Axis::Identity,
            Axis::SystemFs,
            Axis::CrossAppPackages,
            Axis::Time
        ]),
        "every axis that answered a question in this run is named in that answer's own event: \
         {labelled:?}"
    );
    // And the network axis, once a request exists.
    let mut s2 = shim_with(
        SubstratePolicy::default()
            .with(Axis::Network, "synthetic_loopback")
            .unwrap(),
    );
    let u = s2
        .invoke(
            "Ljava/net/URL;",
            "<init>",
            "(Ljava/lang/String;)V",
            &[shim::Value::Str("https://x.invalid/a".into())],
        )
        .unwrap();
    let c = s2
        .invoke(
            "Ljava/net/URL;",
            "openConnection",
            "()Ljava/net/URLConnection;",
            &[u],
        )
        .unwrap();
    let _ = s2.invoke("Ljava/net/URLConnection;", "connect", "()V", &[c]);
    assert!(blob(&s2).contains("substrate_policy axis network"));
    // And a self-query is labelled by nobody, because no axis may reach it.
    let mut s3 = shim_with(
        SubstratePolicy::default()
            .with(Axis::CrossAppPackages, "all_present")
            .unwrap(),
    );
    let _ = s3.invoke(
        "Landroid/content/pm/PackageManager;",
        "getPackageInfo",
        "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;",
        &[
            shim::Value::Ref("Landroid/content/pm/PackageManager;".into(), 1),
            shim::Value::Str("org.substrate.policy.test".into()),
            shim::Value::Int(0),
        ],
    );
    let pm_probes: Vec<&shim::SubstrateEvent> = s3
        .events()
        .iter()
        .filter(|e| matches!(&e.detail, Detail::Probes { .. }))
        .collect();
    for p in &pm_probes {
        let Detail::Probes { axis, .. } = &p.detail else {
            unreachable!()
        };
        assert_eq!(*axis, None, "a self-query is not a cross-app query: {p:?}");
    }
}

#[test]
fn the_refusing_identity_arm_fails_through_the_ordinary_classloader() {
    // Not a special case in a shim method: the class is simply gone from the
    // table, so the failure an app sees is the same `NoClassDefFoundError` its
    // own dex would produce for a missing framework class.
    let mut s = shim_with(
        SubstratePolicy::default()
            .with(Axis::Identity, "refusing")
            .unwrap(),
    );
    let r = s.read_static("Landroid/os/Build;", "FINGERPRINT");
    assert!(r.is_err(), "the read must fail, not return a value");
    // The probe is still recorded: which field the app went for is the
    // measurement, and it does not depend on getting an answer.
    let probes: Vec<String> = s
        .events()
        .iter()
        .filter(|e| e.group == Group::Probes)
        .map(|e| e.summary())
        .collect();
    assert!(
        probes.iter().any(|p| p.contains("Build.FINGERPRINT")),
        "{probes:?}"
    );
    assert!(
        s.events()
            .iter()
            .any(|e| e.group == Group::Exceptions && e.summary().contains("NoClassDefFoundError")),
        "the failure is a recorded exception: {}",
        blob(&s)
    );
    // And the loader agrees, which is the point: the same answer comes from the
    // classloader, not from a policy check.
    assert_eq!(
        s.loader().resolve("Landroid/os/Build;").0,
        shim::Resolution::Unresolvable
    );
    // Under every other arm the class resolves.
    for m in ["fabricated", "withheld"] {
        let s2 = shim_with(SubstratePolicy::default().with(Axis::Identity, m).unwrap());
        assert!(
            s2.loader()
                .resolve("Landroid/os/Build;")
                .0
                .is_served_by_shim(),
            "{m} must still serve the class"
        );
    }
}

#[test]
fn the_empty_system_fs_arm_is_a_third_answer_and_not_a_variant_of_the_first() {
    // `exists()` then `read()` is the decision an app makes, and it is a
    // different decision under `empty` and under `absent`.
    let mut s = shim_with(
        SubstratePolicy::default()
            .with(Axis::SystemFs, "empty")
            .unwrap(),
    );
    let bytes = s
        .read_path_public("/proc/self/status")
        .expect("the path exists");
    assert!(bytes.is_empty());
    let fs: Vec<&shim::SubstrateEvent> =
        s.events().iter().filter(|e| e.group == Group::Fs).collect();
    assert!(fs[0].summary().contains("-> ok"), "{}", fs[0].summary());

    let mut s = shim_with(
        SubstratePolicy::default()
            .with(Axis::SystemFs, "absent")
            .unwrap(),
    );
    assert!(s.read_path_public("/proc/self/status").is_err());
    let fs: Vec<&shim::SubstrateEvent> =
        s.events().iter().filter(|e| e.group == Group::Fs).collect();
    assert!(fs[0].summary().contains("enoent"), "{}", fs[0].summary());
    // And the loud arm says *why* in a probe, not only in a syscall result.
    assert!(
        blob(&s).contains("substrate_policy axis system_fs = absent"),
        "{}",
        blob(&s)
    );
}

#[test]
fn a_host_clock_policy_declares_that_it_is_not_reproducible() {
    let p = SubstratePolicy {
        time: TimeMode::HostReal,
        ..SubstratePolicy::default()
    };
    let j = p.to_json();
    assert_eq!(j["reproducible"], serde_json::json!(false));
    assert!(
        j.to_string().contains("NOT REPRODUCIBLE"),
        "the declaration must say it in words, not only in a boolean: {j}"
    );
    // And a reproducible policy says so too, so the field is not a formality.
    assert_eq!(
        SubstratePolicy::default().to_json()["reproducible"],
        serde_json::json!(true)
    );
}

#[test]
fn an_axis_whose_value_did_not_change_has_no_observable_effect() {
    // The converse of attribution, and the check that keeps `governs` honest: if
    // a declaration claims an axis governs a class, then changing that axis must
    // move something in that class. Otherwise the declaration is decoration.
    for a in Axis::all() {
        // Change the axis under test and nothing else, so "moved something in a
        // governed class" is a statement about that axis alone.
        let (changed, other) = match a {
            Axis::Identity => (
                "refusing",
                SubstratePolicy::default()
                    .with(Axis::Identity, "refusing")
                    .unwrap(),
            ),
            Axis::SystemFs => (
                "absent",
                SubstratePolicy::default()
                    .with(Axis::SystemFs, "absent")
                    .unwrap(),
            ),
            Axis::CrossAppPackages => (
                "error",
                SubstratePolicy::default()
                    .with(Axis::CrossAppPackages, "error")
                    .unwrap(),
            ),
            Axis::Network => (
                "synthetic_loopback",
                SubstratePolicy::default()
                    .with(Axis::Network, "synthetic_loopback")
                    .unwrap(),
            ),
            Axis::Time => (
                "frozen",
                SubstratePolicy::default()
                    .with(Axis::Time, "frozen")
                    .unwrap(),
            ),
        };
        assert_ne!(
            SubstratePolicy::default().axis(a),
            other.axis(a),
            "{changed}"
        );
        let d = shim::differential::run(SubstratePolicy::default(), other).expect("differential");
        let moved_in_governed = a.governs().iter().any(|c| !d.moved_in(*c).is_empty());
        assert!(
            moved_in_governed,
            "axis {} claims it governs {:?} but moving it moved nothing in those classes",
            a.as_str(),
            a.governs()
        );
    }
}

// =====================================================================
// 2. Egress stays structurally impossible
// =====================================================================

#[test]
fn no_policy_value_can_reach_a_real_socket() {
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    // A real listener on loopback. Nothing in the shim knows it exists; that is
    // the point — the denial is not a policy about *this* address, and no axis
    // value can widen it.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("non-blocking");
    let connected = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&connected);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let watchdog = std::thread::spawn(move || {
        while !stop_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut s, _)) => {
                    flag.store(true, Ordering::Relaxed);
                    let _ = s.write_all(b"");
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(_) => break,
            }
        }
    });

    // EVERY axis value of EVERY axis, on both the most and the least plausible
    // arm, driven through every network surface the shim has.
    let mut policies: Vec<SubstratePolicy> = Vec::new();
    for identity in [
        IdentityMode::Fabricated,
        IdentityMode::Withheld,
        IdentityMode::Refusing,
    ] {
        for system_fs in [
            SystemFsMode::Fabricated,
            SystemFsMode::Empty,
            SystemFsMode::Absent,
        ] {
            for packages in [
                PackageMode::SubjectOnly,
                PackageMode::AllPresent,
                PackageMode::Error,
            ] {
                for network in [NetworkMode::RecordAndDeny, NetworkMode::SyntheticLoopback] {
                    for time in [
                        TimeMode::Virtual,
                        TimeMode::Scaled {
                            numerator: 2,
                            denominator: 1,
                        },
                        TimeMode::Frozen,
                    ] {
                        policies.push(SubstratePolicy {
                            identity,
                            system_fs,
                            cross_app_packages: packages,
                            network,
                            time,
                        });
                    }
                }
            }
        }
    }
    assert_eq!(
        policies.len(),
        3 * 3 * 3 * 2 * 3,
        "the axis vocabulary changed"
    );
    for p in &policies {
        let mut s = shim_with(*p);
        let url = format!("http://127.0.0.1:{port}/collect?k=v");
        let u = s
            .invoke(
                "Ljava/net/URL;",
                "<init>",
                "(Ljava/lang/String;)V",
                &[shim::Value::Str(url.clone())],
            )
            .expect("URL");
        let c = s
            .invoke(
                "Ljava/net/URL;",
                "openConnection",
                "()Ljava/net/URLConnection;",
                &[u],
            )
            .expect("openConnection");
        let _ = s.invoke(
            "Ljava/net/HttpURLConnection;",
            "setRequestMethod",
            "(Ljava/lang/String;)V",
            &[c.clone(), shim::Value::Str("POST".into())],
        );
        let _ = s.invoke(
            "Ljava/net/URLConnection;",
            "setConnectTimeout",
            "(I)V",
            &[c.clone(), shim::Value::Int(1)],
        );
        // A body, so a body length exists to be counted.
        let out = s.invoke(
            "Ljava/net/HttpURLConnection;",
            "getOutputStream",
            "()Ljava/io/OutputStream;",
            std::slice::from_ref(&c),
        );
        if let Ok(sink) = out {
            let _ = s.invoke(
                "Ljava/io/OutputStream;",
                "write",
                "([BII)V",
                &[
                    sink,
                    shim::Value::Bytes(vec![0u8; 64]),
                    shim::Value::Int(0),
                    shim::Value::Int(64),
                ],
            );
        }
        let _ = s.invoke(
            "Ljava/net/URLConnection;",
            "connect",
            "()V",
            std::slice::from_ref(&c),
        );
        let _ = s.invoke(
            "Ljava/net/HttpURLConnection;",
            "getResponseCode",
            "()I",
            std::slice::from_ref(&c),
        );
        let _ = s.invoke(
            "Ljava/net/HttpURLConnection;",
            "getInputStream",
            "()Ljava/io/InputStream;",
            std::slice::from_ref(&c),
        );
        // A raw Socket, which is the other way in.
        let _ = s.invoke(
            "Ljava/net/Socket;",
            "connect",
            "(Ljava/net/SocketAddress;I)V",
            &[
                shim::Value::Ref("Ljava/net/Socket;".into(), 1),
                shim::Value::Null,
                shim::Value::Int(1),
            ],
        );
        // A WebView, which is a request wearing a different hat.
        let _ = s.invoke(
            "Landroid/webkit/WebView;",
            "loadUrl",
            "(Ljava/lang/String;)V",
            &[
                shim::Value::Ref("Landroid/webkit/WebView;".into(), 1),
                shim::Value::Str(url),
            ],
        );

        // And the assertion that matters: the SINK refused, under this policy, on
        // every net event — including the loopback arm, which is the whole risk.
        for e in s.events() {
            if let Detail::Net {
                outcome,
                presentation,
                ..
            } = &e.detail
            {
                assert!(
                    outcome.is_err(),
                    "policy {} produced a net event whose sink outcome was Ok",
                    p.axis(Axis::Identity)
                );
                let _ = presentation;
            }
        }
    }

    std::thread::sleep(Duration::from_millis(150));
    stop.store(true, Ordering::Relaxed);
    let _ = watchdog.join();
    assert!(
        !connected.load(Ordering::Relaxed),
        "some substrate policy value opened a TCP connection to a live listener: egress denial \
         is no longer structural"
    );
}

#[test]
fn the_loopback_arm_refuses_at_the_sink_and_only_presents() {
    // The distinction the whole network axis rests on, asserted directly: the
    // refusal and the presentation are two fields and the refusal does not move.
    for p in [
        SubstratePolicy::default(),
        SubstratePolicy::default()
            .with(Axis::Network, "synthetic_loopback")
            .unwrap(),
    ] {
        let mut s = shim_with(p);
        let u = s
            .invoke(
                "Ljava/net/URL;",
                "<init>",
                "(Ljava/lang/String;)V",
                &[shim::Value::Str("https://x.invalid/a".into())],
            )
            .unwrap();
        let c = s
            .invoke(
                "Ljava/net/URL;",
                "openConnection",
                "()Ljava/net/URLConnection;",
                &[u],
            )
            .unwrap();
        let _ = s.invoke(
            "Ljava/net/URLConnection;",
            "connect",
            "()V",
            std::slice::from_ref(&c),
        );
        let net: Vec<&shim::SubstrateEvent> = s
            .events()
            .iter()
            .filter(|e| e.group == Group::Net)
            .collect();
        assert_eq!(net.len(), 1, "the attempt is recorded exactly once");
        let Detail::Net {
            outcome,
            presentation,
            ..
        } = &net[0].detail
        else {
            panic!()
        };
        assert!(outcome.is_err(), "the sink refused under {}", p.digest());
        match presentation {
            NetPresentation::Denied => assert_eq!(p.network, NetworkMode::RecordAndDeny),
            NetPresentation::Loopback(r) => {
                assert_eq!(p.network, NetworkMode::SyntheticLoopback);
                assert_eq!(r.status, 200);
                assert_eq!(r.declared_body_bytes, 0, "no body is ever fabricated");
            }
        }
    }
}

// =====================================================================
// 3. Redaction stays in the types
// =====================================================================

#[test]
fn no_policy_value_can_capture_a_body_a_header_or_a_query_value() {
    // The strongest form of the invariant available before a code change: run
    // every axis value, with canaries in the three places the redaction layer
    // exists for, and require the canaries to survive nowhere — not in the event
    // stream, not in the shim's state, and not in the serialised document.
    const BODY: &str = "policy-canary-body-9f3a-do-not-record";
    const HEADER: &str = "policy-canary-bearer-4b7e-do-not-record";
    const QUERY: &str = "policy-canary-sig-1c2d-do-not-record";

    let mut ran = 0usize;
    for identity in [
        IdentityMode::Fabricated,
        IdentityMode::Withheld,
        IdentityMode::Refusing,
    ] {
        for system_fs in [
            SystemFsMode::Fabricated,
            SystemFsMode::Empty,
            SystemFsMode::Absent,
        ] {
            for packages in [
                PackageMode::SubjectOnly,
                PackageMode::AllPresent,
                PackageMode::Error,
            ] {
                for network in [NetworkMode::RecordAndDeny, NetworkMode::SyntheticLoopback] {
                    for time in [TimeMode::Virtual, TimeMode::Frozen] {
                        let p = SubstratePolicy {
                            identity,
                            system_fs,
                            cross_app_packages: packages,
                            network,
                            time,
                        };
                        let mut s = shim_with(p);
                        let url = format!(
                            "https://api.substrate.invalid/v1/sync?token={QUERY}&sig={QUERY}#f"
                        );
                        let u = s
                            .invoke(
                                "Ljava/net/URL;",
                                "<init>",
                                "(Ljava/lang/String;)V",
                                &[shim::Value::Str(url)],
                            )
                            .expect("URL");
                        let c = s
                            .invoke(
                                "Ljava/net/URL;",
                                "openConnection",
                                "()Ljava/net/URLConnection;",
                                &[u],
                            )
                            .expect("openConnection");
                        for (name, value) in [
                            ("Authorization", format!("Bearer {HEADER}")),
                            ("X-Api-Key", format!("key-{HEADER}")),
                        ] {
                            let _ = s.invoke(
                                "Ljava/net/URLConnection;",
                                "setRequestProperty",
                                "(Ljava/lang/String;Ljava/lang/String;)V",
                                &[
                                    c.clone(),
                                    shim::Value::Str(name.into()),
                                    shim::Value::Str(value),
                                ],
                            );
                        }
                        if let Ok(sink) = s.invoke(
                            "Ljava/net/HttpURLConnection;",
                            "getOutputStream",
                            "()Ljava/io/OutputStream;",
                            std::slice::from_ref(&c),
                        ) {
                            let _ = s.invoke(
                                "Ljava/io/OutputStream;",
                                "write",
                                "([BII)V",
                                &[
                                    sink,
                                    shim::Value::Bytes(BODY.as_bytes().to_vec()),
                                    shim::Value::Int(0),
                                    shim::Value::Int(BODY.len() as i32),
                                ],
                            );
                        }
                        let _ = s.invoke(
                            "Ljava/net/URLConnection;",
                            "connect",
                            "()V",
                            std::slice::from_ref(&c),
                        );
                        let _ = s.invoke(
                            "Ljava/net/HttpURLConnection;",
                            "getResponseCode",
                            "()I",
                            std::slice::from_ref(&c),
                        );
                        ran += 1;

                        // The event stream.
                        let events = format!("{:?}", s.events());
                        for canary in [BODY, HEADER, QUERY] {
                            assert!(
                                !events.contains(canary),
                                "{canary:?} survived into the events under policy {}",
                                p.digest()
                            );
                        }
                        // The names DO survive, because they are the finding.
                        assert!(events.contains("X-Api-Key"));
                        assert!(events.contains("token"));

                        // And the document, which is the artefact.
                        let facts = shim::recording::CaptureFacts::fixture_with(p);
                        let doc = shim::recording::build(
                            &facts,
                            s.events(),
                            &shim::recording::Extras::default(),
                        )
                        .expect("build");
                        let rendered = serde_json::to_string(&doc).expect("serialise");
                        for canary in [BODY, HEADER, QUERY] {
                            assert!(
                                !rendered.contains(canary),
                                "{canary:?} survived into a recording under policy {}",
                                p.digest()
                            );
                        }
                        assert!(shim::redact::scrub(&rendered, &[BODY, HEADER, QUERY]).is_ok());
                    }
                }
            }
        }
    }
    assert_eq!(ran, 3 * 3 * 3 * 2 * 2, "the axis vocabulary changed");
}

#[test]
fn the_policy_type_holds_no_field_that_could_carry_one() {
    // A structural check, so the invariant is not "nobody has written the code
    // yet". If a `Vec<String>`, a `String` on a response, or anything else that
    // could hold a byte of a body or a header value appears on the policy type,
    // this fails and the author has to decide, deliberately, to weaken it.
    let src = include_str!("../src/policy.rs");

    // The type's own field list.
    let body = src
        .split("pub struct SubstratePolicy {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("the SubstratePolicy body");
    let fields: Vec<&str> = body
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| l.split(':').next())
        .collect();
    assert_eq!(
        fields,
        vec![
            "identity",
            "system_fs",
            "cross_app_packages",
            "network",
            "time"
        ],
        "SubstratePolicy's field set is the redaction invariant as far as the policy is \
         concerned: five enums, none of which can hold a byte of anything"
    );

    // And the response type, which is the only type a policy can hand an app
    // beyond a value: a status, a length and a content type, and no bytes.
    let body = src
        .split("pub struct LoopbackResponse {")
        .nth(1)
        .and_then(|s| s.split('}').next())
        .expect("the LoopbackResponse body");
    let fields: Vec<&str> = body
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| l.split(':').next())
        .collect();
    assert_eq!(
        fields,
        vec!["status", "declared_body_bytes", "content_type"],
        "a synthesised response is a status, a LENGTH and a content type. A `String` here \
         would be a body the shim invented and an interpreter could record."
    );

    // No axis value can be built from a string the app supplied. This is the
    // sharpest available form: every `SubstratePolicy::set` takes a `&str` that
    // is matched against a closed list and rejected otherwise, so there is no
    // path by which a URL, a header or a body could become a policy value.
    for axis in Axis::all() {
        for hostile in [
            "Bearer secret",
            "https://evil.invalid",
            "token=abc",
            "",
            "record_and_deny; allow",
        ] {
            let mut p = SubstratePolicy::default();
            assert!(
                p.set(axis, hostile).is_err(),
                "axis {} accepted {hostile:?} as a value",
                axis.as_str()
            );
        }
    }
}

// =====================================================================
// 4. The recording carries the policy, and round-trips it
// =====================================================================

#[test]
fn a_recording_round_trips_its_policy() {
    // Every arm, serialised into a document, read back out of the document, and
    // checked against the original — including the digest, which is recomputed
    // rather than trusted.
    for p in [
        SubstratePolicy::default(),
        SubstratePolicy::default()
            .with(Axis::Identity, "withheld")
            .unwrap(),
        SubstratePolicy::default()
            .with(Axis::Identity, "refusing")
            .unwrap(),
        SubstratePolicy::default()
            .with(Axis::SystemFs, "empty")
            .unwrap(),
        SubstratePolicy::default()
            .with(Axis::SystemFs, "absent")
            .unwrap(),
        SubstratePolicy::default()
            .with(Axis::CrossAppPackages, "all_present")
            .unwrap(),
        SubstratePolicy::default()
            .with(Axis::CrossAppPackages, "error")
            .unwrap(),
        SubstratePolicy::default()
            .with(Axis::Network, "synthetic_loopback")
            .unwrap(),
        SubstratePolicy {
            time: TimeMode::Scaled {
                numerator: 7,
                denominator: 3,
            },
            ..SubstratePolicy::default()
        },
        SubstratePolicy {
            time: TimeMode::Frozen,
            ..SubstratePolicy::default()
        },
    ] {
        let out = shim::scenario::run_with(p).expect("run");
        let block = out
            .document
            .get("substrate_policy")
            .expect("every substrate recording carries its declaration");
        let back = SubstratePolicy::from_json(block).expect("read back");
        assert_eq!(back, p, "round trip");
        assert_eq!(back.digest(), p.digest());
        // And the recorder options carry the same pointer, so a reader who reads
        // only `recorder.options` still learns which substrate ran.
        assert_eq!(
            out.document["recorder"]["options"]["substrate_policy"],
            serde_json::json!(p.digest())
        );
        // And every declared axis has a declaration entry with a `governs` list.
        let decls = block["axis_declarations"].as_array().expect("declarations");
        assert_eq!(decls.len(), Axis::all().len());
        for (d, a) in decls.iter().zip(Axis::all()) {
            assert_eq!(d["axis"], serde_json::json!(a.as_str()));
            assert_eq!(d["value"], serde_json::json!(p.axis(a)));
            assert!(!d["governs"].as_array().expect("governs").is_empty());
            assert!(!d["statement"].as_str().unwrap_or_default().is_empty());
        }
    }
}

#[test]
fn a_document_with_no_declaration_cannot_be_attributed_and_says_so() {
    // The negative half of the affordance: the diff refuses a document that does
    // not declare its substrate, rather than silently attributing nothing.
    let doc = shim::scenario::run_with(SubstratePolicy::default())
        .expect("run")
        .document;
    let mut stripped = doc.as_object().expect("object").clone();
    stripped.remove("substrate_policy");
    let e = shim::differential::diff(&serde_json::Value::Object(stripped), &doc)
        .expect_err("must refuse");
    assert!(format!("{e}").contains("substrate_policy"), "{e}");
}

#[test]
fn a_tampered_declaration_is_refused_rather_than_run() {
    let doc = shim::scenario::run_with(SubstratePolicy::default())
        .expect("run")
        .document;
    let mut tampered = doc.as_object().expect("object").clone();
    let mut block = tampered["substrate_policy"]
        .as_object()
        .expect("block")
        .clone();
    block.insert("network".into(), serde_json::json!("synthetic_loopback"));
    tampered.insert("substrate_policy".into(), serde_json::Value::Object(block));
    let e = shim::differential::diff(&serde_json::Value::Object(tampered), &doc)
        .expect_err("a digest that does not describe the content must be refused");
    assert!(format!("{e}").contains("digest"), "{e}");
}

#[test]
fn the_environment_block_is_derived_from_the_policy_and_never_asserted() {
    // A document whose `environment` is a hard-coded constant while the
    // `substrate_policy` beside it says `withheld` is a document that lies to
    // anyone who diffs the two. The schema has no way to catch that; this does.
    for (identity, expect_value) in [
        (IdentityMode::Fabricated, "Substrate"),
        (IdentityMode::Withheld, ""),
    ] {
        let p = SubstratePolicy {
            identity,
            ..SubstratePolicy::default()
        };
        let out = shim::scenario::run_with(p).expect("run");
        let env = &out.document["environment"];
        assert_eq!(
            env["model"],
            serde_json::json!(expect_value),
            "identity {identity:?} and the environment disagree"
        );
        assert_eq!(
            env["sdk_int"],
            serde_json::json!(if identity == IdentityMode::Withheld {
                1
            } else {
                34
            }),
            "the schema's `minimum: 1` floor is reported and named in notes"
        );
    }
    // The floor is named, not left to be discovered.
    let withheld = shim::scenario::run_with(
        SubstratePolicy::default()
            .with(Axis::Identity, "withheld")
            .unwrap(),
    )
    .expect("run");
    let n = withheld.document["notes"].as_str().unwrap_or_default();
    assert!(n.contains(&withheld.substrate_policy.digest()));
}

#[test]
fn the_committed_recordings_carry_their_declarations_and_the_differential_is_current() {
    // Byte-identity, for all three committed artefacts. The same arrangement as
    // `synthetic.recording.json`: regeneration is checked, not asserted.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_shim-differential"))
        .output()
        .expect("run shim-differential");
    assert!(out.status.success(), "shim-differential failed");
    let text = String::from_utf8(out.stdout).expect("utf-8");

    let mut arms: Vec<String> = Vec::new();
    let mut report = String::new();
    let mut current: Option<&str> = None;
    for line in text.lines() {
        if line.starts_with("==== ") && line.ends_with(" ====") {
            if line == "==== report ====" {
                current = Some("");
                continue;
            }
            current = Some(line);
            arms.push(String::new());
            continue;
        }
        if line == "==== report ====" {
            current = Some("");
            continue;
        }
        let Some(i) = arms.len().checked_sub(1) else {
            continue;
        };
        if current == Some("") {
            report.push_str(line);
            report.push('\n');
        } else {
            arms[i].push_str(line);
            arms[i].push('\n');
        }
    }
    assert_eq!(arms.len(), 2, "two arms");
    assert_eq!(
        arms[0].trim_end(),
        include_str!("../recordings/differential-left.fabricated.recording.json").trim_end(),
        "shim/recordings/differential-left.fabricated.recording.json is stale; regenerate with the \
         command in shim/recordings/README.md"
    );
    assert_eq!(
        arms[1].trim_end(),
        include_str!("../recordings/differential-right.loud.recording.json").trim_end(),
        "shim/recordings/differential-right.loud.recording.json is stale"
    );
    assert_eq!(
        report.trim_end(),
        include_str!("../recordings/differential.report.txt").trim_end(),
        "shim/recordings/differential.report.txt is stale"
    );

    // And the report's headline numbers, so a report that says "0 unattributed"
    // while the harness disagrees cannot be committed.
    assert!(report.contains("(none) Every difference is explained by the policy"));
    assert!(report.contains("app                      moved 0"));
    assert!(
        !report.contains("  app                      moved 1"),
        "an app-class fact moved; the report is stale or the shim regressed"
    );
}

#[test]
fn the_apps_own_exceptions_are_the_same_and_the_substrates_are_not() {
    // The sharpest single fact in the differential, asserted rather than
    // described. Both arms run the same script; the exceptions the SCRIPT provokes
    // are identical, and every exception that differs is one the substrate chose
    // to throw. An app whose `catch` blocks ran in one arm and not the other has
    // a behavioural difference that neither document can attribute.
    let (l, r) = shim::differential::two_arms(
        SubstratePolicy::default(),
        SubstratePolicy {
            identity: IdentityMode::Withheld,
            system_fs: SystemFsMode::Absent,
            cross_app_packages: PackageMode::Error,
            network: NetworkMode::SyntheticLoopback,
            time: TimeMode::Frozen,
        },
    )
    .expect("two arms");
    let classes = |d: &serde_json::Value| -> Vec<String> {
        d["exceptions"]
            .as_array()
            .expect("exceptions")
            .iter()
            .map(|e| e["class"].as_str().unwrap_or_default().to_string())
            .collect()
    };
    let lc = classes(&l.document);
    let rc = classes(&r.document);
    // The app's own: from `Class.forName` and from `loadLibrary`/`load`.
    for c in [
        "java.lang.ClassNotFoundException",
        "java.lang.UnsatisfiedLinkError",
    ] {
        assert_eq!(
            lc.iter().filter(|x| *x == c).count(),
            rc.iter().filter(|x| *x == c).count(),
            "{c} is the app's own exception and must not depend on the substrate"
        );
        assert!(lc.contains(&c.to_string()), "{lc:?}");
    }
    // The substrate's: the network refusals vanish under the loopback arm and the
    // package refusals appear under the error arm.
    assert!(
        lc.iter().any(|c| c == "java.net.ConnectException"),
        "{lc:?}"
    );
    assert!(!rc.iter().any(|c| c.starts_with("java.net.")), "{rc:?}");
    assert!(
        rc.iter()
            .any(|c| c == "android.content.pm.NameNotFoundException"),
        "{rc:?}"
    );
    assert!(!lc.iter().any(|c| c.contains("pm.NameNotFound")), "{lc:?}");
}

#[test]
fn the_refusals_that_must_not_move_did_not_move() {
    // Under `synthetic_loopback` the app is shown a 200. These five facts are the
    // evidence that the policy changed a presentation and not a capability, and
    // they are asserted on the committed pair rather than on a fresh run.
    let r = shim::differential::committed_policies().1;
    assert_eq!(r.network, NetworkMode::SyntheticLoopback);
    let doc = shim::scenario::run_with(r).expect("run").document;
    assert_eq!(
        doc["environment"]["network"]["egress_available"],
        serde_json::json!(false)
    );
    assert_eq!(
        doc["network"]["byte_totals_observed"]["tx_bytes"],
        serde_json::json!(0)
    );
    assert_eq!(
        doc["network"]["byte_totals_observed"]["rx_bytes"],
        serde_json::json!(0)
    );
    let attempts = doc["network"]["attempts"].as_array().expect("attempts");
    assert!(!attempts.is_empty(), "the attempts are still recorded");
    for a in attempts {
        assert_eq!(
            a["result"],
            serde_json::json!("blocked_by_policy"),
            "the sink refused even though the app was shown a response: {a}"
        );
    }
    // And at least one status_code is present, which is the whole point of the
    // arm: the document does contain a fabricated status, and it is labelled.
    assert!(
        attempts.iter().any(|a| a["status_code"].is_number()
            && a["notes"]
                .as_str()
                .unwrap_or_default()
                .contains("PRESENTATION")),
        "a status_code must never appear without saying it was synthesised"
    );
}

#[test]
fn every_fact_class_an_axis_governs_is_a_class_the_diff_can_actually_produce() {
    // The declaration and the classifier must agree, and a test is the only
    // thing that notices when one gains a class the other does not.
    let doc = shim::scenario::run_with(SubstratePolicy::default())
        .expect("run")
        .document;
    // Exercise the classifier over every pointer in a real recording.
    let mut pointers: Vec<String> = Vec::new();
    collect_pointers(&doc, "", &mut pointers);
    assert!(pointers.len() > 400, "only {} pointers", pointers.len());
    for p in &pointers {
        let c = shim::differential::classify(p, None, None);
        assert!(
            FactClass::all().contains(&c),
            "{p} classified to something outside FactClass::all()"
        );
    }
    // And every governed class is reachable by at least one pattern token, so a
    // governed class is not a class nothing can ever be.
    for a in Axis::all() {
        for c in a.governs() {
            assert_ne!(
                *c,
                FactClass::App,
                "{} governs the app class, which would make every app fact a substrate fact",
                a.as_str()
            );
            assert_ne!(*c, FactClass::PolicyDeclaration);
        }
    }
}

fn collect_pointers(v: &serde_json::Value, at: &str, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, child) in m {
                let p = format!("{at}/{k}");
                out.push(p.clone());
                collect_pointers(child, &p, out);
            }
        }
        serde_json::Value::Array(a) => {
            for (i, child) in a.iter().enumerate() {
                let p = format!("{at}/#{i}");
                out.push(p.clone());
                collect_pointers(child, &p, out);
            }
        }
        _ => {}
    }
}
