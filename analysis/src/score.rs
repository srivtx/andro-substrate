//! The predicted-substrate-dependency rubric.
//!
//! # Read this before using the number
//!
//! **The weights below are a judgement call and are not validated.** They are
//! an ordered opinion about which substrate dependencies hurt most, written
//! down before any app was analysed, and they encode no measurement. The whole
//! point of reporting the components alongside the total is that a reader who
//! disagrees can re-weight one row without discarding the rest.
//!
//! Three structural choices, all arguable:
//!
//! 1. **Hard walls are gates, not weights.** An app that ships a `.so` is not
//!    "mostly incompatible"; it is out of scope for a bytecode-only substrate,
//!    exactly as `corpus/report.md` §"What this licenses the project to claim"
//!    already argues. Mixing that fact into a weighted average would produce a
//!    number whose meaning changes discontinuously at the boundary. So a gate
//!    sets `predicted = REFUSE` and the weighted score is reported beside it as
//!    a description of *how much else* is also wrong, not as the prediction.
//! 2. **Every subscore is a saturating count**, `min(1, n / saturation)`. No
//!    per-app normalisation, so one app with 4,000 `invoke-virtual` sites does
//!    not drag the distribution.
//! 3. **Absence of evidence is not evidence of absence** in either direction: a
//!    `0` subscore means the analyzer did not find the signal, which is not the
//!    same as the app not having the dependency. See `prediction.md` T-VAL-1.
//!
//! # What is deliberately *not* in the score
//!
//! * `resources.arsc`. Not parsed (out of scope), so `SUB.RES.ARSC` is neither
//!   counted nor claimed. It is arguably the single largest unmeasured risk.
//! * `targetSdk`. A high `targetSdk` correlates with modern bytecode, but
//!   correlating is not the same as measuring, and the manifest is not read.
//! * Obfuscation. The analyzer is name-based, so an obfuscated app scores lower
//!   for having the same behaviour. This is a bias, and it is directional:
//!   **obfuscation lowers the score.** See T-VAL-3.

use serde::Serialize;
use std::collections::BTreeMap;

use crate::analysis::AppFacts;

/// A hard wall: enough on its own to make bytecode-only execution impossible.
///
/// The set is deliberately small. It is not "everything that could go wrong";
/// it is the set the taxonomy's §17.1 calls structurally guaranteed to fail
/// *and* that is statically observable. `SUB.TRUST.PLAY_INTEGRITY` is in it
/// with a caveat recorded in the ADR: what is detected is the client-side API
/// call, and the actual refusal happens on the app's own server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Gate {
    /// A `lib/<abi>/*.so` entry exists, or a `.so` payload is shipped under
    /// `assets/`. Sufficient reason to reject for a bytecode-only substrate.
    NativePayload,
    /// The APK declares `native` methods. Even with no `.so` shipped, the
    /// implementations are missing, so a call is an `UnsatisfiedLinkError`.
    NativeMethodUnimplemented,
    /// A decoded method body contains `invoke-polymorphic`, `invoke-custom`, or
    /// `const-method-handle`. These cannot be resolved without the
    /// `MethodHandle`/`CallSite` bootstrap machinery.
    DynamicInvoke,
    /// `com.google.android.gms.*` classes are referenced. `NoClassDefFoundError`
    /// at first use, and there is no way to proxy GMS out of existence.
    PlayServices,
}

/// One scored component of the rubric.
#[derive(Debug, Clone, Serialize)]
pub struct Component {
    /// Stable identifier, used in the JSON row and in `prediction.md`.
    pub id: &'static str,
    /// One line naming what the component measures.
    pub description: &'static str,
    /// Share of the total. The set of components sums to 1.0 exactly; asserted
    /// in `tests/rubric.rs`.
    pub weight: f64,
    /// `min(1, n / saturation)` for the underlying evidence count `n`.
    pub subscore: f64,
    /// `weight * subscore`, the contribution to the total.
    pub contribution: f64,
    /// The count `n` the subscore was computed from, so a reader can re-derive
    /// the subscore without reading the code.
    pub evidence_count: u64,
    /// The point at which the subscore saturates at 1.0.
    pub saturation: u64,
    /// `true` if a [`Gate`] fires for this component, in which case `contribution`
    /// is reported but the component is not the basis of the prediction.
    pub gated: bool,
}

/// The five-point band the score maps onto, plus the unknown state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Band {
    /// A hard wall fired: the prediction is that the app will not run.
    Refuse,
    /// Score in `[0.40, 0.70)`: a substantial number of assumptions unmet, most
    /// of them non-fatal in principle. Prediction is that the app starts and
    /// some capability is missing.
    Degrade,
    /// Score in `[0.20, 0.40)`: mostly the always-present substrate facts
    /// (network egress, `Build.SDK_INT`). Prediction is that the app runs with
    /// no specific capability loss.
    LikelyRuns,
    /// Score below `0.20`: the app uses very little that a substrate would have
    /// to fake.
    Minimal,
    /// The APK could not be analysed, or a DEX failed to parse. Not a score.
    Unknown,
}

/// The full prediction.
#[derive(Debug, Clone, Serialize)]
pub struct Prediction {
    /// The weighted total, 0.0–100.0, over the components that are not gated.
    pub score_0_100: f64,
    /// Sum of `weight` over ungated components, so the total is comparable even
    /// when a gate fired. `1.0` when no gate fired.
    pub ungated_weight: f64,
    /// The total rescaled so its denominator is 1.0, i.e. what the score would
    /// be if the gated components' weights were redistributed proportionally.
    /// Reported because a gated app's raw total is a different quantity.
    pub score_rescaled_0_100: f64,
    pub band: Band,
    /// Every gate that fired, with the evidence that fired it.
    pub gates: Vec<GateHit>,
    pub components: Vec<Component>,
    /// Free text stating what the score does *not* cover. Rendered into the
    /// JSON so a consumer cannot print the number without the caveat.
    pub not_covered: Vec<&'static str>,
}

/// A gate that fired, and why.
#[derive(Debug, Clone, Serialize)]
pub struct GateHit {
    pub gate: Gate,
    /// Human-readable evidence: entry names, signatures, counts.
    pub evidence: Vec<String>,
    /// The taxonomy IDs this gate corresponds to.
    pub taxonomy: Vec<&'static str>,
}

impl std::fmt::Display for Band {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Band::Refuse => "REFUSE",
            Band::Degrade => "DEGRADE",
            Band::LikelyRuns => "LIKELY_RUNS",
            Band::Minimal => "MINIMAL",
            Band::Unknown => "UNKNOWN",
        })
    }
}

/// The rubric. Weights are the *unconditional* share; a gated component still
/// reports its weight and contribution, and `ungated_weight` is what the total
/// divides by.
///
/// The ordering below is a claim: native code and the invokedynamic machinery
/// are worse than Play Services, which is worse than build-identity reads, which
/// is worse than reflection, which is worse than the kernel and filesystem
/// literals. That claim is reasonable and unmeasured.
pub static RUBRIC: &[ComponentSpec] = &[
    ComponentSpec {
        id: "native_payload",
        description: "A native payload ships in the APK (lib/<abi>/*.so or a .so under assets/), or a loadLibrary call site exists.",
        weight: 0.22,
        saturation: 1,
        gate: Some(Gate::NativePayload),
    },
    ComponentSpec {
        id: "dynamic_invoke",
        description: "invoke-polymorphic, invoke-custom, or const-method-handle appears in a decoded method body.",
        weight: 0.18,
        saturation: 1,
        gate: Some(Gate::DynamicInvoke),
    },
    ComponentSpec {
        id: "play_services",
        description: "com.google.android.gms.* classes are referenced. Unproxyable in a browser substrate.",
        weight: 0.15,
        saturation: 1,
        gate: Some(Gate::PlayServices),
    },
    ComponentSpec {
        id: "native_methods",
        description: "The APK declares methods with the native modifier. Implementation must come from somewhere; if no .so ships, it does not.",
        weight: 0.12,
        saturation: 4,
        gate: Some(Gate::NativeMethodUnimplemented),
    },
    ComponentSpec {
        id: "integrity_attestation",
        description: "Play Integrity, SafetyNet or licensing/DRM APIs referenced.",
        weight: 0.10,
        saturation: 1,
        gate: None,
    },
    ComponentSpec {
        id: "build_identity",
        description: "Instruction-level reads of android.os.Build identity fields (FINGERPRINT, MODEL, SERIAL, SUPPORTED_ABIS, ...).",
        weight: 0.09,
        saturation: 4,
        gate: None,
    },
    ComponentSpec {
        id: "reflection_surface",
        description: "Decoded call sites to Class.forName / getMethod(s) / getDeclaredMethod(s) / Field.setAccessible / Proxy.",
        weight: 0.06,
        saturation: 8,
        gate: None,
    },
    ComponentSpec {
        id: "dynamic_code",
        description: "DexClassLoader, InMemoryDexClassLoader or PathClassLoader referenced: more dex at run time.",
        weight: 0.05,
        saturation: 1,
        gate: None,
    },
    ComponentSpec {
        id: "kernel_fs_literals",
        description: "String constants naming /proc, /sys, /dev nodes, /system partitions, /data/data or SELinux contexts.",
        weight: 0.02,
        saturation: 8,
        gate: None,
    },
    ComponentSpec {
        id: "hardware_surface",
        description: "Sensor, camera, location, Bluetooth, NFC, telephony, biometric or vibration APIs referenced.",
        weight: 0.01,
        saturation: 4,
        gate: None,
    },
];

/// A rubric row, without the per-app numbers.
#[derive(Debug, Clone, Copy)]
pub struct ComponentSpec {
    pub id: &'static str,
    pub description: &'static str,
    pub weight: f64,
    pub saturation: u64,
    pub gate: Option<Gate>,
}

/// Predictions the score deliberately does not attempt to make, carried in the
/// output so the number cannot travel without them.
const NOT_COVERED: &[&str] = &[
    "resources.arsc is not parsed (out of scope), so SUB.RES.ARSC is unmeasured and is likely the largest single source of divergence.",
    "String-constant evidence proves the constant is in the APK, not that the app acts on it.",
    "Name-based analysis: R8 renames reflection targets, so an obfuscated app scores lower for the same behaviour.",
    "Server-side gating (Play Integrity verdicts, account state, licence checks) is not observable statically and is not modelled.",
    "The score predicts substrate *dependency*, not compatibility. A dependent app may still run, degraded.",
];

impl Prediction {
    /// Compute the prediction from the collected per-app facts.
    ///
    /// Returns [`Band::Unknown`] when `facts` is not analysable, so a caller
    /// cannot print a confident number over a file that failed to parse.
    pub fn compute(facts: &AppFacts) -> Prediction {
        if !facts.analysable {
            return Prediction {
                score_0_100: 0.0,
                ungated_weight: 0.0,
                score_rescaled_0_100: 0.0,
                band: Band::Unknown,
                gates: Vec::new(),
                components: Vec::new(),
                not_covered: NOT_COVERED.to_vec(),
            };
        }

        // Evidence counts, one per rubric row, computed once so a reader can
        // check them against the JSON signal blocks.
        let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
        for spec in RUBRIC {
            let n = match spec.id {
                "native_payload" => facts.native_payload_evidence(),
                "dynamic_invoke" => facts.dynamic_invoke_sites(),
                "play_services" => facts.play_services_references(),
                "native_methods" => facts.native_method_count(),
                "integrity_attestation" => facts.integrity_evidence(),
                "build_identity" => facts.build_field_read_count(),
                "reflection_surface" => facts.reflection_call_site_count(),
                "dynamic_code" => facts.dynamic_code_references(),
                "kernel_fs_literals" => facts.kernel_fs_literal_count(),
                "hardware_surface" => facts.hardware_reference_count(),
                other => unreachable!("rubric row {other} has no evidence rule"),
            };
            counts.insert(spec.id, n);
        }

        let gates = collect_gates(facts);
        let gated: BTreeSet<Gate> = gates.iter().map(|g| g.gate).collect();

        let mut components = Vec::with_capacity(RUBRIC.len());
        let mut total = 0.0f64;
        let mut ungated_weight = 0.0f64;
        let mut gated_contribution = 0.0f64;

        for spec in RUBRIC {
            let evidence_count = counts[spec.id];
            let subscore = if spec.saturation == 0 {
                0.0
            } else {
                (evidence_count as f64 / spec.saturation as f64).min(1.0)
            };
            let contribution = spec.weight * subscore;
            let is_gated = spec.gate.is_some_and(|g| gated.contains(&g));
            if is_gated {
                gated_contribution += contribution;
            } else {
                ungated_weight += spec.weight;
                total += contribution;
            }
            components.push(Component {
                id: spec.id,
                description: spec.description,
                weight: spec.weight,
                subscore,
                contribution,
                evidence_count,
                saturation: spec.saturation,
                gated: is_gated,
            });
        }

        // Two totals, because they answer different questions.
        //   score_0_100          "how much of the *ungated* rubric is violated"
        //   score_rescaled_0_100 "how much of the *whole* rubric is violated,
        //                          with gated weights redistributed"
        let score_0_100 = if ungated_weight > 0.0 {
            (total / ungated_weight) * 100.0
        } else {
            0.0
        };
        let score_rescaled_0_100 = if ungated_weight > 0.0 {
            (total + gated_contribution) * 100.0
        } else {
            0.0
        };

        let band = if !gates.is_empty() {
            Band::Refuse
        } else if score_0_100 >= 40.0 {
            Band::Degrade
        } else if score_0_100 >= 20.0 {
            Band::LikelyRuns
        } else {
            Band::Minimal
        };

        Prediction {
            score_0_100,
            ungated_weight,
            score_rescaled_0_100,
            band,
            gates,
            components,
            not_covered: NOT_COVERED.to_vec(),
        }
    }
}

use std::collections::BTreeSet;

/// Which gates fire, and the evidence for each.
fn collect_gates(facts: &AppFacts) -> Vec<GateHit> {
    let mut gates = Vec::new();

    if !facts.native.lib_entries.is_empty() || !facts.native.asset_native_payloads.is_empty() {
        let mut ev: Vec<String> = facts
            .native
            .lib_entries
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>();
        ev.extend(facts.native.asset_native_payloads.iter().take(4).cloned());
        if !facts.native.load_library_calls.is_empty() {
            ev.push(format!(
                "{} loadLibrary call site(s)",
                facts.native.load_library_calls.len()
            ));
        }
        gates.push(GateHit {
            gate: Gate::NativePayload,
            evidence: ev,
            taxonomy: vec![
                "SUB.NATIVE.LOAD_LIBRARY",
                "SUB.FS.LIB_PATH",
                "SUB.NATIVE.JNI_ENTRY",
            ],
        });
    }

    if facts.code.invoke.has_dynamic_invoke()
        || facts.code.invoke.invoke_polymorphic > 0
        || facts.code.invoke.invoke_custom > 0
        || facts.code.invoke.const_method_handle > 0
    {
        gates.push(GateHit {
            gate: Gate::DynamicInvoke,
            evidence: vec![
                format!(
                    "invoke-polymorphic x{}",
                    facts.code.invoke.invoke_polymorphic
                ),
                format!("invoke-custom x{}", facts.code.invoke.invoke_custom),
                format!(
                    "const-method-handle x{}",
                    facts.code.invoke.const_method_handle
                ),
                format!("const-method-type x{}", facts.code.invoke.const_method_type),
                format!("map_list call_site_ids x{}", facts.code.map_call_site_ids),
                format!("map_list method_handles x{}", facts.code.map_method_handles),
            ],
            taxonomy: vec!["SUB.FW.INVOKEDYNAMIC"],
        });
    }

    if facts.play_services_references() > 0 {
        gates.push(GateHit {
            gate: Gate::PlayServices,
            evidence: facts
                .trust
                .play_services_classes
                .iter()
                .take(8)
                .cloned()
                .collect(),
            taxonomy: vec!["SUB.TRUST.PLAY_SERVICES"],
        });
    }

    if !facts.native.native_declarations.is_empty() {
        let unimplemented: Vec<&crate::dexscan::NativeDeclaration> =
            if facts.native.lib_entries.is_empty() {
                facts.native.native_declarations.iter().collect()
            } else {
                Vec::new()
            };
        if unimplemented.is_empty() {
            // A `.so` ships, so the declarations are presumably implemented; the
            // NativePayload gate already fired. Not double-counted.
        } else {
            gates.push(GateHit {
                gate: Gate::NativeMethodUnimplemented,
                evidence: unimplemented
                    .iter()
                    .take(8)
                    .map(|d| d.signature.clone())
                    .collect(),
                taxonomy: vec!["SUB.NATIVE.JNI_ENTRY"],
            });
        }
    }

    gates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weights_sum_to_exactly_one() {
        let sum: f64 = RUBRIC.iter().map(|r| r.weight).sum();
        assert!(
            (sum - 1.0).abs() < 1e-12,
            "rubric weights sum to {sum}, not 1.0"
        );
    }

    #[test]
    fn component_ids_are_unique() {
        let mut ids: Vec<&str> = RUBRIC.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before, "duplicate rubric id");
    }

    #[test]
    fn every_saturation_is_at_least_one() {
        for r in RUBRIC {
            assert!(r.saturation >= 1, "{} saturates at 0", r.id);
        }
    }

    #[test]
    fn an_unanalysable_app_is_unknown_not_zero() {
        let facts = AppFacts {
            analysable: false,
            ..Default::default()
        };
        let p = Prediction::compute(&facts);
        assert_eq!(p.band, Band::Unknown);
        assert!(p.components.is_empty());
        assert!(!p.not_covered.is_empty());
    }

    #[test]
    fn a_completely_clean_app_lands_in_minimal() {
        let facts = AppFacts {
            analysable: true,
            ..Default::default()
        };
        let p = Prediction::compute(&facts);
        assert_eq!(p.band, Band::Minimal);
        assert_eq!(p.score_0_100, 0.0);
        assert!(p.gates.is_empty());
        assert_eq!(p.components.len(), RUBRIC.len());
    }
}
