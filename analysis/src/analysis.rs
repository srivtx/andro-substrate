//! Per-app aggregation: turn an APK's bytes into one JSON analysis.
//!
//! This module is the seam between *facts* ([`dexscan`], [`strings`],
//! [`zip`]) and *judgement* ([`score`], [`taxonomy`]). It is deliberately thin
//! on judgement: everything it decides is either an aggregate of counted facts
//! or a selection rule that is stated in a doc comment.
//!
//! # Selection rules, all stated
//!
//! * `lib/<abi>/*.so` is counted by **entry name**, matching
//!   `corpus/report.md` definition A, so the two measurements are comparable.
//!   It is not confirmed by reading the ELF header.
//! * A native payload under `assets/` is detected two ways: by the `.so`
//!   extension, and by sniffing the first four bytes of every asset for the ELF
//!   magic `\x7fELF`. The sniff is bounded and its coverage is reported, because
//!   an unbounded sniff of a 40 MB asset is not an analysis budget.
//! * `Play Services` is judged on `external_types` — classes the APK references
//!   but does **not** define — so a bundled GMS stub is not counted as a
//!   dependency on GMS.
//! * Anything that could not be read is `unknown`, never zero.

use serde::Serialize;
use std::collections::BTreeSet;

use crate::dexscan::{self, DexScan, Evidence, LoadLibraryCall, NativeDeclaration, TaxonomyHit};
use crate::error::Error;
use crate::score::Prediction;
use crate::strings::StringTag;
use crate::taxonomy::Confidence;
use crate::zip::Archive;

/// ELF magic.
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
/// How many bytes of each asset are read when sniffing for ELF.
const ASSET_SNIFF_BYTES: u64 = 512;
/// How many assets are sniffed before the budget is declared exhausted.
const ASSET_SNIFF_MAX_ENTRIES: usize = 4096;
/// Total compressed bytes the sniff will decompress before stopping.
const ASSET_SNIFF_MAX_BYTES: u64 = 64 << 20;

/// Native payload inventory.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NativeFacts {
    /// `lib/<abi>/*.so` entry names.
    pub lib_entries: Vec<String>,
    /// The distinct ABI directory names under `lib/`.
    pub abis: Vec<String>,
    /// `.so`-named or ELF-magic-bearing entries **outside** `lib/`, e.g. a
    /// Chaquopy Python runtime under `assets/`.
    pub asset_native_payloads: Vec<String>,
    /// Every `loadLibrary`/`load` call site, with the bound name if any.
    pub load_library_calls: Vec<LoadLibraryCall>,
    /// Distinct library names inferred at those call sites.
    pub load_library_names: Vec<String>,
    /// `loadLibrary` call sites whose argument register was never written by a
    /// `const-string` in the same method. `unknown`, not "no name".
    pub load_library_name_unknown: u32,
    /// Methods declared `native`.
    pub native_declarations: Vec<NativeDeclaration>,
    /// Count of `native` declarations whose class also has a `System.loadLibrary`
    /// or a `lib/<abi>/<class>.so` sibling. A native declaration with *neither*
    /// is the specific, reportable failure mode: nothing in the APK implements
    /// it.
    pub native_declarations_unimplemented: Vec<NativeDeclaration>,
    /// Coverage of the asset ELF sniff, so the reader knows what was and was not
    /// looked at.
    pub assets_total: u32,
    pub assets_sniffed: u32,
    pub assets_sniff_budget_exhausted: bool,
}

/// JNI, reflection and dynamic-code facts.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CodeFacts {
    pub invoke: dexscan::InvokeCounts,
    /// `map_list` `call_site_id_item` count across all DEX.
    pub map_call_site_ids: u32,
    /// `map_list` `method_handle_item` count across all DEX. Structurally zero
    /// on DEX 039; see [`CodeFacts::map_sections`].
    pub map_method_handles: u32,
    /// DEX version strings seen, sorted and deduplicated. A sample where every
    /// app is `039` explains why `map_call_site_ids` is 0 without any of it
    /// being about the apps.
    pub dex_versions: Vec<String>,
    /// The `map_list` inventory of the first DEX, as `(section, count)`. The
    /// *absence* of `call_site_ids` and `method_handles` is the load-bearing
    /// observation, and it cannot be expressed as a zero-valued field.
    pub map_sections: Vec<(String, u32)>,
    /// Reflection call sites, capped for output.
    pub reflection_call_sites: Vec<Evidence>,
    /// True when `reflection_call_sites` was truncated for output.
    pub reflection_call_sites_truncated: bool,
    /// Total reflection call sites, before capping.
    pub reflection_call_site_total: u32,
    /// The distinct reflective members referenced.
    pub reflective_members: Vec<String>,
    /// String constants that look like a class or member name, capped.
    pub reflective_string_constants: Vec<String>,
    /// True when the constant list was truncated.
    pub reflective_string_constants_truncated: bool,
    /// Total qualifying constants before capping.
    pub reflective_string_constant_total: u32,
    /// External (not-defined-here) `DexClassLoader`-family classes.
    pub dynamic_code_classes: Vec<String>,
    pub methods_with_code: u32,
    pub methods_undecodable: u32,
    pub methods_tries_unparsed: u32,
    pub methods_truncated_tail: u32,
    pub instructions_decoded: u64,
}

/// `android.os.Build` identity reads.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BuildFacts {
    /// The distinct `Build` fields read, as `Landroid/os/Build;.NAME:type`.
    pub fields_read: Vec<String>,
    /// Distinct field *names*, sorted: the taxonomy's per-ID signal.
    pub field_names_read: Vec<String>,
    pub static_reads: u32,
    pub instance_reads: u32,
    /// Up to this many call sites, with the enclosing method named.
    pub evidence: Vec<Evidence>,
    pub evidence_truncated: bool,
    pub total_reads: u32,
}

/// Trust and integrity, with the client/server distinction kept explicit.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TrustFacts {
    /// External classes under `com.google.android.gms.*`.
    pub play_services_classes: Vec<String>,
    /// External classes under `com.google.firebase.*` (kept separate: Firebase
    /// has non-GMS backends, so it is a weaker signal).
    pub firebase_classes: Vec<String>,
    /// External classes under `com.google.android.play.core.*`, which is where
    /// the Play Integrity client API lives.
    pub play_integrity_api_classes: Vec<String>,
    /// String constants naming a Play Integrity or SafetyNet symbol.
    pub integrity_literals: Vec<String>,
    /// String constants naming a licensing or DRM symbol.
    pub drm_literals: Vec<String>,
    /// External classes under `com.google.android.vending.*`.
    pub licensing_classes: Vec<String>,
    /// Always `false`, and present precisely so it is never confused with the
    /// field above. See the note.
    pub server_side_verdict_observable: bool,
    /// The note, carried in the output rather than only in the docs.
    pub server_side_note: &'static str,
}

/// Substrate file-layout assumptions.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PathFacts {
    /// Per-tag counts, e.g. `PROC_PATH: 3`.
    pub tag_counts: Vec<(StringTag, u32)>,
    /// Matching constants, capped.
    pub constants: Vec<crate::strings::TaggedString>,
    pub constants_truncated: bool,
    pub total_constants: u32,
    /// External `PackageManager` classes the app queries other packages through.
    /// Presence of the class is not proof of a *cross-package* query; the
    /// taxonomy ID `SUB.IPC.PACKAGE_MANAGER_OTHER` is a conjecture here.
    pub package_manager_classes: Vec<String>,
}

/// All the counted facts, and the accessors the rubric reads.
///
/// The accessors are the *only* place a count is derived from a fact, so
/// `prediction.md` can list the ten of them and a reader can check each against
/// the corresponding JSON block.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AppFacts {
    /// `false` when the APK or one of its DEX files could not be read. The
    /// prediction is then `unknown`, never `Minimal`.
    pub analysable: bool,
    /// Typed reason, present when `analysable` is `false`.
    pub error: Option<Error>,
    pub apk_bytes: u64,
    pub zip_entries: u32,
    pub zip64: bool,
    pub dex_files: Vec<String>,
    pub dex_bytes: u64,
    pub classes: u32,
    pub methods_declared: u32,
    pub fields_declared: u32,
    pub native: NativeFacts,
    pub code: CodeFacts,
    pub build: BuildFacts,
    pub trust: TrustFacts,
    pub paths: PathFacts,
    /// The analyzer → taxonomy join.
    pub taxonomy_hits: Vec<TaxonomyHit>,
    /// Per-family rollup: family → (member count, id count).
    pub family_rollup: Vec<(String, u32, u32)>,
    /// Framework classes referenced externally, aggregated by prefix family
    /// (`android.app`, `android.view`, `java.io`, …), capped.
    pub framework_prefix_counts: Vec<(String, u32)>,
    pub framework_prefix_truncated: bool,
    /// Distinct framework classes, before capping.
    pub framework_class_total: u32,
    /// Number of distinct `type_id` entries, for the ratio against
    /// `framework_class_total`.
    pub referenced_type_count: u32,
    /// The per-DEX scans, for a reader who wants the raw evidence.
    pub dex_scans: Vec<DexScan>,
}

const EVIDENCE_CAP: usize = 64;
const CONSTANT_CAP: usize = 128;

/// `com.google.android.gms.` prefix, the Play Services class space.
const GMS_PREFIX: &str = "Lcom/google/android/gms/";
const FIREBASE_PREFIX: &str = "Lcom/google/firebase/";
const PLAY_CORE_PREFIX: &str = "Lcom/google/android/play/core/";
const VENDING_PREFIX: &str = "Lcom/google/android/vending/";
/// Dynamic-code class loaders, as external type descriptors.
const DYNAMIC_CODE_CLASSES: &[&str] = &[
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/InMemoryDexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ldalvik/system/BaseDexClassLoader;",
];
const PACKAGE_MANAGER_CLASSES: &[&str] = &[
    "Landroid/content/pm/PackageManager;",
    "Landroid/content/pm/LauncherApps;",
];

impl AppFacts {
    // ------------------------------------------------------------- accessors
    // Each of these is the sole derivation of one rubric row, and is named in
    // `prediction.md` so a disagreement is localisable.

    /// `lib/` entries + `assets/` payloads + `loadLibrary` call sites.
    ///
    /// Any one of the three is sufficient for the gate, so the count is a sum
    /// purely for display.
    pub fn native_payload_evidence(&self) -> u64 {
        self.native.lib_entries.len() as u64
            + self.native.asset_native_payloads.len() as u64
            + self.native.load_library_calls.len() as u64
    }

    /// `invoke-polymorphic` + `invoke-custom`, counted in decoded method bodies.
    pub fn dynamic_invoke_sites(&self) -> u64 {
        self.code.invoke.invoke_polymorphic as u64 + self.code.invoke.invoke_custom as u64
    }

    /// Distinct external `com.google.android.gms.*` classes.
    pub fn play_services_references(&self) -> u64 {
        self.trust.play_services_classes.len() as u64
    }

    /// Methods declared with the `native` modifier.
    pub fn native_method_count(&self) -> u64 {
        self.native.native_declarations.len() as u64
    }

    /// Play Integrity / SafetyNet / licensing evidence: the API classes, plus
    /// the string constants that name those symbols, plus the DRMs. Counted as
    /// a sum because the three are different kinds of reference and the rubric
    /// only asks "is any of this present".
    pub fn integrity_evidence(&self) -> u64 {
        self.trust.play_integrity_api_classes.len() as u64
            + self.trust.integrity_literals.len() as u64
            + self.trust.drm_literals.len() as u64
            + self.trust.licensing_classes.len() as u64
    }

    /// Instruction-level `Build` identity field reads.
    pub fn build_field_read_count(&self) -> u64 {
        self.build.total_reads as u64
    }

    /// Decoded reflection call sites.
    pub fn reflection_call_site_count(&self) -> u64 {
        self.code.reflection_call_site_total as u64
    }

    /// External `DexClassLoader`-family classes.
    pub fn dynamic_code_references(&self) -> u64 {
        self.code.dynamic_code_classes.len() as u64
    }

    /// Path-shaped string constants, counted per tag and summed here.
    pub fn kernel_fs_literal_count(&self) -> u64 {
        self.paths
            .tag_counts
            .iter()
            .filter(|(t, _)| {
                matches!(
                    t,
                    StringTag::ProcPath
                        | StringTag::SysPath
                        | StringTag::DevNode
                        | StringTag::SystemPartition
                        | StringTag::AppDataPath
                        | StringTag::SelinuxContext
                        | StringTag::ExternalStorage
                )
            })
            .map(|(_, n)| *n as u64)
            .sum()
    }

    /// Distinct referenced members whose taxonomy family is `SUB.HW`, plus
    /// `SUB.GFX.CAMERA_PIPE`. Derived from the rule table so the score and the
    /// ADR table cannot disagree about what counts as hardware.
    pub fn hardware_reference_count(&self) -> u64 {
        self.taxonomy_hits
            .iter()
            .filter(|h| h.family == "SUB.HW" || h.id == "SUB.GFX.CAMERA_PIPE")
            .map(|h| h.member_count as u64)
            .sum()
    }
}

/// Analyse a whole APK.
pub fn analyze_apk(bytes: Vec<u8>) -> AppFacts {
    let apk_bytes = bytes.len() as u64;
    let archive = match Archive::open(bytes) {
        Ok(a) => a,
        Err(e) => {
            return AppFacts {
                analysable: false,
                error: Some(e),
                apk_bytes,
                ..Default::default()
            }
        }
    };

    let mut facts = AppFacts {
        analysable: true,
        apk_bytes,
        zip_entries: archive.entry_count() as u32,
        zip64: archive.zip64,
        ..Default::default()
    };

    collect_native(&archive, &mut facts);

    // ------------------------------------------------------------- the DEX
    let dex_names: Vec<String> = archive
        .filter(is_dex_name)
        .map(|e| e.name.clone())
        .collect();
    let mut scans: Vec<DexScan> = Vec::new();
    let mut dex_error: Option<Error> = None;
    for name in &dex_names {
        let Some(entry) = archive.find(name) else {
            continue;
        };
        match archive.read_entry(entry) {
            Ok(dex_bytes) => {
                facts.dex_bytes += dex_bytes.len() as u64;
                match DexScan::scan(name, &dex_bytes) {
                    Ok(s) => scans.push(s),
                    Err(e) => {
                        if dex_error.is_none() {
                            dex_error = Some(e);
                        }
                    }
                }
            }
            Err(e) => {
                if dex_error.is_none() {
                    dex_error = Some(e);
                }
            }
        }
    }

    if scans.is_empty() {
        facts.analysable = false;
        facts.error = Some(dex_error.unwrap_or(Error::Dex {
            name: "<none>".to_string(),
            detail: "no classes*.dex entries in the archive".to_string(),
        }));
        return facts;
    }
    // A DEX that failed to parse makes the counts a lower bound. Flagged, not
    // hidden: the JSON carries `methods_undecodable` and `error`.
    if let Some(e) = dex_error {
        facts.error = Some(e);
    }

    facts.dex_files = scans.iter().map(|s| s.name.clone()).collect();
    merge_scans(&scans, &mut facts);
    facts.dex_scans = scans;
    facts
}

/// `classes.dex` and `classes2.dex` …, but not `classes-foo.dex` from a split,
/// and not a random file that happens to be named `xclasses.dex`.
fn is_dex_name(name: &str) -> bool {
    if !name.ends_with(".dex") || name.contains('/') {
        return false;
    }
    let stem = &name[..name.len() - 4];
    stem == "classes"
        || (stem.starts_with("classes") && stem[7..].chars().all(|c| c.is_ascii_digit()))
}

/// `lib/` inventory, the `assets/` ELF sniff, and the `loadLibrary` calls.
fn collect_native(archive: &Archive, facts: &mut AppFacts) {
    let mut abis: BTreeSet<String> = BTreeSet::new();
    for e in archive.entries() {
        if e.is_native_lib() {
            facts.native.lib_entries.push(e.name.clone());
            if let Some(abi) = e.abi() {
                abis.insert(abi.to_string());
            }
        }
    }
    facts.native.abis = abis.into_iter().collect();

    // `assets/**` native payload sniff. Bounded; coverage reported.
    let assets: Vec<_> = archive.filter(|n| n.starts_with("assets/")).collect();
    facts.native.assets_total = assets.len() as u32;
    let mut budget = ASSET_SNIFF_MAX_BYTES;
    for e in assets.iter().take(ASSET_SNIFF_MAX_ENTRIES) {
        if facts.native.assets_sniffed as usize >= ASSET_SNIFF_MAX_ENTRIES || budget == 0 {
            facts.native.assets_sniff_budget_exhausted = true;
            break;
        }
        // By name first: cheap, and the corpus found these.
        if e.name.ends_with(".so") {
            facts.native.asset_native_payloads.push(e.name.clone());
            facts.native.assets_sniffed += 1;
            continue;
        }
        if e.uncompressed_size < 4 || e.compressed_size > budget {
            // Too big to sniff within budget: skipped, and the budget flag is
            // set so the reader knows the sniff is not exhaustive.
            facts.native.assets_sniff_budget_exhausted = true;
            continue;
        }
        budget -= e.compressed_size;
        facts.native.assets_sniffed += 1;
        if let Ok(prefix) = archive.read_entry_prefix(e, ASSET_SNIFF_BYTES) {
            if prefix.len() >= 4 && &prefix[..4] == ELF_MAGIC {
                facts.native.asset_native_payloads.push(e.name.clone());
            }
        }
    }
    // `.so` outside `lib/` but not under `assets/` — the `res/5x.so` shape the
    // corpus flagged, and a real evasion route.
    for e in archive.entries() {
        if e.name.starts_with("lib/") || e.name.starts_with("assets/") {
            continue;
        }
        if e.name.ends_with(".so") {
            facts.native.asset_native_payloads.push(e.name.clone());
        }
    }
    facts.native.asset_native_payloads.sort();
    facts.native.asset_native_payloads.dedup();
}

/// Fold every per-DEX scan into the per-app facts.
fn merge_scans(scans: &[DexScan], facts: &mut AppFacts) {
    let mut invoke = dexscan::InvokeCounts::default();
    let mut call_sites: std::collections::BTreeMap<String, u32> = Default::default();
    let mut field_reads: std::collections::BTreeMap<String, u32> = Default::default();
    let mut referenced_methods: BTreeSet<String> = BTreeSet::new();
    let mut referenced_fields: BTreeSet<String> = BTreeSet::new();
    let mut referenced_types: BTreeSet<String> = BTreeSet::new();
    let mut external_types: BTreeSet<String> = BTreeSet::new();
    let mut all_strings: Vec<(StringTag, String)> = Vec::new();
    let mut reflective_strings: BTreeSet<String> = BTreeSet::new();

    for s in scans {
        facts.classes += s.classes;
        facts.methods_declared += s.methods_declared;
        facts.fields_declared += s.fields_declared;
        facts.code.methods_with_code += s.methods_with_code;
        facts.code.methods_undecodable += s.methods_undecodable;
        facts.code.methods_tries_unparsed += s.methods_tries_unparsed;
        facts.code.methods_truncated_tail += s.methods_truncated_tail;
        facts.code.instructions_decoded += s.instructions_decoded;
        facts.code.map_call_site_ids += s.map_call_site_ids;
        facts.code.map_method_handles += s.map_method_handles;
        if !s.dex_version.is_empty() && !facts.code.dex_versions.contains(&s.dex_version) {
            facts.code.dex_versions.push(s.dex_version.clone());
        }
        if facts.code.map_sections.is_empty() {
            facts.code.map_sections = s.map_sections.clone();
        }
        invoke.merge(&s.invoke);
        for (k, v) in &s.call_sites_by_target {
            *call_sites.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &s.field_reads_by_target {
            *field_reads.entry(k.clone()).or_insert(0) += v;
        }
        referenced_methods.extend(s.referenced_methods.iter().cloned());
        referenced_fields.extend(s.referenced_fields.iter().cloned());
        referenced_types.extend(s.referenced_types.iter().cloned());
        external_types.extend(s.external_types.iter().cloned());
        facts
            .native
            .native_declarations
            .extend(s.native_declarations.iter().cloned());
        facts
            .native
            .load_library_calls
            .extend(s.load_library_calls.iter().cloned());
        for r in &s.build_field_reads {
            facts.build.total_reads += 1;
            if r.static_access {
                facts.build.static_reads += 1;
            } else {
                facts.build.instance_reads += 1;
            }
            if facts.build.evidence.len() < EVIDENCE_CAP {
                facts.build.evidence.push(r.evidence.clone());
            }
            if let Some((_, name)) = r.field.rsplit_once('.') {
                if let Some((n, _)) = name.split_once(':') {
                    facts.build.field_names_read.push(n.to_string());
                }
            }
        }
        facts.code.reflection_call_site_total += s.reflection_call_sites.len() as u32;
        for e in &s.reflection_call_sites {
            if facts.code.reflection_call_sites.len() < EVIDENCE_CAP {
                facts.code.reflection_call_sites.push(e.clone());
            }
        }
        for m in &s.reflective_members {
            if !facts.code.reflective_members.contains(m) {
                facts.code.reflective_members.push(m.clone());
            }
        }
        for t in &s.tagged_strings {
            all_strings.push((t.tag, t.text.clone()));
            if matches!(
                t.tag,
                StringTag::QualifiedClassName | StringTag::QualifiedMemberName
            ) {
                reflective_strings.insert(t.text.clone());
            }
        }
    }

    facts.code.dex_versions.sort();
    facts.code.map_sections.sort();
    facts.code.invoke = invoke;
    facts.code.reflection_call_sites_truncated =
        facts.code.reflection_call_site_total as usize > facts.code.reflection_call_sites.len();
    facts.native.load_library_calls.sort();
    facts.native.load_library_calls.dedup();
    for c in &facts.native.load_library_calls {
        if c.name_unknown {
            facts.native.load_library_name_unknown += 1;
        }
        for n in &c.inferred_names {
            if !facts.native.load_library_names.contains(n) {
                facts.native.load_library_names.push(n.clone());
            }
        }
    }
    facts.native.load_library_names.sort();

    // Native declarations with nothing in the APK to implement them.
    //
    // The rule is a *name* match and nothing more: a `lib/<abi>/<name>.so` whose
    // basename equals the JNI short name, or a `loadLibrary` argument equal to
    // it. A real JNI implementation lives inside a `.so` under an unpredictable
    // name, so this is a lower bound on "unimplemented" — which is why the
    // field is a list, not a verdict. Everything statically resolvable about a
    // native method's implementation is unknown in general.
    let lib_basenames: BTreeSet<String> = facts
        .native
        .lib_entries
        .iter()
        .filter_map(|n| n.rsplit('/').next().map(str::to_string))
        .collect();
    let loaded: BTreeSet<String> = facts.native.load_library_names.iter().cloned().collect();
    for d in &facts.native.native_declarations {
        let short = d
            .signature
            .rsplit_once('.')
            .map(|(_, rest)| rest.split('(').next().unwrap_or("").to_string())
            .unwrap_or_default();
        let class_simple = d
            .class
            .strip_prefix('L')
            .and_then(|c| c.strip_suffix(';'))
            .and_then(|c| c.rsplit('/').next())
            .unwrap_or("")
            .to_string();
        let has_lib = lib_basenames.contains(&format!("{short}.so"))
            || lib_basenames.contains(&format!("{class_simple}.so"));
        let has_load = loaded.contains(&short) || loaded.contains(&class_simple);
        if !has_lib && !has_load {
            facts
                .native
                .native_declarations_unimplemented
                .push(d.clone());
        }
    }

    // Framework classes, aggregated by prefix family.
    let mut prefixes: std::collections::BTreeMap<String, u32> = Default::default();
    for t in &external_types {
        if let Some(family) = framework_prefix(t) {
            *prefixes.entry(family).or_insert(0) += 1;
        }
    }
    facts.framework_class_total = external_types.len() as u32;
    let mut pv: Vec<(String, u32)> = prefixes.into_iter().collect();
    pv.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    if pv.len() > EVIDENCE_CAP {
        facts.framework_prefix_truncated = true;
        pv.truncate(EVIDENCE_CAP);
    }
    facts.framework_prefix_counts = pv;

    // Trust.
    for t in &external_types {
        if t.starts_with(GMS_PREFIX) {
            facts.trust.play_services_classes.push(t.clone());
        } else if t.starts_with(FIREBASE_PREFIX) {
            facts.trust.firebase_classes.push(t.clone());
        } else if t.starts_with(PLAY_CORE_PREFIX) {
            facts.trust.play_integrity_api_classes.push(t.clone());
        } else if t.starts_with(VENDING_PREFIX) {
            facts.trust.licensing_classes.push(t.clone());
        }
    }
    facts.trust.server_side_verdict_observable = false;
    facts.trust.server_side_note = TRUST_NOTE;

    // Trust string constants. Populated from the string-constant classifier,
    // not from the pool, because a Play Integrity reference is nearly always a
    // string: the client-side class is `com.google.android.play.core.integrity`
    // and the *verdict strings* are literals. See `TRUST_NOTE` for the
    // client/server distinction this must not blur.
    for (tag, text) in &all_strings {
        let bucket = match tag {
            StringTag::IntegrityLiteral => &mut facts.trust.integrity_literals,
            StringTag::DrmLiteral => &mut facts.trust.drm_literals,
            _ => continue,
        };
        if !bucket.contains(text) {
            bucket.push(text.clone());
        }
    }
    facts.trust.integrity_literals.sort();
    facts.trust.drm_literals.sort();

    // Paths.
    let mut tag_counts: std::collections::BTreeMap<StringTag, u32> = Default::default();
    let mut constants: Vec<crate::strings::TaggedString> = Vec::new();
    for s in scans {
        for t in &s.tagged_strings {
            *tag_counts.entry(t.tag).or_insert(0) += 1;
            if constants.len() < CONSTANT_CAP {
                constants.push(t.clone());
            }
        }
    }
    facts.paths.total_constants = tag_counts.values().sum();
    facts.paths.constants_truncated = facts.paths.total_constants as usize > constants.len();
    facts.paths.constants = constants;
    facts.paths.tag_counts = tag_counts.into_iter().collect();
    for c in PACKAGE_MANAGER_CLASSES {
        if external_types.contains(*c) {
            facts.paths.package_manager_classes.push((*c).to_string());
        }
    }

    // Reflection-shaped string constants, capped.
    let all: Vec<String> = reflective_strings.into_iter().collect();
    facts.code.reflective_string_constant_total = all.len() as u32;
    facts.code.reflective_string_constants_truncated = all.len() > EVIDENCE_CAP;
    facts.code.reflective_string_constants = all.into_iter().take(EVIDENCE_CAP).collect();

    // Dynamic code loaders.
    for c in DYNAMIC_CODE_CLASSES {
        if external_types.contains(*c) {
            facts.code.dynamic_code_classes.push((*c).to_string());
        }
    }

    // The taxonomy join. Type-level rules are matched against `external_types`
    // — classes referenced but *not* defined here — so that an app bundling a
    // thin `Lcom/google/android/gms/...` stub does not appear to depend on Play
    // Services. Member-level rules use the full `method_ids`/`field_ids`, which
    // is correct because a call to a class the app defines is a real call
    // whatever the class is.
    let rm: Vec<String> = referenced_methods.into_iter().collect();
    let rf: Vec<String> = referenced_fields.into_iter().collect();
    let et: Vec<String> = external_types.into_iter().collect();
    let rt: Vec<String> = referenced_types.into_iter().collect();
    facts.taxonomy_hits = dexscan::map_references(&rm, &rf, &et, &call_sites, &field_reads);
    facts.referenced_type_count = rt.len() as u32;

    // `Build` field names, deduped.
    facts.build.field_names_read.sort();
    facts.build.field_names_read.dedup();
    let mut fields: BTreeSet<String> = BTreeSet::new();
    for s in scans {
        for r in &s.build_field_reads {
            fields.insert(r.field.clone());
        }
    }
    facts.build.fields_read = fields.into_iter().collect();
    // `evidence` is capped at EVIDENCE_CAP; `total_reads` is the real count.
    facts.build.evidence_truncated = facts.build.total_reads as usize > facts.build.evidence.len();

    // Per-family rollup.
    let mut fams: std::collections::BTreeMap<&str, (std::collections::BTreeSet<String>, u32)> =
        Default::default();
    for h in &facts.taxonomy_hits {
        let e = fams.entry(h.family).or_default();
        e.1 += h.member_count;
        e.0.insert(h.id.to_string());
    }
    facts.family_rollup = fams
        .into_iter()
        .map(|(f, (ids, members))| (f.to_string(), members, ids.len() as u32))
        .collect();
    facts
        .family_rollup
        .sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
}

/// `Landroid/os/Build$VERSION;` → `android.os`; `Lcom/x/Y;` → `com.x`;
/// `Ljava/util/Map$Entry;` → `java.util`.
fn framework_prefix(descriptor: &str) -> Option<String> {
    let body = descriptor.strip_prefix('L')?.strip_suffix(';')?;
    // Drop the nested-class part first, then keep the first two package
    // segments: `Landroid/os/Build$VERSION;` and `Landroid/os/Build;` both
    // aggregate as `android.os`.
    let head = body.split('$').next()?;
    let segs: Vec<&str> = head.split('/').collect();
    if segs.len() < 2 {
        return None;
    }
    Some(segs[..2].join("."))
}

/// The note carried in every `trust` block.
pub const TRUST_NOTE: &str = "A Play Integrity reference is a *client-side API call*: the app obtains a token and sends it to its own backend. Whether that backend accepts the request is not observable statically, is not a substrate failure, and is not modelled here. What the analyzer reports is only that the client-side path is present.";

/// `analyze_apk` plus the rubric, the common entry point.
pub fn predict(bytes: Vec<u8>) -> (AppFacts, Prediction) {
    let facts = analyze_apk(bytes);
    let prediction = Prediction::compute(&facts);
    (facts, prediction)
}

/// Count of hits at a given confidence level, for a summary report.
pub fn confidence_counts(facts: &AppFacts) -> (u32, u32) {
    let mut verified = 0;
    let mut conjecture = 0;
    for h in &facts.taxonomy_hits {
        match h.confidence {
            Confidence::Verified => verified += 1,
            Confidence::Conjecture => conjecture += 1,
        }
    }
    (verified, conjecture)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score::Band;

    #[test]
    fn dex_name_matching_is_exact() {
        assert!(is_dex_name("classes.dex"));
        assert!(is_dex_name("classes2.dex"));
        assert!(is_dex_name("classes10.dex"));
        assert!(!is_dex_name("classes-foo.dex"));
        assert!(!is_dex_name("foo/classes.dex"));
        assert!(!is_dex_name("classesx.dex"));
        assert!(!is_dex_name("resources.arsc"));
    }

    #[test]
    fn framework_prefix_collapses_to_two_segments() {
        assert_eq!(
            framework_prefix("Landroid/os/Build;"),
            Some("android.os".to_string())
        );
        assert_eq!(
            framework_prefix("Landroid/os/Build$VERSION;"),
            Some("android.os".to_string())
        );
        assert_eq!(
            framework_prefix("Lcom/google/android/gms/Foo;"),
            Some("com.google".to_string())
        );
        assert_eq!(
            framework_prefix("Ljava/util/Map$Entry;"),
            Some("java.util".to_string())
        );
        assert_eq!(
            framework_prefix("Ljava/lang/Object;"),
            Some("java.lang".to_string())
        );
        assert_eq!(framework_prefix("Ljava;"), None);
        assert_eq!(framework_prefix("[I"), None);
    }

    #[test]
    fn a_zip_without_dex_is_not_analysable() {
        let mut bytes = Vec::new();
        // Minimal stored-only archive with one non-dex entry.
        bytes.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        bytes.extend_from_slice(&[
            10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ]);
        let name = b"a.txt";
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(name);
        let cd_off = bytes.len() as u32;
        bytes.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        bytes.extend_from_slice(&[20, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(name);
        let cd_size = bytes.len() as u32 - cd_off;
        bytes.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        bytes.extend_from_slice(&cd_size.to_le_bytes());
        bytes.extend_from_slice(&cd_off.to_le_bytes());
        bytes.extend_from_slice(&[0, 0]);

        let facts = analyze_apk(bytes);
        assert!(!facts.analysable);
        assert_eq!(Prediction::compute(&facts).band, Band::Unknown);
    }

    #[test]
    fn a_non_zip_is_not_analysable_rather_than_panicking() {
        let facts = analyze_apk(b"hello".to_vec());
        assert!(!facts.analysable);
        assert_eq!(facts.error.as_ref().unwrap().kind(), "not_a_zip");
    }
}
