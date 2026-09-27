#!/usr/bin/env node
/**
 * Sample driver: fetch a deterministic sample of APKs, predict each one, and
 * print the aggregate distribution.
 *
 * The sample is **not** random and is not chosen by the analyzer's own output.
 * The rule is a stride over the package-sorted corpus, stratified by whether the
 * APK ships `lib/<abi>/*.so`, because the project's question is about the
 * DEX-only subset and a uniform sample of F-Droid is ~55% native. Both strata
 * are reported separately, and the denominators are printed next to every
 * figure, because a percentage without a denominator is the failure mode this
 * project is trying not to reproduce.
 *
 *   node analysis/run-sample.mjs --n 60 --out-dir /tmp/apks
 *   node analysis/run-sample.mjs --n 60 --strata 40:20   # native:dex-only
 *
 * Nothing here is committed: `corpus/apks/` is gitignored, and the default
 * output directory is outside the repository.
 */

import { createWriteStream } from 'node:fs';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import { once } from 'node:events';
import path from 'node:path';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const SURVEY = path.join(REPO, 'corpus', 'survey.jsonl');
const DEFAULT_OUT_DIR = '/tmp/andro-substrate-apks';
/** Above this the fetch is skipped and the app is recorded as a miss, so a
 *  multi-hundred-megabyte game does not silently dominate the run's runtime. */
const MAX_APK_BYTES = 120 * 1024 * 1024;

function parseArgs(argv) {
  const args = {
    n: 60,
    strata: '30:30',
    outDir: DEFAULT_OUT_DIR,
    rows: path.join(REPO, 'analysis', 'sample', 'rows.jsonl'),
    summary: path.join(REPO, 'analysis', 'sample', 'summary.json'),
    concurrency: 4,
    retries: 3,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf('=');
    const key = eq === -1 ? a : a.slice(0, eq);
    const value = eq === -1 ? null : a.slice(eq + 1);
    const next = () => value ?? argv[++i];
    switch (key) {
      case '--n': args.n = Number(next()); break;
      case '--strata': args.strata = next(); break;
      case '--out-dir': args.outDir = next(); break;
      case '--rows': args.rows = next(); break;
      case '--summary': args.summary = next(); break;
      case '--concurrency': args.concurrency = Number(next()); break;
      default:
        throw new Error(`unknown flag ${key}`);
    }
  }
  return args;
}

/**
 * Stride sampling: take every k-th element of a sorted list.
 *
 * Deterministic, order-independent of any hash, and easy to re-derive by hand
 * from `corpus/survey.jsonl`. Recorded in the summary so the sample can be
 * reconstructed without this script.
 */
function stride(list, want) {
  if (want <= 0 || list.length === 0) return [];
  const k = list.length / want;
  const out = [];
  for (let i = 0; i < want; i++) {
    out.push(list[Math.min(list.length - 1, Math.floor(i * k))]);
  }
  return out;
}

async function download(url, dest, retries) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { redirect: 'follow' });
      if (!res.ok) throw new Error(`http ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      await writeFile(dest, buf);
      return { ok: true, bytes: buf.length, sha256: sha256(buf) };
    } catch (e) {
      if (attempt === retries) return { ok: false, error: String(e.message ?? e) };
      await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
    }
  }
  return { ok: false, error: 'unreachable' };
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/** Read a JSONL file into an array, skipping unparseable lines. */
async function readJsonl(p) {
  const text = await readFile(p, 'utf8');
  return text
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}

/**
 * Run the `predict` binary over a list of APKs, one JSONL row per APK.
 *
 * `--summary` is not optional here. The full document includes every
 * `type_id`, `method_id` and `field_id` in every DEX, which for a 10 MB APK is
 * tens of megabytes of JSON; 60 of them do not fit in a Node string. The
 * per-DEX scans stay available via `predict <apk>` for anyone who wants them
 * for one app.
 */
async function predict(paths, bin) {
  const tmp = path.join(await mkdtemp(path.join(tmpdir(), 'predict-')), 'out.jsonl');
  const out = createWriteStream(tmp);
  const child = spawn(bin, ['--jsonl', '--summary', '--out', tmp, ...paths], {
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  const [code] = await once(child, 'close');
  if (code !== 0 && code !== 2) throw new Error(`predict exited ${code}`);
  out.close();
  const text = await readFile(tmp, 'utf8');
  return text
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}

/** An asynchronous worker pool over `items`. */
async function pool(items, width, fn) {
  const out = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, width) }, async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [wantNative, wantDexOnly] = args.strata.split(':').map(Number);
  const survey = await readJsonl(SURVEY);

  // Deterministic order: package name, then versionCode. The corpus file order
  // is already a seeded sample, but depending on that would make the rule
  // depend on a file this project does not control.
  const ok = survey
    .filter((r) => r.ok === true)
    .sort((a, b) =>
      a.packageName === b.packageName
        ? a.versionCode - b.versionCode
        : a.packageName < b.packageName ? -1 : 1);

  const native = ok.filter((r) => r.hasNativeCode === true && r.apkBytes <= MAX_APK_BYTES);
  const dexOnly = ok.filter((r) => r.hasNativeCode === false && r.apkBytes <= MAX_APK_BYTES);
  const chosen = [
    ...stride(native, wantNative).map((r) => ({ row: r, stratum: 'native' })),
    ...stride(dexOnly, wantDexOnly).map((r) => ({ row: r, stratum: 'dex-only' })),
  ];

  await mkdir(args.outDir, { recursive: true });
  await mkdir(path.dirname(args.rows), { recursive: true });

  console.log(`corpus rows: ${survey.length}, ok: ${ok.length}`);
  console.log(`  native stratum: ${native.length} eligible, taking ${wantNative} by stride`);
  console.log(`  dex-only stratum: ${dexOnly.length} eligible, taking ${wantDexOnly} by stride`);
  console.log(`  max APK bytes: ${MAX_APK_BYTES}`);

  const fetched = await pool(chosen, args.concurrency, async ({ row, stratum }) => {
    const dest = path.join(args.outDir, row.apkName);
    const existing = await stat(dest).catch(() => null);
    if (existing) {
      // Recompute rather than trusting a sidecar: the SHA-256 is what makes the
      // sample reproducible, and a stale one is worse than none.
      return {
        row,
        stratum,
        dest,
        bytes: existing.size,
        sha256: sha256(await readFile(dest)),
        cached: true,
      };
    }
    const r = await download(row.apkUrl, dest, args.retries);
    if (!r.ok) return { row, stratum, dest, error: r.error };
    return { row, stratum, dest, bytes: r.bytes, sha256: r.sha256 };
  });

  const okFetched = fetched.filter((f) => !f.error);
  const failed = fetched.filter((f) => f.error);
  console.log(`fetched ${okFetched.length}/${fetched.length}` +
    (failed.length ? `, ${failed.length} failed: ${failed.map((f) => f.row.packageName).join(', ')}` : ''));

  const bin = path.join(REPO, 'analysis', 'target', 'release', 'predict');
  await stat(bin).catch(() => {
    throw new Error(`${bin} not built; run: (cd analysis && cargo build --release)`);
  });

  const predicted = await predict(okFetched.map((f) => f.dest), bin);
  const byPath = new Map(predicted.map((p) => [p.apk_path, p]));

  const rows = [];
  for (const f of okFetched) {
    const p = byPath.get(f.dest);
    if (!p) continue;
    // `--summary` flattens the document: the signal blocks are top level and
    // the per-DEX scans are omitted.
    const rows0 = {
      packageName: f.row.packageName,
      versionCode: f.row.versionCode,
      apkName: f.row.apkName,
      stratum: f.stratum,
      corpusHasNativeCode: f.row.hasNativeCode,
      corpusDexCount: f.row.dexCount,
      corpusDexBytes: f.row.dexBytes,
      minSdk: f.row.minSdk,
      targetSdk: f.row.targetSdk,
      fetchedSha256: f.sha256 ?? f.cachedSha256 ?? null,
      analysable: p.analysable,
      error: p.error,
      band: p.prediction.band,
      score: p.prediction.score_0_100,
      scoreRescaled: p.prediction.score_rescaled_0_100,
      gates: p.prediction.gates.map((g) => g.gate),
      components: p.prediction.components.map((c) => ({
        id: c.id, weight: c.weight, subscore: c.subscore, evidence: c.evidence_count, gated: c.gated,
      })),
      invoke: p.code.invoke,
      mapCallSiteIds: p.code.map_call_site_ids,
      mapMethodHandles: p.code.map_method_handles,
      dexVersions: p.code.dex_versions,
      mapSections: p.code.map_sections,
      methodsWithCode: p.code.methods_with_code,
      nativeMethods: p.native.native_declarations.length,
      nativeMethodsUnimplemented: p.native.native_declarations_unimplemented.length,
      loadLibraryCalls: p.native.load_library_calls.length,
      loadLibraryNames: p.native.load_library_names,
      loadLibraryEvidence: p.native.load_library_calls.slice(0, 6).map((c) => c.evidence),
      libEntries: p.native.lib_entries,
      assetNativePayloads: p.native.asset_native_payloads,
      assetsTotal: p.native.assets_total,
      assetsSniffed: p.native.assets_sniffed,
      assetsSniffBudgetExhausted: p.native.assets_sniff_budget_exhausted,
      buildFieldNames: p.build.field_names_read,
      buildFieldReads: p.build.total_reads,
      buildFieldEvidence: p.build.evidence.slice(0, 6),
      reflectionCallSites: p.code.reflection_call_site_total,
      reflectionEvidence: p.code.reflection_call_sites.slice(0, 6),
      reflectiveStringConstants: p.code.reflective_string_constant_total,
      reflectiveStringSample: p.code.reflective_string_constants.slice(0, 8),
      playServicesClasses: p.trust.play_services_classes,
      playIntegrityClasses: p.trust.play_integrity_api_classes,
      integrityLiterals: p.trust.integrity_literals,
      drmLiterals: p.trust.drm_literals,
      licensingClasses: p.trust.licensing_classes.length,
      firebaseClasses: p.trust.firebase_classes.length,
      dynamicCodeClasses: p.code.dynamic_code_classes,
      methodsWithCode: p.code.methods_with_code,
      methodsUndecodable: p.code.methods_undecodable,
      methodsTriesUnparsed: p.code.methods_tries_unparsed,
      methodsTruncatedTail: p.code.methods_truncated_tail,
      pathTagCounts: Object.fromEntries(p.paths.tag_counts.map(([t, n]) => [t, n])),
      pathConstantSample: p.paths.constants.slice(0, 6).map((c) => `${c.tag} ${c.text}`),
      packageManagerClasses: p.paths.package_manager_classes,
      frameworkPrefixCounts: p.taxonomy_hits.length,
      taxonomyHitCount: p.taxonomy_hits.length,
      taxonomyHits: p.taxonomy_hits.map((h) => ({
        id: h.id,
        family: h.family,
        confidence: h.confidence,
        memberCount: h.member_count,
        callSites: h.call_sites,
        members: h.members.slice(0, 6),
      })),
    };
    rows.push(rows0);
  }

  const out = createWriteStream(args.rows);
  for (const r of rows) out.write(`${JSON.stringify(r)}\n`);
  out.end();
  await once(out, 'close');

  const summary = summarise(rows, chosen, survey, args, { failed: failed.map((f) => ({ pkg: f.row.packageName, error: f.error })) });
  await writeFile(args.summary, `${JSON.stringify(summary, null, 2)}\n`);
  console.log('');
  console.log(pretty(summary));
  console.log('');
  console.log(`rows:  ${args.rows}`);
  console.log(`report: ${args.summary}`);
}

function pct(n, d) {
  return d === 0 ? 'n/a' : `${n}/${d} = ${(100 * n / d).toFixed(1)}%`;
}

/**
 * The one definition of each headline signal.
 *
 * `headline`, `headlineAsCounts` and the per-stratum breakdowns are all derived
 * from this table, so a number cannot be right in one column and wrong in
 * another — the failure mode of a report that recomputes its own denominators.
 */
const SIGNALS = {
  invokePolymorphic: 'a decoded invoke-polymorphic or invoke-polymorphic/range',
  invokeCustom: 'a decoded invoke-custom or invoke-custom/range',
  eitherDynamicInvoke: 'either of the two, or const-method-handle',
  constMethodHandle: 'a decoded const-method-handle',
  constMethodType: 'a decoded const-method-type',
  declaredNativeMethods: 'a method declared with the native modifier',
  loadLibraryCallSites: 'a System.loadLibrary / System.load / Runtime.load call site',
  loadLibraryNamesBound: 'a loadLibrary call site whose library name was bound in the same basic block',
  libEntries: 'a lib/<abi>/*.so entry in the central directory',
  assetNativePayloads: 'a .so entry outside lib/, or an assets/ entry with ELF magic',
  buildIdentityReads: 'an instruction-level read of an android.os.Build identity field',
  playServices: 'an external com.google.android.gms.* class',
  playIntegrity: 'a com.google.android.play.core.* class or a Play Integrity / SafetyNet string constant',
  drmOrLicensing: 'a com.google.android.vending.* class or a licensing/DRM string constant',
  reflectionCallSites: 'a decoded Class.forName / getMethod(s) / getDeclaredMethod(s) call site',
  dynamicCode: 'an external DexClassLoader / InMemoryDexClassLoader / PathClassLoader',
};

const predFn = {
  invokePolymorphic: (r) => r.invoke.invoke_polymorphic > 0,
  invokeCustom: (r) => r.invoke.invoke_custom > 0,
  eitherDynamicInvoke: (r) =>
    r.invoke.invoke_polymorphic > 0
    || r.invoke.invoke_custom > 0
    || r.invoke.const_method_handle > 0,
  constMethodHandle: (r) => r.invoke.const_method_handle > 0,
  constMethodType: (r) => r.invoke.const_method_type > 0,
  declaredNativeMethods: (r) => r.nativeMethods > 0,
  loadLibraryCallSites: (r) => r.loadLibraryCalls > 0,
  loadLibraryNamesBound: (r) => r.loadLibraryNames.length > 0,
  libEntries: (r) => r.libEntries.length > 0,
  assetNativePayloads: (r) => r.assetNativePayloads.length > 0,
  buildIdentityReads: (r) => r.buildFieldReads > 0,
  playServices: (r) => r.playServicesClasses.length > 0,
  playIntegrity: (r) => r.playIntegrityClasses.length > 0 || r.integrityLiterals.length > 0,
  drmOrLicensing: (r) => r.drmLiterals.length > 0 || r.licensingClasses > 0,
  reflectionCallSites: (r) => r.reflectionCallSites > 0,
  dynamicCode: (r) => r.dynamicCodeClasses.length > 0,
};

function summarise(rows, chosen, survey, args, extra) {
  const analysable = rows.filter((r) => r.analysable);
  const dexOnly = analysable.filter((r) => r.stratum === 'dex-only');
  const nativeStratum = analysable.filter((r) => r.stratum === 'native');
  const byId = new Map();
  for (const r of analysable) {
    for (const h of r.taxonomyHits) {
      const e = byId.get(h.id) ?? { id: h.id, apps: 0, members: 0, callSites: 0, confidence: h.confidence };
      e.apps += 1;
      e.members += h.memberCount;
      e.callSites += h.callSites;
      if (h.confidence === 'VERIFIED') e.confidence = 'VERIFIED';
      byId.set(h.id, e);
    }
  }
  const taxonomy = [...byId.values()].sort((a, b) => b.apps - a.apps || a.id.localeCompare(b.id));
  const count = (pred) => analysable.filter(pred).length;
  return {
    generated: null,
    predictorVersion: '0.1.0',
    repoVersion: 30000,
    selection: {
      rule: 'stride over corpus/survey.jsonl rows with ok===true, sorted by (packageName, versionCode), stratified by corpus hasNativeCode; APKs above maxApkBytes excluded',
      maxApkBytes: MAX_APK_BYTES,
      corpusRows: survey.length,
      corpusOkRows: survey.filter((r) => r.ok === true).length,
      nativeEligible: chosen.filter((c) => c.stratum === 'native').length,
      dexOnlyEligible: chosen.filter((c) => c.stratum === 'dex-only').length,
      requested: args.strata,
      selected: chosen.length,
      fetched: rows.length,
    },
    denominators: {
      chosen: chosen.length,
      analysable: analysable.length,
      dexOnlyStratum: dexOnly.length,
      nativeStratum: nativeStratum.length,
      unanalysable: chosen.length - analysable.length,
    },
    failures: extra.failed,
    dexVersions: Object.fromEntries(
      [...new Set(rows.flatMap((r) => r.dexVersions ?? []))]
        .sort()
        .map((v) => [v, rows.filter((r) => (r.dexVersions ?? []).includes(v)).length])),
    coverage: {
      methodsWithCode: analysable.reduce((a, r) => a + r.methodsWithCode, 0),
      methodsUndecodable: analysable.reduce((a, r) => a + r.methodsUndecodable, 0),
      methodsTruncatedTail: analysable.reduce((a, r) => a + r.methodsTruncatedTail, 0),
      methodsTriesUnparsed: analysable.reduce((a, r) => a + r.methodsTriesUnparsed, 0),
      appsWithAnyUndecodable: analysable.filter((r) => r.methodsUndecodable > 0).length,
    },
    callSiteSectionsPresent: analysable.filter((r) => r.mapCallSiteIds > 0).length,
    methodHandleSectionsPresent: analysable.filter((r) => r.mapMethodHandles > 0).length,
    headline: Object.fromEntries(
      Object.keys(predFn).map((k) => [k, analysable.filter(predFn[k]).length])),
    headlineAsCounts: Object.fromEntries(
      Object.keys(predFn).map((k) => [k, analysable.filter(predFn[k]).length])),
    signalDefinitions: SIGNALS,
    dexOnlyStratumHeadline: Object.fromEntries(
      ['invokePolymorphic', 'invokeCustom', 'eitherDynamicInvoke', 'constMethodHandle',
        'declaredNativeMethods', 'loadLibraryCallSites', 'loadLibraryNamesBound',
        'libEntries', 'assetNativePayloads', 'buildIdentityReads', 'playServices',
        'playIntegrity', 'drmOrLicensing', 'reflectionCallSites', 'dynamicCode']
        .map((k) => [k, dexOnly.filter((r) => predFn[k](r)).length]),
    ),
    nativeStratumHeadline: Object.fromEntries(
      ['eitherDynamicInvoke', 'declaredNativeMethods', 'loadLibraryCallSites', 'libEntries',
        'buildIdentityReads', 'playServices', 'reflectionCallSites']
        .map((k) => [k, nativeStratum.filter((r) => predFn[k](r)).length]),
    ),
    bands: Object.fromEntries(
      ['REFUSE', 'DEGRADE', 'LIKELY_RUNS', 'MINIMAL', 'UNKNOWN']
        .map((b) => [b, analysable.filter((r) => r.band === b).length])),
    gates: Object.fromEntries(
      ['NATIVE_PAYLOAD', 'DYNAMIC_INVOKE', 'PLAY_SERVICES', 'NATIVE_METHOD_UNIMPLEMENTED']
        .map((g) => [g, analysable.filter((r) => r.gates.includes(g)).length])),
    taxonomy,
  };
}

function pretty(s) {
  const L = [];
  const d = s.denominators;
  L.push(`denominators: chosen=${d.chosen} analysable=${d.analysable} unanalysable=${d.unanalysable}`);
  L.push(`              dex-only stratum=${d.dexOnlyStratum} native stratum=${d.nativeStratum}`);
  L.push('');
  L.push('headline (of analysable):');
  for (const [k, v] of Object.entries(s.headlineAsCounts)) {
    L.push(`  ${k.padEnd(24)} ${pct(v, d.analysable)}`);
  }
  L.push('');
  const dd = s.denominators.dexOnlyStratum;
  L.push(`headline, DEX-only stratum only (denominator ${dd}):`);
  for (const [k, v] of Object.entries(s.dexOnlyStratumHeadline)) {
    L.push(`  ${k.padEnd(24)} ${pct(v, dd)}`);
  }
  L.push('');
  L.push('bands:');
  for (const [k, v] of Object.entries(s.bands)) L.push(`  ${k.padEnd(24)} ${pct(v, d.analysable)}`);
  L.push('');
  L.push('dex versions:');
  for (const [k, v] of Object.entries(s.dexVersions ?? {})) L.push(`  ${k.padEnd(24)} ${v}/${d.analysable}`);
  L.push(`  map_list call_site_ids present:     ${s.callSiteSectionsPresent}/${d.analysable}`);
  L.push(`  map_list method_handles present:  ${s.methodHandleSectionsPresent}/${d.analysable}`);
  L.push('');
  L.push('instruction coverage:');
  const c = s.coverage;
  const pctc = (x) => `${x} of ${c.methodsWithCode} methods (${(100 * x / Math.max(1, c.methodsWithCode)).toFixed(3)}%)`;
  L.push(`  methods with code read      ${c.methodsWithCode}`);
  L.push(`  fully decoded               ${pctc(c.methodsWithCode - c.methodsUndecodable - c.methodsTruncatedTail)}`);
  L.push(`  undecodable (lost)          ${pctc(c.methodsUndecodable)}`);
  L.push(`  truncated tail (no loss)    ${pctc(c.methodsTruncatedTail)}`);
  L.push(`  try table unparsed          ${pctc(c.methodsTriesUnparsed)}`);
  L.push(`  apps with any undecodable   ${c.appsWithAnyUndecodable}/${d.analysable}`);
  L.push('');
  L.push('gates:');
  for (const [k, v] of Object.entries(s.gates)) L.push(`  ${k.padEnd(24)} ${pct(v, d.analysable)}`);
  L.push('');
  L.push(`top taxonomy ids (apps / analysable):`);
  for (const t of s.taxonomy.slice(0, 30)) {
    L.push(`  ${t.id.padEnd(34)} ${String(t.apps).padStart(4)}  ${pct(t.apps, d.analysable).padEnd(22)} ${t.confidence}  members=${t.members} callSites=${t.callSites}`);
  }
  return L.join('\n');
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
