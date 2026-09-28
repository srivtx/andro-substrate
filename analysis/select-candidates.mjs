#!/usr/bin/env node
/**
 * Choose the first real APK andro-substrate will execute.
 *
 * **What this decides.** One package name. Nothing has ever been run, and the
 * candidate was previously going to be picked "somewhat at random". The
 * difference between a good first subject and a bad one is an afternoon versus
 * a fortnight, and the cost of getting it wrong is paid by everything
 * downstream, so the rule is written down and re-runnable rather than held in
 * someone's head.
 *
 * **The constraint being optimised against.** `shim/CONFORMANCE.md` measures the
 * framework shim at 144 classes, 334 methods and 55 fields: 100% type coverage
 * but 27.4% method coverage of what real apps call, and well under 0.5% of the
 * declared platform. The first subject must therefore need as little framework
 * surface as possible, and it must *draw something*, because the study's
 * dependent variable is `L2_FIRST_FRAME_DRAWN` and an app with no UI cannot
 * produce an L2 observation at all.
 *
 * # Three stages, and only the middle one touches the network
 *
 * | stage | input | output | pure? |
 * |---|---|---|---|
 * | 1 `pool` | `corpus/survey.jsonl` | the rows that pass the census-derivable filters | yes |
 * | 2 `measure` | the pool | `candidates/measured.jsonl` — one row per downloaded APK | no; downloads APKs |
 * | 3 `rank` | survey + `measured.jsonl` | the ranked shortlist | yes |
 *
 * Stage 2 is separated because it is the only one that needs the network and the
 * only one whose output is an artefact rather than a decision. Its output is
 * committed (like `sample/rows.jsonl` is), so **stage 3 re-runs identically
 * offline**, and every number in `candidates.md` is re-derivable from two
 * committed files plus this script. Stage 3 **refuses to run** if a pool member
 * has no measured row, rather than quietly ranking on less evidence.
 *
 * # Determinism
 *
 * There is no random seed, because nothing here is random. The pool is a total
 * order on `(dexBytes, packageName, versionCode)`; the shortlist is a total
 * order on `(score, distinctAndroidTypes, distinctAndroidMethods, dexBytes,
 * packageName, versionCode)`. Every component is a pure function of one integer
 * and one saturation constant, all of which are printed in `--explain` and
 * pinned by `analysis/tests/`. Re-running any stage gives byte-identical output.
 *
 * # Usage
 *
 * ```sh
 * node analysis/select-candidates.mjs pool                    # stage 1, offline
 * node analysis/select-candidates.mjs measure                 # stage 2, downloads
 * node analysis/select-candidates.mjs rank --top 10           # stage 3, offline
 * node analysis/select-candidates.mjs rank --explain           # every component
 * node analysis/select-candidates.mjs verify <apk>...          # hard filters, by hand
 * ```
 *
 * No APK is ever committed: the cache is outside the repository by default.
 */

import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';

import { onclickBindings, parseAxml } from './lib/axml.mjs';
import {
  dexEntries,
  libEntries,
  readApk,
  readEntry,
  readManifest,
  sharedObjectEntries,
  sniffElf,
} from './lib/apk.mjs';
import { indexSurface, loadShimSurface, splitFieldRef, splitMethodRef } from './lib/shim-surface.mjs';
import { classHistogram, parseTaxonomy, taxonomyWeight, EXPECTED_CLASSIFIED_IDS } from './lib/taxonomy-classes.mjs';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const REPO = path.resolve(HERE, '..');
const SURVEY = path.join(REPO, 'corpus', 'survey.jsonl');
const TAXONOMY = path.join(REPO, 'docs', 'divergence-taxonomy.md');
const MEASURED = path.join(HERE, 'candidates', 'measured.jsonl');
/** Measured rows for packages the pool excludes; the known-bad fixtures. */
const NEGATIVES = path.join(HERE, 'candidates', 'negatives.jsonl');
const PREDICT_BIN = path.join(HERE, 'target', 'release', 'predict');

/**
 * APKs are fetched here. A literal `/tmp` path, matching
 * `analysis/run-sample.mjs`'s `/tmp/andro-substrate-apks`, so a reader looking
 * for the cache does not have to evaluate `os.tmpdir()`. Outside the
 * repository, so nothing here can be committed by accident.
 */
const DEFAULT_CACHE = '/tmp/andro-substrate-candidates';

// =====================================================================
// Stage 1 — the pool. A pure function of corpus/survey.jsonl.
// =====================================================================

/**
 * The census-derivable half of the hard filters, plus the two size caps.
 *
 * Every predicate is `survey.jsonl`'s own field. The archive-level filters
 * (`.so` anywhere, ELF anywhere, `native` methods, GMS, manifest components)
 * are **not** here, because the census cannot see them: they need the bytes and
 * belong to stage 2. `hasNativeCode` in particular is the census's `lib/<abi>/`
 * test, and it is *not sufficient* — see `filterNativePayload`.
 *
 * @param {object} r one survey row
 * @returns {string[]} the reasons it was rejected, empty when it passed
 */
export function poolFilterRejections(r) {
  const why = [];
  if (r.ok !== true) why.push('survey_row_not_ok');
  // Hard filter 1, census-visible half. `straySharedObjects` is the field that
  // catches a native payload outside `lib/`; omitting it is the specific mistake
  // that admits org.bitbucket.watashi564.combapp.
  if (r.hasNativeCode !== false) why.push('has_native_lib');
  if (r.nativeLibraryCount !== 0) why.push('native_library_count');
  if ((r.straySharedObjects ?? []).length > 0) why.push('stray_shared_object');
  // Hard filter 5, and the survey's own structural preconditions. An app with no
  // DEX, no resources.arsc or an unparseable manifest cannot be measured at all.
  if (!(r.dexCount >= 1) || !(r.dexBytes > 0)) why.push('no_dex');
  if (r.resourcesArsc !== true) why.push('no_resources_arsc');
  if (r.manifestStatus !== 'ok') why.push('manifest_unparsed');
  if (typeof r.minSdk !== 'number') why.push('no_min_sdk');
  // Size caps, from the pre-registered exclusion list
  // (docs/research-protocol.md §3.5, "the APK exceeds a size that makes
  // installation exceed the boot-timeout"). Both are stated here so a reader can
  // see they are caps and not measurements.
  if (r.apkBytes > LIMITS.maxApkBytes) why.push('apk_over_cap');
  if (r.dexBytes > LIMITS.maxDexBytes) why.push('dex_over_cap');
  return why;
}

/**
 * How many per-reference lists are stored in a measured row.
 *
 * The **counts** (`distinctAndroidMethods`, `shimMethodsCovered`, …) are always
 * exact; only the enumerated lists are capped, and each carries a
 * `*Truncated` flag. Without a cap, `candidates/negatives.jsonl` is 2.5 MB
 * almost entirely because `se.leap.riseupvpn` references 6,906 framework
 * methods — four rows of evidence do not need 6,906 strings, and a 7 MB
 * committed artefact is a cost every reader pays.
 *
 * The cap is **1024, chosen from the data so that it never binds on the pool**:
 * the largest `distinctAndroidMethods` in the 200 measured rows is 586
 * (`cn.rbc.termuc`) and the largest uncovered count is 512
 * (`com.trianguloy.clipboardeditor`). All four measured negatives exceed it —
 * 2,821 / 3,678 / 3,733 / 6,906 — which is the whole reason the cap exists. A
 * test asserts that no pool row is truncated, so no published figure can depend
 * on a shortened list; if a future pool row does exceed the cap, that test fails
 * and the cap is revisited rather than quietly relied upon.
 */
const LIST_CAP = 1024;
const capList = (xs) => (xs.length > LIST_CAP ? xs.slice(0, LIST_CAP) : xs);

/** Stated, not derived, and printed by `--explain`. */
export const LIMITS = Object.freeze({
  /** 8 MiB. Well under any boot-timeout risk, and it bounds the fetch. */
  maxApkBytes: 8 * 1024 * 1024,
  /** 128 KiB of DEX. "A small app is a small framework surface", made a rule. */
  maxDexBytes: 128 * 1024,
  /** How many pool members stage 2 measures. */
  poolSize: 200,
});

/** Total order. No seed, no randomness, no dependence on file order. */
function cmpPool(a, b) {
  if (a.dexBytes !== b.dexBytes) return a.dexBytes - b.dexBytes;
  if (a.packageName !== b.packageName) return a.packageName < b.packageName ? -1 : 1;
  return a.versionCode - b.versionCode;
}

/** @returns {{pool: object[], rejected: Map<string, number>, survivors: number}} */
export function buildPool(rows) {
  const rejected = new Map();
  const pool = [];
  for (const r of rows) {
    const why = poolFilterRejections(r);
    if (why.length === 0) pool.push(r);
    else for (const w of why) rejected.set(w, (rejected.get(w) ?? 0) + 1);
  }
  pool.sort(cmpPool);
  return { pool, rejected, survivors: rows.length };
}

// =====================================================================
// Stage 2 — measurement. The only stage that needs the network.
// =====================================================================

/**
 * A call site that proves the app puts something in a window.
 *
 * # Read this before trusting any API-usage signal read out of a DEX pool
 *
 * A `method_id`'s owning class is the **compile-time receiver type**, not the
 * class that declares the method. For an inherited call the compiler emits the
 * *subclass*, including the app's own. Two consequences, both of which bit this
 * script before it was correct:
 *
 * 1. `eu.quelltext.gita` calls `setContentView` **twice**, in
 *    `ChapterActivity.onCreate` and `ChooseChaptersActivity.onCreate`, and the
 *    DEX records both as
 *    `invoke-virtual … Leu/quelltext/gita/activities/ChapterActivity;->setContentView(I)V`
 *    — an `L.../...;` owner that is the *app's own package*. A signature
 *    anchored on `^Landroid/` therefore scored this app **0** `setContentView`
 *    sites, and the render gate then rejected an app whose entire job is to
 *    inflate a layout and put it on screen. The ranking still put it first, on
 *    the strength of two `inflate` sites — i.e. it was in the shortlist for the
 *    wrong reason, and the published `setContentView = 0` was false.
 * 2. The same trap in the other direction: `org.debian.eugen.headingcalculator`
 *    wires its keypad with `Landroid/widget/Button;->setOnClickListener(...)`, so
 *    a signature anchored on `Landroid/view/View;` reported **zero** clickable
 *    views for an app that is nothing but buttons.
 *
 * So: **match on the member name, and anchor on the owner class only where the
 * owner cannot be the app's own** — that is, where the class is one the app
 * cannot define because the platform does (`LayoutInflater`, `Canvas`).
 */
const RENDER_SIGNATURES = Object.freeze([
  // Inherited from Activity; the owner is routinely the app's own subclass.
  { key: 'set_content_view', name: 'setContentView' },
  // LayoutInflater.inflate: the app does not define LayoutInflater, so the owner
  // is safe to anchor on and the name `inflate` is too generic not to.
  { key: 'layout_inflate', name: 'inflate', owner: 'Landroid/view/LayoutInflater;' },
  // ditto Canvas.draw*
  { key: 'canvas_draw', name: /^draw[A-Z]/, owner: 'Landroid/graphics/Canvas;' },
]);

/**
 * A call site that proves the app has something a person can press.
 *
 * The protocol's automated procedure sends no input
 * (`docs/research-protocol.md` §4.4), so clickability is not needed for the
 * dependent variable — `L2_FIRST_FRAME_DRAWN` only needs a frame. It matters
 * for a different reason: an app with a pressable control is the one where
 * `SUB.INPUT.INPUT_EVENT` and `SUB.FW.REFLECTION` are *reachable*, so the first
 * real run has something to observe beyond "it drew something". Weighted, not
 * gated, for that reason.
 *
 * `onTouchEvent` and `performClick` are the app's own overrides, so their owner
 * is the app's class by definition — name-only is the correct match, and is the
 * only way to see them at all.
 */
const CLICK_SIGNATURES = Object.freeze([
  { key: 'set_on_click_listener', name: 'setOnClickListener' },
  { key: 'perform_click', name: 'performClick' },
  { key: 'set_on_item_click_listener', name: 'setOnItemClickListener' },
  { key: 'on_touch_event', name: 'onTouchEvent' },
]);

/**
 * Does one `method_id` reference match a signature?
 *
 * The reference form the analyzer emits is
 * `L<pkg>/<Cls>;.member(<args>)<ret>` — a semicolon then a **dot**. The
 * `;->member(...)` spelling is what `dexcore`'s own human-readable dumps use,
 * and both are accepted, because a matcher that only accepts one of them fails
 * *silently* on the other: it returns no matches, every count is 0, and the
 * consequence is a confident "this app has no render call site".
 *
 * @param {string} ref e.g. `Leu/quelltext/gita/activities/ChapterActivity;.setContentView(I)V`
 * @param {{name: string|RegExp, owner?: string}} sig
 */
export function refMatches(ref, sig) {
  const sep = ref.indexOf(';');
  if (sep < 0) return false;
  if (sig.owner !== undefined && !ref.startsWith(sig.owner)) return false;
  let tail = ref.slice(sep + 1);
  if (tail.startsWith('->')) tail = tail.slice(2);
  else if (tail.startsWith('.')) tail = tail.slice(1);
  else return false;
  const paren = tail.indexOf('(');
  const member = paren < 0 ? tail : tail.slice(0, paren);
  if (member === '') return false;
  return sig.name instanceof RegExp ? sig.name.test(member) : member === sig.name;
}

/** Read the predictor's full JSON document for one APK. */
async function predictOne(apkPath) {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const { stdout } = await promisify(execFile)(PREDICT_BIN, [apkPath], {
    maxBuffer: 512 * 1024 * 1024,
  });
  return JSON.parse(stdout);
}

/**
 * Count decoded call-site targets against a signature table.
 *
 * `call_sites_by_target` is keyed by the full `method_id` reference, so this is
 * a per-reference structural match (`Lowner;->member(args)ret`), not a string
 * search: `Landroid/view/View;` must not match `Landroid/view/View$MeasureSpec;`,
 * and `.onDraw` must not match `.onDrawSomethingElse` when `name` is a literal.
 */
function tally(dexScans, signatures) {
  const out = Object.fromEntries(signatures.map((s) => [s.key, 0]));
  for (const s of dexScans) {
    for (const [target, n] of Object.entries(s.call_sites_by_target ?? {})) {
      for (const sig of signatures) if (refMatches(target, sig)) out[sig.key] += n;
    }
  }
  if (Object.values(out).some((v) => !Number.isFinite(v))) {
    throw new Error(`call-site tally produced a non-finite count: ${JSON.stringify(out)}`);
  }
  return out;
}

const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);

/** Binary-XML magic: `ResChunk_header` type 0x0003 (`RES_XML_TYPE`). */
const RES_XML_TYPE = 0x0003;

/**
 * Find every `android:onClick` binding in the APK's compiled layouts.
 *
 * **Bounded, and the bound is reported.** Layout files are AXML like the
 * manifest, and resource-name obfuscation means they cannot be found by path —
 * `org.vi_server.red_screen`'s only layout is `res/01.xml`, and
 * `org.debian.eugen.headingcalculator`'s is `res/Qc.xml`. So every entry is
 * tested for the AXML magic and parsed if it has it. An entry that is not AXML,
 * or that fails to parse, is counted in `unreadable` rather than assumed clean.
 *
 * @returns {{bindings: Array<{entry: string, view: string, handler: string}>, scanned: number, unreadable: number}}
 */
export function scanLayoutOnclick(buf, entries, { maxEntries = 4096 } = {}) {
  const bindings = [];
  let scanned = 0;
  let unreadable = 0;
  for (const e of entries) {
    if (e.isDirectory || !e.name.endsWith('.xml')) continue;
    if (scanned >= maxEntries) break;
    let data;
    try {
      data = readEntry(buf, e);
    } catch {
      unreadable++;
      continue;
    }
    if (data.length < 8 || data.readUInt16LE(0) !== RES_XML_TYPE) continue;
    scanned++;
    try {
      for (const b of onclickBindings(parseAxml(data))) {
        bindings.push({ entry: e.name, view: b.view, handler: b.handler });
      }
    } catch {
      unreadable++;
    }
  }
  bindings.sort((a, b) =>
    a.entry === b.entry ? a.handler.localeCompare(b.handler) : a.entry.localeCompare(b.entry));
  return { bindings, scanned, unreadable };
}

async function download(url, dest, expectedBytes, retries = 3) {
  const tmp = dest + '.part';
  for (let attempt = 0; attempt < retries; attempt++) {
    try {
      const res = await fetch(url, { redirect: 'follow' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      await pipeline(Readable.fromWeb(res.body), createWriteStream(tmp));
      const bytes = (await stat(tmp)).size;
      // The index's size is a free integrity check: it is a second, independent
      // statement that the bytes are the right ones, available before hashing.
      if (expectedBytes != null && bytes !== expectedBytes) {
        throw new Error(`fetched ${bytes} bytes, index says ${expectedBytes}`);
      }
      await rename(tmp, dest);
      return bytes;
    } catch (e) {
      await rm(tmp, { force: true });
      if (attempt === retries - 1) throw e;
      await new Promise((r) => setTimeout(r, 700 * (attempt + 1)));
    }
  }
  throw new Error('unreachable');
}

/**
 * Stage 2 for one APK: hash it, look at the archive, look at the manifest, and
 * ask the predictor about the DEX.
 */
export async function measureApk(row, apkPath, { shim, taxonomy }) {
  const buf = await readFile(apkPath);
  const sha256 = createHash('sha256').update(buf).digest('hex');
  const { entries } = readApk(buf);
  const manifest = readManifest(buf, entries);
  const ms = manifest ? manifest.summary : null;

  const soAnywhere = sharedObjectEntries(entries);
  const lib = libEntries(entries);
  const elf = sniffElf(buf, entries);

  // `android:onClick` bindings across every compiled layout. The framework
  // resolves these reflectively, so they are invisible in the app's own DEX.
  const layoutScan = scanLayoutOnclick(buf, entries);

  const pred = await predictOne(apkPath);
  const F = pred.facts;

  // --- the distinct framework surface, from the DEX pools -----------------
  const referencedTypes = new Set();
  const externalTypes = new Set();
  const referencedMethods = new Set();
  const referencedFields = new Set();
  for (const s of F.dex_scans) {
    for (const t of s.referenced_types) referencedTypes.add(t);
    for (const t of s.external_types) externalTypes.add(t);
    for (const m of s.referenced_methods) referencedMethods.add(m);
    for (const m of s.referenced_fields) referencedFields.add(m);
  }
  const androidTypes = [...referencedTypes].filter((t) => t.startsWith('Landroid/')).sort();
  const androidMethods = [...referencedMethods].filter((m) => m.startsWith('Landroid/')).sort();
  const androidFields = [...referencedFields].filter((m) => m.startsWith('Landroid/')).sort();

  // --- shim coverage, by class and by member name -------------------------
  //
  // Two readings, because "is this method implemented?" has two honest answers
  // and reporting only the pessimistic one understates every candidate.
  //
  // * `shimMethodsCovered` — the shim declares `(exact class, method name)`.
  //   This is the conservative number and the one the score uses.
  // * `shimMethodNamesCovered` — the shim declares *a* method with this name on
  //   *some* class. It over-counts, because two unrelated classes can share a
  //   name.
  //
  // The gap between them is not noise. `eu.quelltext.gita` calls
  // `findViewById` through its own `ChapterActivity`, so the DEX records the
  // owner as `Leu/quelltext/gita/activities/ChapterActivity;` and the exact
  // match fails — but the shim *does* implement
  // `Landroid/app/Activity;.findViewById(I)Landroid/view/View;`. Resolving the
  // app's own inheritance chain would settle it; that needs the DEX class
  // hierarchy, which this script does not read. So the exact figure is
  // reported as the headline and the name-level figure beside it, and the
  // difference is stated rather than quietly averaged away.
  const typesCovered = androidTypes.filter((t) => shim.classes.has(t));
  const shimMethodNames = new Set();
  for (const names of shim.methodNamesByClass.values()) for (const n of names) shimMethodNames.add(n);
  let methodsCovered = 0;
  let methodNamesCovered = 0;
  const uncoveredMethods = [];
  const coveredByNameOnly = [];
  for (const ref of androidMethods) {
    const p = splitMethodRef(ref);
    if (!p) continue;
    const names = shim.methodNamesByClass.get(p.cls);
    const exact = names ? names.has(p.name) : false;
    if (exact) methodsCovered++;
    else uncoveredMethods.push(`${p.cls}.${p.name}`);
    if (shimMethodNames.has(p.name)) methodNamesCovered++;
    else if (!exact) coveredByNameOnly.push(`${p.cls}.${p.name}`);
  }
  let fieldsCovered = 0;
  for (const ref of androidFields) {
    const p = splitFieldRef(ref);
    const names = p && shim.fieldNamesByClass.get(p.cls);
    if (names && names.has(p.name)) fieldsCovered++;
  }

  // --- render and click evidence ------------------------------------------
  // Both accumulators are built *from* their signature tables rather than
  // written out separately. Written separately, the two key spellings drifted
  // once and every count became `NaN`, which `JSON.stringify` turns into
  // `null` — so the whole pool was rejected for "no render call site" with a
  // confident-looking number. Deriving one from the other makes that
  // impossible, and the finiteness check makes the next variant of it loud.
  const render = tally(F.dex_scans, RENDER_SIGNATURES);
  const click = tally(F.dex_scans, CLICK_SIGNATURES);
  const renderCallSites = sum(render);
  const clickCallSites = sum(click);

  // Calls made through the app's *own* class as the receiver type.
  //
  // `androidMethods` counts only references owned by an `Landroid/` class, so an
  // inherited framework method called through an app subclass is not counted at
  // all: `eu.quelltext.gita`'s two `setContentView` calls are both recorded as
  // `Leu/quelltext/gita/activities/ChapterActivity;.setContentView(I)V`.
  // Attributing them properly needs the DEX class hierarchy to know that
  // `ChapterActivity` extends `Activity`, which this script does not read. So
  // the members involved are enumerated here instead, which is enough to judge
  // whether the gap matters for a given candidate — and for gita it does not,
  // because the two members are `setContentView` (implemented by the shim) and
  // nothing else.
  const appPrefix = `L${row.packageName.replace(/\./g, '/')}/`;
  const appOwned = new Map();
  for (const s of F.dex_scans) {
    for (const [target, n] of Object.entries(s.call_sites_by_target ?? {})) {
      if (!target.startsWith(appPrefix)) continue;
      const sep = target.indexOf(';');
      const rest = target.slice(sep + 1);
      const arrow = rest.indexOf('->');
      const tail = (arrow >= 0 ? rest.slice(arrow + 2) : rest).replace(/^\./, '');
      const paren = tail.indexOf('(');
      appOwned.set(paren < 0 ? tail : tail.slice(0, paren), (appOwned.get(paren < 0 ? tail : tail.slice(0, paren)) ?? 0) + n);
    }
  }
  // Code-unit order, not `localeCompare`: collation is locale-dependent, so a
  // `localeCompare` sort makes the committed file's byte order depend on the
  // machine that produced it. `amirz.dngprocessor` caught this — `<init>` and
  // `$ctor` collate differently from their code-unit order.
  const appOwnedCallSiteMembers = [...appOwned]
    .map(([member, n]) => ({ member, callSites: n }))
    .sort((a, b) => (a.member < b.member ? -1 : a.member > b.member ? 1 : 0));

  // --- taxonomy -----------------------------------------------------------
  const taxIds = [...new Set(F.taxonomy_hits.map((h) => h.id))].sort();
  const taxWeighted = taxIds.reduce((a, id) => a + taxonomyWeight(taxonomy.get(id)), 0);
  const taxByClass = { REFUSE: [], MISBEHAVE: [], DEGRADE: [] };
  for (const id of taxIds) {
    const e = taxonomy.get(id);
    if (!e) continue;
    for (const c of e.classes) if (taxByClass[c]) taxByClass[c].push(id);
  }

  return {
    packageName: row.packageName,
    versionCode: row.versionCode,
    apkName: row.apkName,
    apkUrl: row.apkUrl,
    apkBytes: buf.length,
    sha256,
    census: {
      dexBytes: row.dexBytes,
      dexCount: row.dexCount,
      minSdk: row.minSdk,
      targetSdk: row.targetSdk,
      apkBytesIndex: row.apkBytes,
      hasNativeCode: row.hasNativeCode,
      straySharedObjects: row.straySharedObjects ?? [],
    },
    archive: {
      entryCount: entries.length,
      dexEntries: dexEntries(entries),
      soAnywhere: soAnywhere.length,
      soAnywhereNames: soAnywhere.slice(0, 8),
      libEntries: lib.length,
      elfPayloads: elf.found.length,
      elfPayloadNames: elf.found.slice(0, 8),
      elfSniffScanned: elf.scanned,
      elfSniffSkipped: elf.skipped,
      elfSniffBudgetExhausted: elf.budgetExhausted,
      layoutXmlEntriesScanned: layoutScan.scanned,
      layoutXmlEntriesUnreadable: layoutScan.unreadable,
      layoutOnclickBindings: layoutScan.bindings,
    },
    manifest: ms
      ? {
          packageName: ms.packageName,
          minSdk: ms.usesSdk?.min ?? null,
          targetSdk: ms.usesSdk?.target ?? null,
          counts: ms.counts,
          totalComponents: ms.totalComponents,
          backgroundComponents: ms.backgroundComponents,
          launchers: ms.launcherActivities,
          launcherCount: ms.launcherActivities.length,
          permissions: ms.permissions,
        }
      : null,
    dex: {
      analysable: F.analysable,
      classes: F.classes,
      methods: F.methods_declared,
      fields: F.fields_declared,
      methodsWithCode: F.code.methods_with_code,
      methodsUndecodable: F.code.methods_undecodable,
      instructionsDecoded: F.code.instructions_decoded,
      dexVersions: F.code.dex_versions,
      distinctTypes: referencedTypes.size,
      distinctAndroidTypes: androidTypes.length,
      androidTypes,
      androidMethodsTruncated: androidMethods.length > LIST_CAP,
      androidMethods: capList(androidMethods),
      distinctAndroidMethods: androidMethods.length,
      uncoveredAndroidMethodsTruncated: uncoveredMethods.length > LIST_CAP,
      uncoveredAndroidMethods: capList(uncoveredMethods),
      distinctAndroidFields: androidFields.length,
      androidFieldsTruncated: androidFields.length > LIST_CAP,
      androidFields: capList(androidFields),
      shimTypesCovered: typesCovered.length,
      shimMethodsCovered: methodsCovered,
      shimMethodNamesCovered: methodNamesCovered,
      shimFieldsCovered: fieldsCovered,
      reflectionCallSites: F.code.reflection_call_site_total,
      reflectiveMembers: F.code.reflective_members.length,
      invokePolymorphic: F.code.invoke.invoke_polymorphic,
      invokeCustom: F.code.invoke.invoke_custom,
      constMethodHandle: F.code.invoke.const_method_handle,
      constMethodType: F.code.invoke.const_method_type,
      nativeMethods: F.native.native_declarations.length,
      nativeMethodsUnimplemented: F.native.native_declarations_unimplemented.length,
      loadLibraryCallSites: F.native.load_library_calls.length,
      loadLibraryNames: F.native.load_library_names,
      playServicesClasses: F.trust.play_services_classes.length,
      playIntegrityApiClasses: F.trust.play_integrity_api_classes.length,
      licensingClasses: F.trust.licensing_classes.length,
      integrityLiterals: F.trust.integrity_literals.length,
      drmLiterals: F.trust.drm_literals.length,
      firebaseClasses: F.trust.firebase_classes.length,
      buildFieldReads: F.build.total_reads,
      buildFieldNames: F.build.field_names_read,
      dynamicCodeClasses: F.code.dynamic_code_classes,
      render,
      renderCallSites,
      click,
      clickCallSites,
      appOwnedCallSiteMembers,
    },
    taxonomy: {
      ids: taxIds,
      weighted: taxWeighted,
      byClass: taxByClass,
      predictorBand: pred.prediction.band,
      predictorScore: pred.prediction.score_0_100,
      predictorGates: pred.prediction.gates.map((g) => g.gate),
    },
  };
}

// =====================================================================
// Stage 3 — the gates, then the ranking. Both pure.
// =====================================================================

/**
 * The archive-level hard filters. Each returns its reasons; empty means passed.
 *
 * Exported and pure so `analysis/tests/` can feed it hand-built cases — including
 * the real `combapp` row — without downloading anything.
 *
 * @param {object} m one measured row
 * @returns {string[]} rejection reasons
 */
export function measuredFilterRejections(m) {
  const why = [];
  const a = m.archive ?? {};
  const d = m.dex ?? {};
  const mf = m.manifest ?? null;

  // Hard filter 1: pure DEX. Two independent tests, because they disagree in the
  // corpus: the name test (`.so` anywhere) and the content test (ELF magic
  // anywhere). Either failing is disqualifying.
  if ((a.soAnywhere ?? 0) > 0) why.push('so_entry_anywhere');
  if ((a.elfPayloads ?? 0) > 0) why.push('elf_payload_anywhere');
  if ((a.libEntries ?? 0) > 0) why.push('lib_entry');
  // A truncated sniff is `unknown`, never clean.
  if (a.elfSniffBudgetExhausted === true) why.push('elf_sniff_budget_exhausted');

  // Hard filter 2: no native methods, no loadLibrary call sites.
  if ((d.nativeMethods ?? 0) > 0) why.push('native_method_declared');
  if ((d.nativeMethodsUnimplemented ?? 0) > 0) why.push('native_method_unimplemented');
  if ((d.loadLibraryCallSites ?? 0) > 0) why.push('load_library_call_site');

  // Hard filter 3: Play Services / Integrity / DRM / licensing. Excluded from
  // scoring per the protocol rather than counted as failures.
  if ((d.playServicesClasses ?? 0) > 0) why.push('play_services');
  if ((d.playIntegrityApiClasses ?? 0) > 0) why.push('play_integrity_api');
  if ((d.licensingClasses ?? 0) > 0) why.push('licensing');
  if ((d.integrityLiterals ?? 0) > 0) why.push('integrity_literal');
  if ((d.drmLiterals ?? 0) > 0) why.push('drm_literal');

  // Hard filter 4: no known blocker opcodes.
  if ((d.invokePolymorphic ?? 0) > 0) why.push('invoke_polymorphic');
  if ((d.invokeCustom ?? 0) > 0) why.push('invoke_custom');
  if ((d.constMethodHandle ?? 0) > 0) why.push('const_method_handle');

  // Hard filter 7: an Activity-only app, if one exists. A background component
  // is a large surface cost (SUB.IPC.BROADCAST, SUB.PWR.BOOT_COMPLETED,
  // SUB.IPC.SERVICE_MANAGER) for no benefit in a first subject.
  if (!mf) why.push('no_manifest');
  else {
    if (mf.launcherCount < 1) why.push('no_launcher_activity');
    if (mf.counts.service > 0) why.push('declares_service');
    if (mf.counts.receiver > 0) why.push('declares_receiver');
    if (mf.counts.provider > 0) why.push('declares_provider');
  }

  // The dependent variable: without a render call site there is no first frame
  // and therefore no L2 observation, whatever else the app is.
  if ((d.renderCallSites ?? 0) < 1) why.push('no_render_call_site');

  // A dynamic class loader is a substrate dependency with no cheap answer.
  if ((d.dynamicCodeClasses ?? []).length > 0) why.push('dynamic_code_loader');

  // WebView is a gate, and only WebView. The taxonomy classes `SUB.FW.WEBVIEW`
  // as REFUSE — "hybrid apps lose their entire UI" — and the first frame of
  // such an app is drawn by a component the substrate may not have at all.
  // `org.asafonov.blockbuster` ranked **2nd** before this gate existed, with
  // only 6 distinct `android.*` types, because it outsources its entire UI to
  // `WebView.loadUrl("file:///android_asset/index.html")` and touches almost no
  // framework itself. That is the failure mode of any surface-size metric: an
  // app that delegates its work to a component the substrate lacks looks
  // *small*.
  //
  // Deliberately **not** a general "no REFUSE-class taxonomy hit" gate. 63 of
  // the 75 then-eligible apps trip at least one, most often
  // `SUB.INPUT.INPUT_EVENT` — which is REFUSE for apps with pointer input, but
  // the protocol's automated cold launch sends none
  // (`docs/research-protocol.md` §4.4: `lifecycle.first_input_delivered`,
  // "normally unobserved"). Gating on it would exclude a third of the pool for
  // a risk that cannot occur in the measurement.
  if ((m.taxonomy?.ids ?? []).includes('SUB.FW.WEBVIEW')) why.push('webview_content_dependency');

  // The next three are *launch-path* gates. Each one was added because the
  // candidate it excludes put something between `onCreate` and the first frame
  // that the substrate either cannot do or does silently, and in every case the
  // DEX signals said the app was clean. All three are hand-verified against the
  // real bytes; the exclusions are named in `candidates.md` §"Launch-path gates".
  //
  // 1. A text field. The taxonomy's own rows tie this to *having* a text field
  //    rather than to calling the IME: `SUB.INPUT.IME` is REFUSE because
  //    "**every app with a text field is unusable**", and `SUB.IPC.WINDOW_MANAGER`
  //    is "REFUSE (for any app with a text field)" — "soft keyboard never
  //    appears … usually the first visible break". Keying on the taxonomy *ID*
  //    instead was tried first and is wrong: it needs the app to reference
  //    `InputMethodManager`, and `dudeofx.eval` — whose layout is
  //    `LinearLayout > ListView + LinearLayout > EditText[requestFocus]`, so the
  //    first thing it does is summon a keyboard — has no `SUB.INPUT.IME` hit and
  //    sailed through the gate. The taxonomy ID is kept as a second trigger for
  //    an app that reaches the IME without an `EditText`.
  const types = new Set(d.androidTypes ?? []);
  if (TEXT_FIELD_TYPES.some((t) => types.has(t)) || (m.taxonomy?.ids ?? []).includes('SUB.INPUT.IME')) {
    why.push('text_field_on_launch_path');
  }

  // 2. `android:onClick` in a layout — resolved by `LayoutInflater` via
  //    `getMethod`, i.e. reflective dispatch *in the framework*, so the app's own
  //    DEX shows zero reflective call sites. `com.tmendes.dadosd` reports
  //    `reflection_call_sites = 0` and binds three of them.
  if ((a.layoutOnclickBindings ?? []).length > 0) why.push('layout_onclick_reflective_dispatch');

  // 3. A special-access permission. `docs/research-protocol.md` §3.5 already
  //    excludes "a launcher/keyboard (requires a role we do not grant)"; an app
  //    that needs a user-granted overlay or wake-lock permission is the same
  //    category. `org.vi_server.red_screen` declares SYSTEM_ALERT_WINDOW and
  //    spends its whole `onCreate` on `WindowManager$LayoutParams` (brightness,
  //    `type = 2010` = TYPE_SYSTEM_ERROR) and a `PowerManager` wake lock.
  const perms = new Set(mf?.permissions ?? []);
  for (const p of SPECIAL_PERMISSIONS) if (perms.has(p)) why.push(`special_permission:${p}`);

  if (d.analysable === false) why.push('unanalysable_dex');
  return why;
}

/** Permissions a substrate cannot be granted, per protocol §3.5's exclusion shape. */
export const SPECIAL_PERMISSIONS = Object.freeze([
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.WAKE_LOCK',
  'android.permission.BIND_INPUT_METHOD',
  'android.permission.BIND_DEVICE_ADMIN',
  'android.permission.MANAGE_OVERLAY_PERMISSION',
]);

/**
 * A referenced type that means "this app has a text field", which the taxonomy
 * makes a REFUSE because the soft keyboard cannot exist in the substrate.
 */
export const TEXT_FIELD_TYPES = Object.freeze([
  'Landroid/widget/EditText;',
  'Landroid/widget/AutoCompleteTextView;',
  'Landroid/widget/MultiAutoCompleteTextView;',
  'Landroid/view/inputmethod/InputMethodManager;',
  'Landroid/view/inputmethod/InputMethod;',
]);

/**
 * The ranking rubric. Every weight is a judgement, stated as one; every
 * saturation is printed by `--explain`; the whole set is pinned by a test.
 *
 * `subscore = min(1, count / saturation)`, `score = Σ weight · subscore`, and
 * **lower is better** — this is a penalty, not the predictor's compatibility
 * score, and the sign is the opposite of `analysis/prediction.md`'s on purpose:
 * that rubric predicts *incompatibility*, this one picks a *subject*.
 *
 * Two of the nine components are not in the brief that set this task, and both
 * are disclosed rather than folded in quietly:
 *
 * - `shim_method_gap` — the number of framework methods an app touches and the
 *   number of those the shim implements are different questions, and only the
 *   second one predicts how much work the first run costs. `S.N.A.K.E` has the
 *   *fewest* distinct `android.*` types in the whole pool (14) and ranks 4th
 *   because 34 of its 40 framework methods have no same-named shim method.
 * - `clickable_view` — added after the first run, which is exactly the
 *   post-hoc adjustment T-09 warns about. It is included because the brief asks
 *   for "an app with a layout and a clickable view", and it changes the answer,
 *   so the ranking **without** it is published alongside: `rank --without
 *   clickable_view`. Read both.
 */
export const RUBRIC = Object.freeze([
  {
    id: 'android_types',
    weight: 0.28,
    saturation: 24,
    unit: 'distinct android.* types referenced',
    why: 'The surface the shim must declare a class for. Primary signal.',
  },
  {
    id: 'android_methods',
    weight: 0.22,
    saturation: 60,
    unit: 'distinct android.* methods referenced',
    why: 'Type coverage is 100% and method coverage is 27.4%; methods are the wall.',
  },
  {
    id: 'taxonomy',
    weight: 0.14,
    saturation: 3,
    unit: 'Σ class-weight over distinct taxonomy IDs hit (REFUSE 1.0 / MISBEHAVE 0.6 / DEGRADE 0.3)',
    why: 'REFUSE costs the measurement; MISBEHAVE is the class worth reaching later.',
  },
  {
    id: 'shim_method_gap',
    weight: 0.15,
    saturation: 1,
    unit: 'fraction of referenced android.* methods with no same-named shim method',
    why: 'Not in the brief. Measures implementation cost, not just surface size.',
  },
  {
    id: 'dex_bytes',
    weight: 0.07,
    saturation: 65536,
    unit: 'compressed DEX bytes',
    why: 'A small app is a small framework surface; also bounds the first run.',
  },
  {
    id: 'dex_methods',
    weight: 0.04,
    saturation: 400,
    unit: 'methods declared in the DEX',
    why: 'Code the interpreter must be able to execute before anything renders.',
  },
  {
    id: 'clickable_view',
    weight: 0.07,
    saturation: 2,
    unit: 'decoded click-handler call sites (setOnClickListener / performClick / setOnItemClickListener / onTouchEvent)',
    why: 'Not in the brief as a component. The brief asks for a clickable view; see `--without`.',
  },
  {
    id: 'reflection',
    weight: 0.02,
    saturation: 8,
    unit: 'decoded reflective call sites',
    why: 'Reflection over an incomplete surface fails quietly; count it, weight it little.',
  },
  {
    id: 'components',
    weight: 0.01,
    saturation: 8,
    unit: 'manifest components declared',
    why: 'Almost decided already by the Activity-only filter; kept for the count.',
  },
]);

/** The rubric's weights sum to exactly 1. Asserted in the tests. */
export function rubricWeightSum(rubric = RUBRIC) {
  return rubric.reduce((a, c) => a + c.weight, 0);
}

/** The raw count behind each component, for one measured row. */
export function scoreComponents(m) {
  const d = m.dex;
  const methods = d.distinctAndroidMethods || 0;
  const gap = methods === 0 ? 1 : (methods - d.shimMethodsCovered) / methods;
  return {
    android_types: d.distinctAndroidTypes,
    android_methods: methods,
    taxonomy: m.taxonomy.weighted,
    shim_method_gap: gap,
    dex_bytes: m.census.dexBytes,
    dex_methods: d.methods,
    clickable_view: d.clickCallSites,
    reflection: d.reflectionCallSites,
    components: m.manifest ? m.manifest.totalComponents : 0,
  };
}

/** @returns {{score: number, components: Array<object>}} `score` is a penalty in [0,1]. */
export function scoreCandidate(m, rubric = RUBRIC) {
  const counts = scoreComponents(m);
  const components = rubric.map((spec) => {
    const n = counts[spec.id];
    if (n === undefined) throw new Error(`rubric component ${spec.id} has no count for ${m.packageName}`);
    const subscore = Math.min(1, n / spec.saturation);
    return {
      id: spec.id,
      weight: spec.weight,
      count: n,
      saturation: spec.saturation,
      subscore,
      contribution: spec.weight * subscore,
    };
  });
  const score = components.reduce((a, c) => a + c.contribution, 0);
  return { score, components };
}

/** Total order. No randomness; `packageName` last so the sort can never tie. */
export function cmpRanked(a, b) {
  if (a.score !== b.score) return a.score - b.score;
  if (a.measured.dex.distinctAndroidTypes !== b.measured.dex.distinctAndroidTypes) {
    return a.measured.dex.distinctAndroidTypes - b.measured.dex.distinctAndroidTypes;
  }
  if (a.measured.dex.distinctAndroidMethods !== b.measured.dex.distinctAndroidMethods) {
    return a.measured.dex.distinctAndroidMethods - b.measured.dex.distinctAndroidMethods;
  }
  if (a.measured.census.dexBytes !== b.measured.census.dexBytes) {
    return a.measured.census.dexBytes - b.measured.census.dexBytes;
  }
  if (a.measured.packageName !== b.measured.packageName) {
    return a.measured.packageName < b.measured.packageName ? -1 : 1;
  }
  return a.measured.versionCode - b.measured.versionCode;
}

/**
 * The shortlist. Gates first (pass/fail, no score), then the penalty score.
 *
 * @param {object[]} measuredRows
 * @param {object[]} [rubric] defaults to `RUBRIC`
 * @returns {{eligible: object[], rejected: Array<{packageName: string, reasons: string[]}>, gateHistogram: Map<string, number>}}
 */
export function buildShortlist(measuredRows, rubric = RUBRIC) {
  const eligible = [];
  const rejected = [];
  const gateHistogram = new Map();
  const byPackage = (a, b) => cmpPool({ ...a.census, packageName: a.packageName, versionCode: a.versionCode },
                                      { ...b.census, packageName: b.packageName, versionCode: b.versionCode });
  for (const m of [...measuredRows].sort(byPackage)) {
    const why = measuredFilterRejections(m);
    if (why.length > 0) {
      rejected.push({ packageName: m.packageName, versionCode: m.versionCode, reasons: why });
      for (const w of why) gateHistogram.set(w, (gateHistogram.get(w) ?? 0) + 1);
      continue;
    }
    const { score, components } = scoreCandidate(m, rubric);
    eligible.push({ measured: m, score, components });
  }
  eligible.sort(cmpRanked);
  return { eligible, rejected, gateHistogram };
}

/** `RUBRIC` minus the named components, for publishing the counterfactual. */
export function withoutComponents(ids) {
  const drop = new Set(ids);
  const rest = RUBRIC.filter((c) => !drop.has(c.id));
  const total = rest.reduce((a, c) => a + c.weight, 0);
  if (total <= 0) throw new Error('withoutComponents removed every component');
  return rest.map((c) => ({ ...c, weight: c.weight / total }));
}

// =====================================================================
// CLI
// =====================================================================

function fmt(n) {
  return typeof n === 'number' ? n.toLocaleString('en-US') : String(n);
}

function readJsonl(file) {
  return readFile(file, 'utf8')
    .then((t) => t.split('\n').filter(Boolean).map((l) => JSON.parse(l)));
}

async function cmdPool() {
  const rows = await readJsonl(SURVEY);
  const { pool, rejected, survivors } = buildPool(rows);
  const take = pool.slice(0, LIMITS.poolSize);
  const bytes = take.reduce((a, r) => a + r.apkBytes, 0);
  console.log(`survey rows: ${rows.length}`);
  console.log(`rejection reasons (a row can trip several):`);
  for (const [k, v] of [...rejected].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))) {
    console.log(`  ${String(v).padStart(5)}  ${k}`);
  }
  console.log(`pool: ${pool.length} of ${survivors}`);
  console.log(`taking ${take.length} (LIMITS.poolSize), total ${fmt(bytes)} bytes`);
  console.log(`  largest dexBytes in the take: ${fmt(take[take.length - 1].dexBytes)}`);
}

async function cmdMeasure(args) {
  const cache = args.cache ?? DEFAULT_CACHE;
  const rows = await readJsonl(SURVEY);
  const { pool } = buildPool(rows);
  const take = pool.slice(0, LIMITS.poolSize);
  // `--extra` measures named packages that the pool *excludes*, so the
  // known-bad cases in the tests are real measurements of real bytes rather
  // than hand-written fixtures that can drift from the census. They go to a
  // separate file so the shortlist's inputs stay exactly the pool.
  const extra = (args.extra ?? []).flatMap((name) => {
    const hits = rows.filter((r) => r.packageName === name);
    if (hits.length === 0) throw new Error(`--extra: no survey row for ${name}`);
    return hits;
  });
  const todo = [...take, ...extra];
  const shim = indexSurface(await loadShimSurface());
  const taxonomy = parseTaxonomy(await readFile(TAXONOMY, 'utf8'));
  await mkdir(cache, { recursive: true });
  await mkdir(path.dirname(MEASURED), { recursive: true });
  if (extra.length > 0) await mkdir(path.dirname(NEGATIVES), { recursive: true });

  const have = new Set((await readdir(cache)).filter((f) => f.endsWith('.apk')));
  console.log(`measuring ${todo.length} APKs (${take.length} pool + ${extra.length} extra) into ${cache}`);
  console.log(`  shim surface: ${shim.classes.size} classes; taxonomy: ${taxonomy.size} classified IDs`);

  const out = [];
  for (const [i, row] of todo.entries()) {
    const dest = path.join(cache, row.apkName);
    try {
      if (!have.has(row.apkName)) await download(row.apkUrl, dest, row.apkBytes);
      const m = await measureApk(row, dest, { shim, taxonomy });
      out.push(m);
      const why = measuredFilterRejections(m);
      const where = extra.some((e) => e.packageName === row.packageName) && !take.includes(row) ? ' (extra)' : '';
      console.log(
        `  ${String(i + 1).padStart(3)}/${todo.length} ${row.packageName.padEnd(46)}${where}` +
          ` types=${String(m.dex.distinctAndroidTypes).padStart(3)} ` +
          `meth=${String(m.dex.distinctAndroidMethods).padStart(4)} ` +
          `shimGap=${m.dex.distinctAndroidMethods - m.dex.shimMethodsCovered}/${m.dex.distinctAndroidMethods} ` +
          `render=${m.dex.renderCallSites} ` +
          (why.length === 0 ? 'PASS' : `reject:${why.join(',')}`),
      );
    } catch (e) {
      console.error(`  ${String(i + 1).padStart(3)}/${todo.length} ${row.packageName} FAILED: ${e.message}`);
      out.push({ packageName: row.packageName, versionCode: row.versionCode, error: String(e.message) });
    }
  }
  const byPackage = (a, b) => (a.packageName < b.packageName ? -1 : a.packageName > b.packageName ? 1 : 0);
  const poolNames = new Set(take.map((r) => r.packageName));
  out.filter((r) => poolNames.has(r.packageName)).sort(byPackage);
  await writeFile(
    MEASURED,
    out.filter((r) => poolNames.has(r.packageName)).sort(byPackage).map((r) => JSON.stringify(r)).join('\n') + '\n',
  );
  console.log(`wrote ${MEASURED}`);
  if (extra.length > 0) {
    await writeFile(
      NEGATIVES,
      out.filter((r) => !poolNames.has(r.packageName)).sort(byPackage).map((r) => JSON.stringify(r)).join('\n') + '\n',
    );
    console.log(`wrote ${NEGATIVES}`);
  }
}

/**
 * Render the `rank` report.
 *
 * Pure, and it *returns* the text rather than printing it, so the test suite can
 * assert that two runs produce byte-identical output without shelling out and
 * diffing. `cmdRank` is the thin wrapper that prints it and sets the exit code.
 *
 * @param {object[]} measured
 * @param {object[]} rubric
 * @param {number} top
 * @param {boolean} explain
 * @returns {string}
 */
export function rankOutput(measured, rubric, top, explain, without = []) {
  const out = [];
  const w = (s = '') => out.push(s);
  const incomplete = measured.filter((m) => m.error || !m.dex);
  if (incomplete.length > 0) {
    return `refusing to rank: ${incomplete.length} of ${measured.length} measured rows are incomplete ` +
      `(${incomplete.map((b) => b.packageName).join(', ')}). Re-run "measure".\n`;
  }
  const { eligible, rejected, gateHistogram } = buildShortlist(measured, rubric);
  if (eligible.length === 0) return 'no eligible candidates\n';
  if (without.length) w(`rubric: RUBRIC without [${without.join(', ')}], weights renormalised`);
  w(`measured: ${measured.length}`);
  w(`rejected by archive-level filters: ${rejected.length}`);
  for (const [k, n] of [...gateHistogram].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))) {
    w(`  ${String(n).padStart(4)}  ${k}`);
  }
  w(`eligible: ${eligible.length}`);
  w('');
  const head = ['#', 'package', 'ver', 'score', 'aTypes', 'aMeth', 'shimGap', 'dexB', 'meths', 'click', 'refl', 'cmp', 'tax'];
  w(head.map((h, i) => (i === 0 ? h.padStart(2) : h.padStart(i === 1 ? -38 : i === 12 ? 12 : 6))).join(' '));
  eligible.slice(0, top).forEach((e, i) => {
    const m = e.measured;
    const d = m.dex;
    w(
      [
        String(i + 1).padStart(2),
        m.packageName.padEnd(38),
        String(m.versionCode).padStart(6),
        e.score.toFixed(4).padStart(6),
        String(d.distinctAndroidTypes).padStart(6),
        String(d.distinctAndroidMethods).padStart(6),
        `${d.distinctAndroidMethods - d.shimMethodsCovered}/${d.distinctAndroidMethods}`.padStart(6),
        fmt(m.census.dexBytes).padStart(6),
        String(d.methods).padStart(6),
        String(d.clickCallSites).padStart(6),
        String(d.reflectionCallSites).padStart(4),
        String(m.manifest.totalComponents).padStart(4),
        String(m.taxonomy.ids.length).padStart(12),
      ].join(' '),
    );
  });
  if (explain) {
    w('');
    w('rubric (penalty, lower is better):');
    let sum = 0;
    for (const c of rubric) {
      sum += c.weight;
      w(`  ${c.id.padEnd(18)} weight ${c.weight.toFixed(4)}  saturate ${String(c.saturation).padStart(6)}  ${c.unit}`);
    }
    w(`  weight sum ${sum.toFixed(6)}`);
    w('');
    w('top candidate component breakdown:');
    for (const c of eligible[0].components) {
      w(
        `  ${c.id.padEnd(18)} count ${String(Number(c.count.toFixed(4))).padStart(10)} ` +
          `/ ${String(c.saturation).padStart(6)} = subscore ${c.subscore.toFixed(4)}  ` +
          `× ${c.weight.toFixed(4)} = ${c.contribution.toFixed(4)}`,
      );
    }
    const total = eligible[0].components.reduce((a, c) => a + c.contribution, 0);
    w(`  ${'total'.padEnd(18)} ${total.toFixed(4).padStart(27)}`);
  }
  return out.join('\n') + '\n';
}

async function cmdRank(args) {
  const measured = await readJsonl(MEASURED);
  const rubric = args.without?.length ? withoutComponents(args.without) : RUBRIC;
  const text = rankOutput(measured, rubric, args.top ?? 10, args.explain === true, args.without ?? []);
  process.stdout.write(text);
  if (text.startsWith('refusing to rank') || text.startsWith('no eligible')) process.exitCode = 3;
}

async function cmdVerify(paths) {
  const taxonomy = parseTaxonomy(await readFile(TAXONOMY, 'utf8'));
  const shim = indexSurface(await loadShimSurface());
  const rows = (await readJsonl(SURVEY)).filter((r) => paths.some((p) => p.includes(r.apkName) || p.endsWith(r.packageName)));
  if (rows.length === 0) {
    console.error('no survey row matches the given paths; pass an APK filename or a package name');
    process.exitCode = 2;
    return;
  }
  for (const row of rows) {
    const p = paths.find((x) => x.includes(row.apkName)) ?? paths.find((x) => x.endsWith(row.packageName));
    console.log(`\n=== ${row.packageName} ${row.versionCode} (${row.apkName})`);
    const m = await measureApk(row, p, { shim, taxonomy });
    const why = measuredFilterRejections(m);
    const { score, components } = scoreCandidate(m);
    console.log(`  sha256              ${m.sha256}`);
    console.log(`  bytes               ${fmt(m.apkBytes)} (index says ${fmt(m.census.apkBytesIndex)})`);
    console.log(`  entries             ${m.archive.entryCount}`);
    console.log(`  .so anywhere        ${m.archive.soAnywhere} ${JSON.stringify(m.archive.soAnywhereNames)}`);
    console.log(`  lib/<abi>/ entries  ${m.archive.libEntries}`);
    console.log(`  ELF payloads        ${m.archive.elfPayloads} ${JSON.stringify(m.archive.elfPayloadNames)}`);
    console.log(`  ELF sniff           scanned ${m.archive.elfSniffScanned}, skipped ${m.archive.elfSniffSkipped}, exhausted ${m.archive.elfSniffBudgetExhausted}`);
    console.log(`  dex                 ${m.archive.dexEntries.length} file(s), ${fmt(m.census.dexBytes)} compressed bytes, ${m.dex.methods} methods, ${m.dex.classes} classes`);
    console.log(`  undecodable methods ${m.dex.methodsUndecodable} of ${m.dex.methodsWithCode} with code`);
    console.log(`  native methods      ${m.dex.nativeMethods} (unimplemented ${m.dex.nativeMethodsUnimplemented}), loadLibrary ${m.dex.loadLibraryCallSites}`);
    console.log(`  GMS / integrity     ${m.dex.playServicesClasses} / ${m.dex.playIntegrityApiClasses} / licensing ${m.dex.licensingClasses} / drm ${m.dex.drmLiterals}`);
    console.log(`  dynamic invoke      poly ${m.dex.invokePolymorphic}, custom ${m.dex.invokeCustom}, cmh ${m.dex.constMethodHandle}, cmt ${m.dex.constMethodType}`);
    console.log(`  manifest            ${JSON.stringify(m.manifest.counts)}, launchers ${m.manifest.launcherCount}, minSdk ${m.manifest.minSdk} targetSdk ${m.manifest.targetSdk}`);
    console.log(`  permissions (${m.manifest.permissions.length})    ${m.manifest.permissions.join(' ')}`);
    console.log(`  render call sites   ${m.dex.renderCallSites} = setContentView ${m.dex.render.set_content_view}, inflate ${m.dex.render.layout_inflate}, canvasDraw ${m.dex.render.canvas_draw}`);
    console.log(`  android.* surface   ${m.dex.distinctAndroidTypes} types, ${m.dex.distinctAndroidMethods} methods, ${m.dex.distinctAndroidFields} fields`);
    console.log(`  shim coverage       ${m.dex.shimTypesCovered}/${m.dex.distinctAndroidTypes} types, ${m.dex.shimMethodsCovered}/${m.dex.distinctAndroidMethods} methods, ${m.dex.shimFieldsCovered}/${m.dex.distinctAndroidFields} fields`);
    console.log(`  reflection          ${m.dex.reflectionCallSites} call sites, ${m.dex.reflectiveMembers} distinct members`);
    console.log(`  taxonomy            ${m.taxonomy.ids.length} IDs, weighted ${m.taxonomy.weighted.toFixed(2)}`);
    console.log(`                       REFUSE ${JSON.stringify(m.taxonomy.byClass.REFUSE)}`);
    console.log(`                       MISBEHAVE ${JSON.stringify(m.taxonomy.byClass.MISBEHAVE)}`);
    console.log(`  predictor band      ${m.taxonomy.predictorBand} score ${m.taxonomy.predictorScore.toFixed(1)} gates ${JSON.stringify(m.taxonomy.predictorGates)}`);
    console.log(`  VERDICT             ${why.length === 0 ? 'ELIGIBLE' : 'REJECTED: ' + why.join(', ')}`);
    console.log(`  selection score     ${score.toFixed(4)} (penalty, lower is better)`);
    for (const c of components) {
      console.log(`    ${c.id.padEnd(18)} ${String(Number(c.count.toFixed(4))).padStart(10)} / ${String(c.saturation).padEnd(6)} = ${c.subscore.toFixed(4)} × ${c.weight.toFixed(2)} = ${c.contribution.toFixed(4)}`);
    }
  }
}

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--top') args.top = Number(argv[++i]);
    else if (a.startsWith('--top=')) args.top = Number(a.slice(6));
    else if (a === '--cache') args.cache = argv[++i];
    else if (a.startsWith('--cache=')) args.cache = a.slice(8);
    else if (a === '--explain') args.explain = true;
    else if (a === '--extra') args.extra = (argv[++i] ?? '').split(',').filter(Boolean);
    else if (a.startsWith('--extra=')) args.extra = a.slice(8).split(',').filter(Boolean);
    else if (a === '--without') args.without = (a2 => a2 === true ? [] : a2.split(','))(argv[++i]);
    else if (a.startsWith('--without=')) args.without = a.slice(10).split(',');
    else args._.push(a);
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  if (cmd === 'pool') await cmdPool();
  else if (cmd === 'measure') await cmdMeasure(args);
  else if (cmd === 'rank') await cmdRank(args);
  else if (cmd === 'verify') await cmdVerify(args._.slice(1));
  else if (cmd === 'taxonomy') {
    const t = parseTaxonomy(await readFile(TAXONOMY, 'utf8'));
    console.log(`classified IDs: ${t.size} (expected ${EXPECTED_CLASSIFIED_IDS})`);
    console.log(`by class: ${JSON.stringify(classHistogram(t))}`);
  } else {
    console.error('usage: select-candidates.mjs <pool|measure|rank|verify|taxonomy> [options]');
    process.exitCode = 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error(e);
    process.exitCode = 1;
  });
}
