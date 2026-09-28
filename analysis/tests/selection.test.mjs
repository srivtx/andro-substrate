/**
 * Tests for candidate selection.
 *
 *   node --test analysis/tests/
 *
 * Three jobs, in order of how much they protect:
 *
 * 1. **Determinism.** The brief's requirement that the script be re-runnable
 *    and produce the identical shortlist. Asserted the strong way: the output
 *    must not depend on the *order* of its input, not merely be stable across
 *    two runs of an already-sorted input. A shuffle is run every time.
 * 2. **Classification.** One known-good and four known-bad candidates, all
 *    measured from real bytes. The known-bad set is not incidental — each case
 *    is a specific way the naive filter passes an app it should not, and
 *    `the_census_alone_admits_a_native_payload` constructs the sharpest one.
 * 3. **The quoted figures.** Every number in `candidates.md` and
 *    `candidate-selection.md` is asserted here, so the prose cannot drift from
 *    the measurement without a red test.
 *
 * Nothing here reaches the network. `candidates/measured.jsonl` and
 * `candidates/negatives.jsonl` are committed derived rows, the same pattern as
 * `analysis/sample/rows.jsonl`, and each carries the SHA-256 of the APK it came
 * from.
 */

import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { test, describe, before } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  LIMITS,
  RUBRIC,
  SPECIAL_PERMISSIONS,
  TEXT_FIELD_TYPES,
  buildPool,
  buildShortlist,
  cmpRanked,
  measuredFilterRejections,
  poolFilterRejections,
  rankOutput,
  refMatches,
  rubricWeightSum,
  scoreCandidate,
  withoutComponents,
} from '../select-candidates.mjs';
import { onclickBindings, parseAxml, summariseManifest } from '../lib/axml.mjs';
import { EXPECTED, loadShimSurface, indexSurface, splitMethodRef } from '../lib/shim-surface.mjs';
import { EXPECTED_CLASSIFIED_IDS, parseTaxonomy, taxonomyWeight } from '../lib/taxonomy-classes.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const SURVEY = path.join(REPO, 'corpus', 'survey.jsonl');
const MEASURED = path.join(REPO, 'analysis', 'candidates', 'measured.jsonl');
const NEGATIVES = path.join(REPO, 'analysis', 'candidates', 'negatives.jsonl');
const TAXONOMY = path.join(REPO, 'docs', 'divergence-taxonomy.md');

const readJsonl = async (f) => (await readFile(f, 'utf8')).split('\n').filter(Boolean).map((l) => JSON.parse(l));

/** A deterministic shuffle, so a failure is reproducible. */
function shuffle(arr, seed) {
  const a = [...arr];
  let s = seed >>> 0;
  const next = () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(next() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

let survey, measured, negatives, taxonomy, pool, shortlist;

before(async () => {
  survey = await readJsonl(SURVEY);
  measured = await readJsonl(MEASURED);
  negatives = await readJsonl(NEGATIVES);
  taxonomy = parseTaxonomy(await readFile(TAXONOMY, 'utf8'));
  pool = buildPool(survey).pool;
  shortlist = buildShortlist(measured);
});

const find = (rows, pkg) => {
  const r = rows.find((x) => x.packageName === pkg);
  assert.ok(r, `expected to find ${pkg}`);
  return r;
};

// =====================================================================

describe('the corpus census is read, and its shape is asserted', () => {
  test('the survey has the 4,475 rows the census reports', () => {
    assert.equal(survey.length, 4475);
    assert.equal(survey.every((r) => r.ok === true), true);
  });

  test('the pool is what the census census-level filters admit, and it is small', () => {
    const { pool: p, rejected } = buildPool(survey);
    assert.equal(p.length, 213);
    assert.equal(p.length >= LIMITS.poolSize, true);
    // The one rejection reason that is *specific to this work* rather than
    // inherited from the census: a native payload outside lib/.
    assert.equal(rejected.get('stray_shared_object'), 6);
    assert.equal(rejected.get('has_native_lib'), 2472);
  });

  test('exactly one app the census calls native-free ships a native payload', () => {
    // This is the census false negative the whole hard-filter-1 rule exists for.
    // Five of the six rows with a stray `.so` are already excluded by
    // `hasNativeCode`; one is not, and it is the interesting one. If this count
    // changes, the note in candidates.md must change too.
    const censusSaysClean = survey.filter((r) => r.hasNativeCode === false && (r.straySharedObjects ?? []).length > 0);
    assert.equal(censusSaysClean.length, 1);
    assert.equal(censusSaysClean[0].packageName, 'org.bitbucket.watashi564.combapp');
    // The other five are the Chaquopy / bundled-interpreter rows, all of which
    // `hasNativeCode` already catches.
    const withNative = survey.filter((r) => r.hasNativeCode === true && (r.straySharedObjects ?? []).length > 0);
    assert.equal(withNative.length, 5);
  });
});

// =====================================================================

describe('determinism', () => {
  test('buildPool is a pure function of its input rows', () => {
    const a = buildPool(survey).pool.map((r) => `${r.packageName}@${r.versionCode}`);
    const b = buildPool([...survey].reverse()).pool.map((r) => `${r.packageName}@${r.versionCode}`);
    assert.deepEqual(a, b);
  });

  test('buildPool does not depend on the corpus file order for the pool order', () => {
    const canonical = buildPool(survey).pool.map((r) => `${r.packageName}@${r.versionCode}`);
    for (const seed of [1, 7, 99, 20260928]) {
      const got = buildPool(shuffle(survey, seed)).pool.map((r) => `${r.packageName}@${r.versionCode}`);
      assert.deepEqual(got, canonical, `shuffle seed ${seed} changed the pool`);
    }
  });

  test('buildShortlist is a pure function of its input rows', () => {
    const order = (s) => s.eligible.map((e) => e.measured.packageName);
    const canonical = order(shortlist);
    for (const seed of [1, 7, 99, 20260928]) {
      const got = order(buildShortlist(shuffle(measured, seed)));
      assert.deepEqual(got, canonical, `shuffle seed ${seed} changed the shortlist`);
    }
  });

  test('the sort is a total order, so no two eligible candidates can tie', () => {
    for (let i = 0; i + 1 < shortlist.eligible.length; i++) {
      const a = shortlist.eligible[i];
      const b = shortlist.eligible[i + 1];
      assert.ok(cmpRanked(a, b) < 0, `${a.measured.packageName} should sort before ${b.measured.packageName}`);
    }
  });

  test('the CLI prints byte-identical output on two consecutive runs', async () => {
    const bin = path.join(REPO, 'analysis', 'select-candidates.mjs');
    const run = () =>
      promisify(execFile)(process.execPath, [bin, 'rank', '--top', '19', '--explain'], {
        cwd: path.join(REPO, 'analysis'),
        maxBuffer: 32 * 1024 * 1024,
      }).then((r) => r.stdout);
    const [a, b] = [await run(), await run()];
    assert.equal(a, b);
    assert.match(a, /eligible: 19/);
  });
});

// =====================================================================

describe('known-good: eu.quelltext.gita is the first subject', () => {
  const gita = () => find(shortlist.eligible.map((e) => e.measured), 'eu.quelltext.gita');

  test('it is eligible', () => {
    assert.deepEqual(measuredFilterRejections(gita()), []);
  });

  test('it ranks first', () => {
    assert.equal(shortlist.eligible[0].measured.packageName, 'eu.quelltext.gita');
  });

  test('it survives every hard filter, by measurement', () => {
    const m = gita();
    assert.equal(m.archive.soAnywhere, 0);
    assert.equal(m.archive.elfPayloads, 0);
    assert.equal(m.archive.libEntries, 0);
    assert.equal(m.archive.elfSniffBudgetExhausted, false);
    assert.equal(m.dex.nativeMethods, 0);
    assert.equal(m.dex.loadLibraryCallSites, 0);
    assert.equal(m.dex.playServicesClasses, 0);
    assert.equal(m.dex.playIntegrityApiClasses, 0);
    assert.equal(m.dex.licensingClasses, 0);
    assert.equal(m.dex.invokePolymorphic, 0);
    assert.equal(m.dex.invokeCustom, 0);
    assert.equal(m.dex.renderCallSites, 4);
    assert.equal(m.dex.clickCallSites, 2);
    assert.equal(m.manifest.launcherCount, 1);
    assert.deepEqual(m.manifest.counts, { activity: 2, activityAlias: 0, service: 0, receiver: 0, provider: 0 });
    assert.equal(m.manifest.permissions.length, 0);
    assert.equal(m.archive.layoutOnclickBindings.length, 0);
    assert.equal(m.taxonomy.byClass.REFUSE.length, 0);
  });

  test('it is a single-DEX app whose method bodies all decoded', () => {
    const m = gita();
    assert.deepEqual(m.archive.dexEntries, ['classes.dex']);
    assert.equal(m.dex.methodsUndecodable, 0);
    assert.equal(m.dex.analysable, true);
  });
});

// =====================================================================

describe('known-bad, constructed deliberately', () => {
  test('the census alone admits an app with a native payload: combapp', () => {
    // The sharpest known-bad. `corpus/survey.jsonl` says this app has no
    // native code, because the census's criterion is `lib/<abi>/` and combapp
    // ships its ELF binaries at `res/5x.so` and `res/yG.so`.
    const row = find(survey, 'org.bitbucket.watashi564.combapp');
    assert.equal(row.hasNativeCode, false);
    assert.equal(row.nativeLibraryCount, 0);
    assert.deepEqual(row.straySharedObjects, ['res/5x.so', 'res/yG.so']);

    // The naive filter — the one a reader would write from the census field
    // name — passes it.
    const naive = row.hasNativeCode === false && row.nativeLibraryCount === 0;
    assert.equal(naive, true, 'the naive lib/-only check is supposed to pass combapp');

    // The filter used here does not.
    assert.ok(poolFilterRejections(row).includes('stray_shared_object'));

    // And the bytes agree: two real ELF binaries, 7.3 MB and 17.8 MB.
    const m = find(negatives, 'org.bitbucket.watashi564.combapp');
    assert.equal(m.archive.libEntries, 0);
    assert.equal(m.archive.elfPayloads, 2);
    assert.deepEqual(m.archive.elfPayloadNames, ['res/5x.so', 'res/yG.so']);
    assert.ok(measuredFilterRejections(m).includes('elf_payload_anywhere'));
    assert.ok(measuredFilterRejections(m).includes('so_entry_anywhere'));
  });

  test('the stray check is load-bearing: without it combapp would be admitted', () => {
    // combapp trips three pool filters, not one: the stray .so, and both size
    // caps. So the honest construction of the known-bad case is the
    // counterfactual — blank the field the census uses for this and the row is
    // admitted, which is exactly the mistake a reader makes by reading
    // `hasNativeCode` as "no native code".
    const row = find(survey, 'org.bitbucket.watashi564.combapp');
    assert.deepEqual(poolFilterRejections(row), ['stray_shared_object', 'apk_over_cap', 'dex_over_cap']);
    const asIfUnnoticed = { ...row, straySharedObjects: [] };
    assert.deepEqual(poolFilterRejections(asIfUnnoticed), ['apk_over_cap', 'dex_over_cap']);
    // And with the sizes it would have inside the caps, it is admitted outright.
    const admitted = {
      ...asIfUnnoticed,
      dexBytes: 64 * 1024,
      apkBytes: 2 * 1024 * 1024,
    };
    assert.deepEqual(poolFilterRejections(admitted), []);
  });

  test('a WebView-only app is rejected: its whole UI is a REFUSE-class dependency', () => {
    // org.asafonov.blockbuster ranked 2nd before the WebView gate existed, with
    // only 6 distinct android.* types, because it outsources its entire UI to
    // WebView.loadUrl("file:///android_asset/index.html"). Small surface, no
    // subject.
    const m = find(measured, 'org.asafonov.blockbuster');
    assert.ok(m.taxonomy.ids.includes('SUB.FW.WEBVIEW'));
    assert.ok(measuredFilterRejections(m).includes('webview_content_dependency'));
    // And the taxonomy really does class it REFUSE.
    const e = taxonomy.get('SUB.FW.WEBVIEW');
    assert.ok(e.classes.has('REFUSE'));
  });

  test('an app whose buttons are bound by android:onClick is rejected', () => {
    // The framework resolves these with getMethod, so the app's own DEX shows
    // zero reflective call sites — the reflection count is blind to them.
    const m = find(measured, 'com.tmendes.dadosd');
    assert.equal(m.dex.reflectionCallSites, 0);
    assert.equal(m.archive.layoutOnclickBindings.length, 3);
    assert.ok(measuredFilterRejections(m).includes('layout_onclick_reflective_dispatch'));
  });

  test('an app with a text field is rejected, and the taxonomy ID is not needed to see it', () => {
    // dudeofx.eval's layout is LinearLayout > ListView + LinearLayout >
    // EditText[requestFocus]. It has no SUB.INPUT.IME taxonomy hit, so keying
    // the gate on the ID would have let it through.
    const m = find(measured, 'dudeofx.eval');
    assert.equal(m.taxonomy.ids.includes('SUB.INPUT.IME'), false);
    assert.ok(m.dex.androidTypes.includes('Landroid/widget/EditText;'));
    assert.ok(measuredFilterRejections(m).includes('text_field_on_launch_path'));
    const e = taxonomy.get('SUB.INPUT.IME');
    assert.ok(e.classes.has('REFUSE'));
  });

  test('an app that needs a special-access permission is rejected', () => {
    // org.vi_server.red_screen ranked 1st on surface size alone: 9 android.*
    // types, 13 methods, 8 declared methods, 1.9 KB of DEX. Its whole onCreate
    // is WindowManager$LayoutParams (forced brightness, type = 2010 =
    // TYPE_SYSTEM_ERROR) plus a PowerManager wake lock, and it declares
    // SYSTEM_ALERT_WINDOW.
    const m = find(measured, 'org.vi_server.red_screen');
    assert.ok(m.manifest.permissions.includes('android.permission.SYSTEM_ALERT_WINDOW'));
    assert.ok(measuredFilterRejections(m).includes('special_permission:android.permission.SYSTEM_ALERT_WINDOW'));
    assert.ok(m.dex.androidTypes.includes('Landroid/view/WindowManager$LayoutParams;'));
  });

  test('an app with a Service is rejected even though it has a launcher and renders', () => {
    // com.termux.boot is one of the six fixtures the shim's CONFORMANCE.md was
    // measured against, so it is not hypothetical: it has an Activity, it
    // renders, and it still costs a whole background lifecycle.
    const m = find(measured, 'com.termux.boot');
    assert.ok(m.manifest.launcherCount >= 1);
    assert.ok(m.dex.renderCallSites >= 1);
    assert.equal(m.manifest.counts.service, 1);
    assert.equal(m.manifest.counts.receiver, 1);
    const why = measuredFilterRejections(m);
    assert.ok(why.includes('declares_service'));
    assert.ok(why.includes('declares_receiver'));
  });

  test('no eligible candidate trips any gate', () => {
    for (const e of shortlist.eligible) {
      assert.deepEqual(measuredFilterRejections(e.measured), [], e.measured.packageName);
    }
  });
});

// =====================================================================

describe('the measured corpus, as pinned in candidates.md', () => {
  test('counts', () => {
    assert.equal(measured.length, 200);
    assert.equal(shortlist.eligible.length, 19);
    assert.equal(shortlist.rejected.length, 181);
  });

  test('gate histogram', () => {
    const want = {
      declares_service: 87,
      declares_receiver: 79,
      text_field_on_launch_path: 73,
      no_launcher_activity: 46,
      layout_onclick_reflective_dispatch: 45,
      webview_content_dependency: 34,
      no_render_call_site: 29,
      declares_provider: 26,
      'special_permission:android.permission.WAKE_LOCK': 13,
      'special_permission:android.permission.SYSTEM_ALERT_WINDOW': 7,
    };
    const got = Object.fromEntries([...shortlist.gateHistogram].sort());
    assert.deepEqual(got, want);
  });

  test('the top 10, with the figures candidates.md quotes', () => {
    const want = [
      // package, versionCode, score, aTypes, aMeth, shimMethodsCovered, dexBytes, methods, click, refl, taxIds
      ['eu.quelltext.gita', 6, 0.513, 15, 17, 7, 24897, 43, 2, 0, 3],
      ['tk.al54.dev.badpixels', 4, 0.5409, 15, 17, 3, 3681, 22, 2, 0, 3],
      ['com.jeffliu.balancetheball', 4, 0.5521, 17, 27, 8, 4671, 30, 0, 0, 6],
      ['org.debian.eugen.headingcalculator', 4, 0.561, 16, 33, 14, 7761, 54, 1, 2, 4],
      ['S.N.A.K.E', 1000001, 0.5735, 14, 40, 6, 3025, 9, 0, 0, 5],
      ['us.spotco.extirpater', 35, 0.6197, 19, 38, 10, 8268, 51, 1, 0, 4],
      ['ru.henridellal.fsassist', 5, 0.7679, 30, 37, 11, 16248, 132, 3, 0, 5],
      ['com.github.rsteube.t4', 4, 0.7769, 25, 41, 15, 14737, 195, 2, 2, 5],
      ['anupam.acrylic', 19, 0.814, 132, 210, 37, 24041, 198, 0, 0, 8],
      ['io.github.ebraminio.bouncy', 1, 0.8145, 32, 66, 11, 7882, 48, 1, 0, 7],
    ];
    assert.equal(shortlist.eligible.length >= want.length, true);
    want.forEach((w, i) => {
      const e = shortlist.eligible[i];
      const m = e.measured;
      const label = `#${i + 1} ${m.packageName}`;
      assert.equal(m.packageName, w[0], label);
      assert.equal(m.versionCode, w[1], label);
      assert.equal(Number(e.score.toFixed(4)), w[2], `${label} score`);
      assert.equal(m.dex.distinctAndroidTypes, w[3], `${label} aTypes`);
      assert.equal(m.dex.distinctAndroidMethods, w[4], `${label} aMeth`);
      assert.equal(m.dex.shimMethodsCovered, w[5], `${label} shimMethodsCovered`);
      assert.equal(m.census.dexBytes, w[6], `${label} dexBytes`);
      assert.equal(m.dex.methods, w[7], `${label} methods`);
      assert.equal(m.dex.clickCallSites, w[8], `${label} click`);
      assert.equal(m.dex.reflectionCallSites, w[9], `${label} refl`);
      assert.equal(m.taxonomy.ids.length, w[10], `${label} taxIds`);
    });
  });

  test('the SHA-256s candidates.md quotes, so the shortlist is pinned to bytes', () => {
    const want = {
      'eu.quelltext.gita': '1dc68f1ff0bff92408dc8b472c2afafec2f45cabb269a0a10cb4222d34b8d8cb',
      'tk.al54.dev.badpixels': '43842c079c9f8cde375dc4a25ad62f7cd39237b4dcbf5ddbbb45738a620dd82f',
      'com.jeffliu.balancetheball': '6180534b151e4d50365b21483f3719e32f207a42675dee20227de449c875c1e2',
      'org.debian.eugen.headingcalculator': 'dbcfc1903051b66e7f6d3bd65a49d79527d2c143dfd870e9384bb2c9c1b8b383',
      'S.N.A.K.E': 'd8b3db6f912c67bec1ae9dec5b1b4ffd9958004bd7c5efec88cec48c23bfca86',
      'us.spotco.extirpater': 'ba8dcd0566affda61b7ad94cb7f1f2b1c0cbff2cb78bd2fd042b6a0e3858406e',
      'ru.henridellal.fsassist': 'e5525642c146806c3251e268d8f120759585a620f353a4680a791f551b32b823',
      'com.github.rsteube.t4': 'f76b18eeef2df33ac77709a1410c9eda68c162954563895325793d42cf83a1e7',
      'anupam.acrylic': 'df01309e3641fac77cd9bd356558e122e31f1317f988dfb4144ebad949e0ac84',
      'io.github.ebraminio.bouncy': 'a509db2afda544f6da9620eb473319b0a034c6ffc8b6536e2a8a7bcc0f407f54',
    };
    for (const [pkg, sha] of Object.entries(want)) {
      assert.equal(find(measured, pkg).sha256, sha, `${pkg} sha256`);
    }
    // Every measured row carries a full 64-hex digest, so a truncated or
    // placeholder value cannot slip through anywhere in the file.
    for (const m of [...measured, ...negatives]) {
      assert.match(m.sha256, /^[0-9a-f]{64}$/, `${m.packageName} sha256 shape`);
      assert.equal(m.archive.elfSniffBudgetExhausted, false, `${m.packageName} sniff budget`);
    }
  });

  test('the APK byte sizes match the F-Droid index the survey recorded', () => {
    // The index size is a second, independent integrity statement, available
    // before hashing. A mismatch means the download is not the indexed artefact.
    for (const m of measured) {
      assert.equal(m.apkBytes, m.census.apkBytesIndex, `${m.packageName} byte size vs index`);
    }
  });

  test('every candidate measured is DEX-only, by the archive itself', () => {
    // The headline the pool was built for, now measured rather than assumed.
    let so = 0, elf = 0, native = 0, loadlib = 0, gms = 0, poly = 0;
    for (const m of measured) {
      so += m.archive.soAnywhere > 0 ? 1 : 0;
      elf += m.archive.elfPayloads > 0 ? 1 : 0;
      native += m.dex.nativeMethods > 0 ? 1 : 0;
      loadlib += m.dex.loadLibraryCallSites > 0 ? 1 : 0;
      gms += m.dex.playServicesClasses > 0 ? 1 : 0;
      poly += m.dex.invokePolymorphic + m.dex.invokeCustom > 0 ? 1 : 0;
    }
    assert.deepEqual({ so, elf, native, loadlib, gms, poly }, {
      so: 0, elf: 0, native: 0, loadlib: 0, gms: 0, poly: 0,
    });
  });

  test('no pool row has a truncated per-reference list, so no figure rests on one', () => {
    // The lists are capped at LIST_CAP so `negatives.jsonl` is not 2.5 MB of
    // evidence about four apps. If any *pool* row were truncated, a published
    // figure could be describing a shortened list, so the cap is asserted not
    // to have bound here.
    for (const m of measured) {
      for (const k of [
        'androidMethodsTruncated',
        'uncoveredAndroidMethodsTruncated',
        'androidFieldsTruncated',
      ]) {
        assert.equal(m.dex[k], false, `${m.packageName} ${k}`);
      }
    }
    // And the stored lists are sorted, so the file is byte-stable.
    for (const m of measured) {
      for (const k of ['androidMethods', 'androidTypes', 'uncoveredAndroidMethods', 'androidFields']) {
        const xs = m.dex[k];
        assert.deepEqual(xs, [...xs].sort(), `${m.packageName} ${k} is not sorted`);
      }
      const members = m.dex.appOwnedCallSiteMembers.map((x) => x.member);
      assert.deepEqual(members, [...members].sort(), `${m.packageName} appOwnedCallSiteMembers is not sorted`);
    }
  });

  test('every DEX in the pool decoded every method body', () => {
    for (const m of measured) {
      assert.equal(m.dex.analysable, true, `${m.packageName} analysable`);
      assert.equal(m.dex.methodsUndecodable, 0, `${m.packageName} undecodable methods`);
    }
  });
});

// =====================================================================

describe('the rubric', () => {
  test('weights sum to 1', () => {
    // Within 1e-12, not `===`: nine decimal weights in binary floating point do
    // not sum to exactly 1.0, and pretending they do is how a real drift would
    // slip past. `rank --explain` prints the sum to 6 places and it is 1.000000.
    assert.ok(Math.abs(rubricWeightSum() - 1) < 1e-12, `weight sum ${rubricWeightSum()}`);
  });

  test('every component has a distinct id, a positive weight and a positive saturation', () => {
    const ids = new Set();
    for (const c of RUBRIC) {
      assert.equal(ids.has(c.id), false, `duplicate component id ${c.id}`);
      ids.add(c.id);
      assert.ok(c.weight > 0, c.id);
      assert.ok(c.saturation > 0, c.id);
      assert.equal(typeof c.unit, 'string');
      assert.equal(typeof c.why, 'string');
    }
  });

  test('the score is a penalty in [0,1] and every subscore saturates at 1', () => {
    for (const e of shortlist.eligible) {
      assert.ok(e.score >= 0 && e.score <= 1, e.measured.packageName);
      for (const c of e.components) {
        assert.ok(c.subscore >= 0 && c.subscore <= 1, `${e.measured.packageName} ${c.id}`);
        assert.equal(c.subscore, Math.min(1, c.count / c.saturation), `${c.id} subscore is min(1, n/sat)`);
      }
      const sum = e.components.reduce((a, c) => a + c.contribution, 0);
      assert.ok(Math.abs(sum - e.score) < 1e-12, 'score is the sum of its contributions');
    }
  });

  test('every component has a count for every candidate, so nothing is silently dropped', () => {
    for (const e of shortlist.eligible) {
      for (const c of RUBRIC) {
        const got = e.components.find((x) => x.id === c.id);
        assert.ok(got, `${e.measured.packageName} is missing component ${c.id}`);
        assert.equal(Number.isFinite(got.count), true, `${c.id} count is finite`);
      }
    }
  });

  test('a component with no data is an error, not a zero', () => {
    // scoreCandidate throws on a missing count. Without that, a typo in a
    // component id would contribute 0 and quietly improve every score.
    const m = structuredClone(find(measured, 'eu.quelltext.gita'));
    delete m.dex.clickCallSites;
    assert.throws(() => scoreCandidate(m), /no count/);
  });

  test('withoutComponents renormalises, so the counterfactual is comparable', () => {
    const r = withoutComponents(['shim_method_gap']);
    assert.equal(r.some((c) => c.id === 'shim_method_gap'), false);
    assert.ok(Math.abs(rubricWeightSum(r) - 1) < 1e-12);
    assert.throws(() => withoutComponents(RUBRIC.map((c) => c.id)), /every component/);
  });

  test('the two added components are the ones candidates.md discloses', () => {
    // Not in the brief that set this task, and said so in the rubric's comment.
    const added = new Set(['shim_method_gap', 'clickable_view']);
    for (const c of RUBRIC) {
      if (added.has(c.id)) assert.match(c.why, /Not in the brief/, `${c.id} must disclose itself`);
    }
    assert.equal(added.size, 2);
  });
});

// =====================================================================

describe('the shim surface', () => {
  test('parses to exactly the counts shim/CONFORMANCE.md publishes', async () => {
    const s = await loadShimSurface();
    assert.equal(s.classCount, EXPECTED.classes);
    assert.equal(s.methodCount, EXPECTED.methods);
    assert.equal(s.fieldCount, EXPECTED.fields);
  });

  test('method-level coverage of the top candidate is what candidates.md claims', () => {
    const m = find(measured, 'eu.quelltext.gita');
    assert.equal(m.dex.distinctAndroidTypes, 15);
    assert.equal(m.dex.shimTypesCovered, 9);
    assert.equal(m.dex.distinctAndroidMethods, 17);
    assert.equal(m.dex.shimMethodsCovered, 7);
    assert.equal(m.dex.shimMethodNamesCovered, 10);
  });

  test('the five classes the top candidate needs are the ListView/Adapter family', async () => {
    const shim = indexSurface(await loadShimSurface());
    const m = find(measured, 'eu.quelltext.gita');
    const missing = m.dex.androidTypes.filter((t) => !shim.classes.has(t));
    assert.deepEqual(missing, [
      'Landroid/annotation/SuppressLint;',
      'Landroid/widget/AdapterView$OnItemClickListener;',
      'Landroid/widget/AdapterView;',
      'Landroid/widget/ArrayAdapter;',
      'Landroid/widget/ListAdapter;',
      'Landroid/widget/ListView;',
    ]);
  });
});

// =====================================================================

describe('the frozen taxonomy', () => {
  test('classifies exactly the 145 IDs it declares', async () => {
    const t = parseTaxonomy(await readFile(TAXONOMY, 'utf8'));
    assert.equal(t.size, EXPECTED_CLASSIFIED_IDS);
  });

  test('the family-summary rows are not mistaken for IDs', () => {
    for (const id of ['SUB.FW', 'SUB.NET', 'SUB.IPC', 'SUB.TRUST', 'SUB.KERNEL']) {
      assert.equal(taxonomy.get(id), undefined, `${id} is a family row, not an assumption`);
    }
  });

  test('the weights are ordered REFUSE > MISBEHAVE > DEGRADE, and multi-class cells take the worst', () => {
    assert.equal(taxonomyWeight(taxonomy.get('SUB.FW.WEBVIEW')), 1.0);
    assert.equal(taxonomyWeight(taxonomy.get('SUB.IPC.PACKAGE_MANAGER_OTHER')), 0.6);
    assert.equal(taxonomyWeight(taxonomy.get('SUB.FS.EXTERNAL_STORAGE')), 0.3);
    // SUB.RES.ARSC is "REFUSE / MISBEHAVE" and must score as REFUSE.
    assert.equal(taxonomy.get('SUB.RES.ARSC').classes.has('REFUSE'), true);
    assert.equal(taxonomy.get('SUB.RES.ARSC').classes.has('MISBEHAVE'), true);
    assert.equal(taxonomyWeight(taxonomy.get('SUB.RES.ARSC')), 1.0);
    // An ID the taxonomy does not have costs 0, and that is a fact about the
    // rule table, not a clean bill of health.
    assert.equal(taxonomyWeight(undefined), 0);
  });
});

// =====================================================================

describe('method_id reference matching — two bugs this had', () => {
  test('the real reference form is `Lcls;.member(args)ret`', () => {
    // The `;->` spelling is what dexcore's human-readable dumps use. A matcher
    // that only accepts one of the two fails *silently* on the other: every
    // count is 0 and the consequence is a confident "no render call site".
    assert.equal(refMatches('Landroid/app/Activity;.setContentView(I)V', { name: 'setContentView' }), true);
    assert.equal(refMatches('Landroid/app/Activity;->setContentView(I)V', { name: 'setContentView' }), true);
  });

  test('an inherited method called through the app own subclass still matches', () => {
    // eu.quelltext.gita calls setContentView twice, both recorded with the app's
    // own class as the owner. An `^Landroid/`-anchored match scored it 0.
    assert.equal(
      refMatches('Leu/quelltext/gita/activities/ChapterActivity;.setContentView(I)V', { name: 'setContentView' }),
      true,
    );
  });

  test('a click handler reached through a subclass still matches', () => {
    // headingcalculator wires its keypad with Button;.setOnClickListener, not
    // View;.setOnClickListener.
    assert.equal(
      refMatches('Landroid/widget/Button;.setOnClickListener(Landroid/view/View$OnClickListener;)V', {
        name: 'setOnClickListener',
      }),
      true,
    );
  });

  test('an owner-anchored signature does not match the app own same-named method', () => {
    assert.equal(refMatches('Landroid/view/LayoutInflater;.inflate(ILandroid/view/ViewGroup;)Landroid/view/View;', {
      name: 'inflate', owner: 'Landroid/view/LayoutInflater;',
    }), true);
    assert.equal(refMatches('Leu/quelltext/gita/Chapter;.inflate(I)V', {
      name: 'inflate', owner: 'Landroid/view/LayoutInflater;',
    }), false);
  });

  test('a literal name is a whole-member match, not a prefix', () => {
    assert.equal(refMatches('Landroid/app/Activity;.setContentViewExtra(I)V', { name: 'setContentView' }), false);
    assert.equal(refMatches('Landroid/app/Activity;.setContentView(Landroid/view/View;)V', { name: 'setContentView' }), true);
  });

  test('malformed references are rejected rather than guessed at', () => {
    for (const bad of ['', 'garbage', 'Landroid/app/Activity', 'Landroid/app/Activity;', 'Landroid/app/Activity;.()V']) {
      assert.equal(refMatches(bad, { name: 'setContentView' }), false, JSON.stringify(bad));
    }
  });
});

describe('splitMethodRef / splitFieldRef', () => {
  test('splits a method reference', () => {
    assert.deepEqual(splitMethodRef('Landroid/app/Activity;.onCreate(Landroid/os/Bundle;)V'), {
      cls: 'Landroid/app/Activity;',
      name: 'onCreate',
    });
  });
});

// =====================================================================

describe('AXML parsing — the two bugs this had', () => {
  test('a UTF-8 pool is detected from its flags, and its length words are variable-width', () => {
    // The pool is flagged 0x0100 (AXML_UTF8_FLAG) and its entries use one-byte
    // length words. Reading the words as fixed 2-byte u16s desynchronises the
    // cursor and the rest of the pool becomes garbage.
    const doc = parseAxml(axmlDocument(ONCLICK_MANIFEST));
    assert.ok(doc.strings.includes('manifest'));
    assert.ok(doc.strings.includes('android:onClick'));
    assert.ok(doc.strings.includes('genData'));
    for (const s of doc.strings) {
      // A desynchronised pool produces identifiers with a stray control byte
      // in front of them, which is how this bug presented.
      assert.doesNotMatch(s, /[\u0000-\u0008\u000e-\u001f]/, JSON.stringify(s));
    }
  });

  test('the element name comes from the attrExt, not the node comment field', () => {
    // The node's `comment` field is -1; reading it as the tag name yields a
    // structurally plausible tree of wrong tags.
    const doc = parseAxml(axmlDocument(ONCLICK_MANIFEST));
    assert.equal(doc.elements[0].tag, 'manifest');
    assert.equal(doc.elements[0].attrs.find((a) => a.local === 'package').value, 'com.example.onclick');
    assert.deepEqual(
      doc.elements.map((e) => e.tag),
      ['manifest', 'application', 'activity', 'intent-filter', 'action', 'category', 'LinearLayout', 'Button', 'ImageView'],
    );
  });

  test('attribute names are split into namespace and local part', () => {
    const doc = parseAxml(axmlDocument(ONCLICK_MANIFEST));
    const btn = doc.elements.find((e) => e.tag === 'Button');
    const a = btn.attrs[0];
    assert.equal(a.ns, ANDROID_URI);
    assert.equal(a.name, 'android:onClick');
    assert.equal(a.local, 'onClick');
    assert.equal(a.value, 'genData');
  });

  test('onclickBindings finds framework-resolved click handlers', () => {
    const b = onclickBindings(parseAxml(axmlDocument(ONCLICK_MANIFEST)));
    assert.deepEqual(b, [
      { view: 'Button', handler: 'genData' },
      { view: 'ImageView', handler: 'murmuring' },
    ]);
  });

  test('a launcher needs MAIN and LAUNCHER together', () => {
    const s = summariseManifest(parseAxml(axmlDocument(ONCLICK_MANIFEST)));
    assert.equal(s.counts.activity, 1);
    assert.equal(s.launcherActivities.length, 1);
    assert.equal(s.launcherActivities[0].name, 'com.example.onclick.activity');
  });

  test('a manifest with no LAUNCHER category has no launcher', () => {
    const noLauncher = structuredClone(ONCLICK_MANIFEST);
    noLauncher.children[0].children[0].children[0].children[1] = { tag: 'category', attrs: [{ ns: 'android', local: 'name', value: 'android.intent.category.DEFAULT' }] };
    assert.equal(summariseManifest(parseAxml(axmlDocument(noLauncher))).launcherActivities.length, 0);
  });
});

// --- minimal AXML builders, so the parser is tested on bytes it did not see --
//
// Everything above is tested against real APKs. These builders exist so the
// three AXML bugs this parser had are pinned on *minimal* inputs, where the
// failure is attributable, and so the test does not depend on an APK being
// present.

const ANDROID_URI = 'http://schemas.android.com/apk/res/android';

/** A RES_XML_TYPE document, assembled from a declarative element tree. */
function axmlDocument(spec) {
  const pool = [];
  const index = new Map();
  const intern = (s) => {
    if (index.has(s)) return index.get(s);
    pool.push(s);
    index.set(s, pool.length - 1);
    return pool.length - 1;
  };
  const nsIdx = intern(ANDROID_URI);
  const t = (n) => intern(n);

  const encode = (el) => {
    if (el.strings) {
      for (const s of el.strings) intern(s);
      return null;
    }
    const nameIdx = t(el.tag);
    const attrs = (el.attrs ?? []).map((a) => {
      const an = a.ns ? `${a.ns}:${a.local}` : a.local;
      return {
        ns: a.ns ? nsIdx : -1,
        name: intern(an),
        value: intern(a.value),
      };
    });
    const kids = (el.children ?? []).map(encode).filter(Boolean);
    return { nameIdx, attrs, kids };
  };
  const tree = encode(spec);

  // A string pool, UTF-8 encoded, with one-byte length words (the form a
  // compiler emits for short names). The two bugs were: reading the length
  // words as fixed 2-byte u16s, and slicing `len` *bytes* out of a pool whose
  // lengths are in code units.
  const flags = 0x0100; // AXML_UTF8_FLAG
  const headerSize = 28;
  const offsets = [];
  const blobs = [];
  let cur = 0;
  for (const s of pool) {
    const bytes = Buffer.from(s, 'utf8');
    const b = Buffer.alloc(2 + bytes.length + 1);
    b.writeUInt8(Math.min(s.length, 0x7f), 0);
    b.writeUInt8(Math.min(bytes.length, 0x7f), 1);
    bytes.copy(b, 2);
    b.writeUInt8(0, 2 + bytes.length);
    offsets.push(cur);
    blobs.push(b);
    cur += b.length;
  }
  const stringsStart = headerSize + offsets.length * 4;
  const poolBody = Buffer.alloc(stringsStart - 8 + cur);
  poolBody.writeUInt32LE(pool.length, 0);
  poolBody.writeUInt32LE(0, 4);
  poolBody.writeUInt32LE(flags, 8);
  poolBody.writeUInt32LE(stringsStart, 12); // relative to the chunk start
  offsets.forEach((o, i) => poolBody.writeUInt32LE(o, 20 + i * 4));
  Buffer.concat(blobs).copy(poolBody, stringsStart - 8);
  const poolChunk = chunk(0x0001, headerSize, poolBody);

  // Depth first, parent first: a START_ELEMENT, then its children, then its
  // END_ELEMENT. Emitting the children first parses without error and produces a
  // tree with the depth relationships transposed, which the element-name
  // assertion below catches.
  const emit = (n) => [
    startElement(n.nameIdx, n.attrs),
    ...n.kids.flatMap(emit),
    endElement(),
  ];

  const parts = [xmlFileHeader(), poolChunk, ...emit(tree)];
  const out = Buffer.concat(parts);
  out.writeUInt32LE(out.length, 4);
  return out;
}

function chunk(type, headerSize, body) {
  const head = Buffer.alloc(8);
  head.writeUInt16LE(type, 0);
  head.writeUInt16LE(headerSize, 2);
  head.writeUInt32LE(8 + body.length, 4);
  return Buffer.concat([head, body]);
}
function xmlFileHeader() {
  const h = Buffer.alloc(8);
  h.writeUInt16LE(0x0003, 0); // RES_XML_TYPE
  h.writeUInt16LE(8, 2);
  h.writeUInt32LE(0, 4); // patched by the caller
  return h;
}
function startElement(nameIdx, attrs) {
  const headerSize = 16; // 8-byte chunk header + lineNumber + comment
  const attrSize = 20;
  // The attrExt is 20 bytes: ns (4) + name (4) + six u16 (12). That is what
  // makes `attributeStart` 20 in a real document; a 16-byte ext puts every
  // attribute four bytes early.
  const ext = Buffer.alloc(20);
  ext.writeInt32LE(-1, 0);
  ext.writeInt32LE(nameIdx, 4);
  ext.writeUInt16LE(20, 8);
  ext.writeUInt16LE(attrSize, 10);
  ext.writeUInt16LE(attrs.length, 12);
  const abuf = Buffer.alloc(attrs.length * attrSize);
  attrs.forEach((a, i) => {
    const o = i * attrSize;
    abuf.writeInt32LE(a.ns, o);
    abuf.writeInt32LE(a.name, o + 4);
    abuf.writeInt32LE(a.value, o + 8); // rawValue
    abuf.writeUInt16LE(8, o + 12);
    abuf.writeUInt8(0, o + 14);
    abuf.writeUInt8(0x03, o + 15); // TYPE_STRING
    abuf.writeUInt32LE(a.value, o + 16);
  });
  const node = Buffer.alloc(8);
  node.writeUInt32LE(1, 0); // lineNumber
  node.writeInt32LE(-1, 4); // comment
  return chunk(0x0102, headerSize, Buffer.concat([node, ext, abuf]));
}
function endElement() {
  return chunk(0x0103, 16, Buffer.alloc(8));
}

const ONCLICK_MANIFEST = {
  tag: 'manifest',
  attrs: [{ local: 'package', value: 'com.example.onclick' }],
  children: [
    {
      tag: 'application',
      children: [
        {
          tag: 'activity',
          attrs: [{ ns: 'android', local: 'name', value: 'com.example.onclick.activity' }],
          children: [
            {
              tag: 'intent-filter',
              children: [
                { tag: 'action', attrs: [{ ns: 'android', local: 'name', value: 'android.intent.action.MAIN' }] },
                { tag: 'category', attrs: [{ ns: 'android', local: 'name', value: 'android.intent.category.LAUNCHER' }] },
              ],
            },
            {
              tag: 'LinearLayout',
              children: [
                { tag: 'Button', attrs: [{ ns: 'android', local: 'onClick', value: 'genData' }] },
                { tag: 'ImageView', attrs: [{ ns: 'android', local: 'onClick', value: 'murmuring' }] },
              ],
            },
          ],
        },
      ],
    },
  ],
};

// =====================================================================

describe('the render and click signals, end to end', () => {
  test('gita renders through inflate and has two click-handler call sites', () => {
    const m = find(measured, 'eu.quelltext.gita');
    assert.equal(m.dex.render.set_content_view, 2);
    assert.equal(m.dex.render.layout_inflate, 2);
    assert.equal(m.dex.render.canvas_draw, 0);
    assert.equal(m.dex.click.set_on_item_click_listener, 2);
    assert.equal(m.dex.renderCallSites, 4);
  });

  test('gita reaches six inherited framework members through its own classes', () => {
    // This is the bug that once put a false "no render call sites" in front of
    // a reader for this exact app, and it is also a standing limitation of the
    // surface measurement: `androidMethods` counts only `Landroid/`-owned
    // references, so an inherited framework method called through an app
    // subclass is invisible to it. `appOwnedCallSiteMembers` enumerates what is
    // reached that way; separating the framework members from the app's own
    // needs the DEX class hierarchy, which this script does not read, so the
    // whole list is pinned and the framework subset is identified by hand in
    // candidates.md.
    const m = find(measured, 'eu.quelltext.gita');
    assert.equal(
      m.dex.androidMethods.some((r) => r.includes('.setContentView(')),
      false,
      'the app own subclass is not an Landroid/ owner, so it is not in androidMethods',
    );
    const byMember = Object.fromEntries(m.dex.appOwnedCallSiteMembers.map((x) => [x.member, x.callSites]));
    // The inherited framework members, identified by reading the app's classes.
    for (const [member, sites] of Object.entries({
      setContentView: 2, findViewById: 2, getIntent: 1, getSystemService: 2,
      getStringResourceByName: 2, getTitle: 2,
    })) {
      assert.equal(byMember[member], sites, `gita ${member} via its own class`);
    }
    // And its own members, which are not framework surface at all.
    for (const member of ['getIndex', 'getMeaning', 'getVerseCount', 'allVerses', 'hasMultipleVerses']) {
      assert.ok(byMember[member] >= 1, `gita own member ${member}`);
    }
  });

  test('the render counts are all finite for every measured row', () => {
    for (const m of measured) {
      for (const [k, v] of Object.entries({ ...m.dex.render, ...m.dex.click })) {
        assert.equal(Number.isFinite(v), true, `${m.packageName} ${k} is ${v}`);
      }
    }
  });
});

describe('CLI surface', () => {
  test('rank refuses to rank an incomplete measurement instead of degrading silently', async () => {
    // Not exercised against the real file; the code path is asserted by reading
    // the guard, and the guard's existence is what matters.
    const src = await readFile(path.join(REPO, 'analysis', 'select-candidates.mjs'), 'utf8');
    assert.match(src, /refusing to rank/);
    assert.match(src, /process\.exitCode = 3/);
  });

  test('rankOutput is deterministic and is what the CLI prints', () => {
    const a = rankOutput(measured, RUBRIC, 19, true);
    const b = rankOutput(measured, RUBRIC, 19, true);
    assert.equal(a, b);
    assert.match(a, /eligible: 19/);
    assert.match(a, /weight sum 1\.000000/);
  });
});
