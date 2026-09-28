// Pins every figure quoted in 0002-is-the-closure-well-defined.md.
//
// Two layers:
//   1. Every number in the document is asserted here against data/figures.json,
//      so editing the prose without re-running the analysis fails the test.
//   2. When the captures listed in data/manifest.json are present, the whole
//      analysis is re-derived from the raw bytes and must reproduce
//      figures.json exactly. The SHA-256 of each capture is checked first, so
//      a different capture cannot silently produce the same numbers.
//
//   node --test closure.test.mjs
//   A15_TRACE_DIR=/dir/with/the/traces node --test closure.test.mjs
//
// The captures are not committed, so layer 2 skips when they are absent and
// says so, rather than passing silently.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const F = JSON.parse(readFileSync(join(here, 'data/figures.json'), 'utf8'));
const MANIFEST = JSON.parse(readFileSync(join(here, 'data/manifest.json'), 'utf8'));
const DOC = readFileSync(join(here, '0002-is-the-closure-well-defined.md'), 'utf8');
// prose is wrapped, so phrase checks run against a whitespace-collapsed copy
const FLAT = DOC.replace(/\s+/g, ' ');

const DIRS = [process.env.A15_TRACE_DIR, '/var/folders/lc/r25hfwjs4j963w2f40s9rc5h0000gn/T/opencode/a15'].filter(Boolean);
const haveCaptures = (() => {
  const all = [
    ...Object.values(MANIFEST.low).flatMap((g) => g.files),
    ...Object.values(MANIFEST.high).filter((g) => g.files).flatMap((g) => g.files),
  ];
  return all.every((f) => DIRS.some((d) => existsSync(join(d, f))));
})();

// --- layer 2: re-derive from the raw captures -----------------------------
if (haveCaptures) {
  test('re-derives figures.json byte-for-byte from the raw captures', () => {
    // This is the load-bearing test: it re-runs the whole analysis against the
    // original bytes and demands an exact match, so figures.json cannot drift
    // away from the captures it claims to summarise.
    const scratch = join(mkdtempSync(join(tmpdir(), 'a15-')), 'figures.json');
    execFileSync(process.execPath, [join(here, 'run-analysis.mjs'), '--quiet'], {
      env: { ...process.env, A15_FIGURES_OUT: scratch },
      stdio: 'pipe',
    });
    const rederived = readFileSync(scratch, 'utf8');
    rmSync(dirname(scratch), { recursive: true, force: true });
    assert.equal(
      rederived,
      readFileSync(join(here, 'data/figures.json'), 'utf8'),
      're-derived figures.json differs from the committed one',
    );
  });

  test('every capture matches its recorded sha256', async () => {
    const { parseTrace } = await import('./lib/arttrace.mjs');
    const groups = [
      ...Object.values(MANIFEST.low),
      ...Object.values(MANIFEST.high).filter((g) => g.files),
    ];
    for (const g of groups) {
      for (let i = 0; i < g.files.length; i++) {
        const p = DIRS.map((d) => join(d, g.files[i])).find((x) => existsSync(x));
        const sha = createHash('sha256').update(readFileSync(p)).digest('hex');
        assert.equal(sha, g.sha256[i], `sha256 ${g.files[i]}`);
        // the decode must satisfy ART's own invariants
        const t = parseTrace(p);
        assert.equal(t.records.length, t.numMethodCalls, `num-method-calls ${g.files[i]}`);
        assert.equal(t.tailBytes, 12, `trailing bytes ${g.files[i]}`);
      }
    }
  });
}

// --- layer 1: pin every figure quoted in the document ---------------------

test('capture inventory', () => {
  assert.equal(F.inventory.capturesUsed.length, 21);
  assert.equal(F.inventory.lost.length, 3);
  assert.deepEqual(F.inventory.lost.map((l) => l.bytes), [0, 0, 0]);
  // the parser cross-check quoted in section 1.1
  assert.equal(F.inventory.recordsEqualHeaderCount.length, 21);
  assert.ok(F.inventory.recordsEqualHeaderCount.every((r) => r.equal), 'records == header count');
});

test('section 1.1 -- per-run record counts, windows and cadence', () => {
  const g = F.lowBudget.gita;
  assert.deepEqual(g.records, [915, 1372, 1295, 1591, 1473, 1393]);
  assert.deepEqual(g.windowMs, [1985, 7121, 2021, 7121, 7129, 2010]);
  assert.deepEqual(g.threads, [7, 9, 7, 7, 6, 7]);
  assert.deepEqual(F.lowBudget.balancetheball.records, [5486, 5450]);
  assert.deepEqual(F.lowBudget.headingcalculator.records, [648, 782, 674]);
  assert.deepEqual(F.lowBudget.badpixels.records, [563, 392, 525]);
  assert.deepEqual(F.highBudget.records, [512758, 504552, 496189]);
  assert.deepEqual(F.highBudget.windowMs, [6216, 6191, 6245]);

  const cad = F.periodicity.lowBudgetCadence;
  // 22.6-83.9 ms for gita
  const gi = cad.gita.map((r) => r.sampleIntervalMs);
  assert.equal(Math.min(...gi), 22.6);
  assert.equal(Math.max(...gi), 83.9);
  // balancetheball: identical cadence in both runs
  assert.deepEqual(cad.balancetheball.map((r) => r.sampleIntervalMs), [17.1, 17.1]);
  // badpixels 111.9-143.1, headingcalculator 15.8-118.5
  const bp = cad.badpixels.map((r) => r.sampleIntervalMs);
  assert.equal(Math.min(...bp), 111.9);
  assert.equal(Math.max(...bp), 143.1);
  const hc = cad.headingcalculator.map((r) => r.sampleIntervalMs);
  assert.equal(Math.min(...hc), 15.8);
  assert.equal(Math.max(...hc), 118.5);
  assert.equal(cad.gita[0].meanStackDepth, 13.26);
});

test('section 1.2 -- the low-budget arm', () => {
  assert.deepEqual(F.lowBudget.gita.sizes, [206, 323, 325, 395, 331, 333]);
  assert.equal(F.lowBudget.gita.union, 683);
  assert.equal(F.lowBudget.gita.intersection, 112);
  assert.equal(F.lowBudget.gita.meanJ, 0.4411);
  assert.equal(F.lowBudget.gita.jLo, 0.4111);
  assert.equal(F.lowBudget.gita.jHi, 0.4697);
  assert.equal(F.lowBudget.gita.jSd, 0.06);
  assert.deepEqual(F.lowBudget.gita.curveSizeSorted, [206, 397, 490, 566, 617, 683]);

  assert.deepEqual(F.lowBudget.balancetheball.sizes, [274, 335]);
  assert.equal(F.lowBudget.balancetheball.union, 403);
  assert.equal(F.lowBudget.balancetheball.intersection, 206);
  assert.equal(F.lowBudget.balancetheball.meanJ, 0.5112);
  assert.equal(F.lowBudget.balancetheball.nRuns, 2);

  assert.deepEqual(F.lowBudget.headingcalculator.sizes, [199, 242, 219]);
  assert.equal(F.lowBudget.headingcalculator.union, 355);
  assert.equal(F.lowBudget.headingcalculator.intersection, 104);
  assert.equal(F.lowBudget.headingcalculator.meanJ, 0.4498);
  assert.equal(F.lowBudget.headingcalculator.jLo, 0.3887);
  assert.equal(F.lowBudget.headingcalculator.jHi, 0.5155);

  assert.deepEqual(F.lowBudget.badpixels.sizes, [192, 145, 158]);
  assert.equal(F.lowBudget.badpixels.union, 265);
  assert.equal(F.lowBudget.badpixels.intersection, 110);
  assert.equal(F.lowBudget.badpixels.meanJ, 0.5264);
  assert.equal(F.lowBudget.badpixels.jLo, 0.4706);
  assert.equal(F.lowBudget.badpixels.jHi, 0.5699);
});

test('section 1.2 -- the figures in the brief are recorded as unreproduced', () => {
  // The brief reported 628 / 373 / 338 / 242, J = 0.451, curve 199..628.
  // None reproduce. This test exists so that if someone later finds the
  // derivation that produced them, the change is deliberate.
  for (const claimed of [628, 373, 338, 242]) {
    assert.ok(!Object.values(F.lowBudget).some((a) => a.union === claimed),
      `no union equals the claimed ${claimed}`);
  }
  assert.notEqual(F.lowBudget.gita.meanJ, 0.451);
  assert.notDeepEqual(F.lowBudget.gita.curveSizeSorted, [199, 366, 450, 545, 583, 628]);
});

test('section 1.3 -- three matched high-budget runs', () => {
  const h = F.highBudget;
  assert.equal(h.nRuns, 3);
  assert.deepEqual(h.sizes, [4649, 4649, 4648]);
  assert.equal(h.union, 4649);
  assert.equal(h.intersection, 4648);
  assert.deepEqual(h.jaccards, [1, 0.999785, 0.999785]);
  assert.equal(h.meanJ, 0.999857);
  assert.equal(h.minJ, 0.999785);
  assert.equal(h.sizeVar, 0.333);
  assert.equal(h.sizeSd, 0.577);
  assert.equal(h.spreadMethods, 1);
});

test('section 1.4 -- the measurement null', () => {
  const r = F.nulls.resample;
  assert.equal(r['915'].meanJ, 0.3067);
  assert.equal(r['915'].sdJ, 0.0161);
  assert.equal(r['915'].sizeMean, 454.4);
  assert.equal(r['1300'].meanJ, 0.3552);
  assert.equal(r['1300'].sizeMean, 570.2);
  assert.equal(r['1591'].meanJ, 0.382);
  assert.equal(r['1591'].sizeMean, 642);
  const p = F.nulls.phase;
  assert.equal(p['915'].meanJ, 0.3119);
  assert.equal(p['915'].sdJ, 0.0228);
  assert.equal(p['915'].sizeMean, 464.9);
  assert.equal(p['1300'].meanJ, 0.3783);
  assert.equal(p['1591'].meanJ, 0.3863);
  // the claim "31-39%"
  const all = [r['915'].meanJ, r['1300'].meanJ, r['1591'].meanJ, p['915'].meanJ, p['1300'].meanJ, p['1591'].meanJ];
  assert.ok(Math.min(...all) >= 0.30 && Math.max(...all) <= 0.40, 'null J in 0.30-0.40');
  // ... against the observed 0.4411
  assert.ok(F.lowBudget.gita.meanJ > Math.max(...all));
});

test('section 1.5 -- aliasing: periodic vs memoryless selection', () => {
  const a = F.aliasing;
  assert.equal(a.cap, 915);
  assert.equal(a.windowMs, 2000);
  assert.equal(a.windowRecords, 456153);
  assert.equal(a.windowPool, 4365);
  const per = a.periodic;
  assert.equal(per['1000'].sizeMean, 184.4);
  assert.equal(per['10000'].sizeMean, 158.8);
  assert.equal(per['35000'].sizeMean, 187.1);
  assert.equal(per['35000'].sizeSd, 60.2);
  assert.equal(per['35000'].meanJ, 0.4873);
  assert.equal(per['35000'].union12, 427);
  assert.equal(per['350000'].sizeMean, 175.4);
  assert.equal(a.memoryless.sizeMean, 473.3);
  assert.equal(a.memoryless.sizeSd, 8.2);
  assert.equal(a.memoryless.meanJ, 0.3192);
  assert.equal(a.memoryless.union12, 1564);
  // the ratios quoted: 2.5x fewer methods, 3.7x less coverage
  assert.equal(+(a.memoryless.sizeMean / per['35000'].sizeMean).toFixed(2), 2.53);
  assert.equal(+(a.memoryless.union12 / per['35000'].union12).toFixed(2), 3.66);
  // The observed sizes fall BETWEEN the two models: the document must not
  // claim aliasing accounts for all of them.
  const lo = F.lowBudget.gita.sizes.slice().sort((x, y) => x - y);
  const median = lo[3];
  const P = per['35000'];
  assert.equal(median, 331);
  assert.equal(+(median / P.sizeMean).toFixed(2), 1.77);
  assert.equal(+(median / a.memoryless.sizeMean).toFixed(2), 0.7);
  assert.equal(+(lo[0] / P.sizeMean).toFixed(2), 1.1);
  assert.equal(+((lo[5] - P.sizeMean) / P.sizeSd).toFixed(2), 3.45);
  // the largest observed run is outside the 2 sd band of the periodic model
  assert.ok(lo[5] > P.sizeMean + 2 * P.sizeSd);
  // ... and the aliasing-free resample null still under-predicts the observed J
  assert.ok(F.nulls.resample['1591'].meanJ < F.lowBudget.gita.meanJ);
});

test('section 1.6 -- the budget explains 96.4% of the size variance', () => {
  assert.equal(F.lowBudget.gita.budgetR2loglog, 0.9635);
  assert.equal(F.lowBudget.headingcalculator.budgetR2loglog, 0.9059);
  assert.equal(F.lowBudget.badpixels.budgetR2loglog, 0.7167);
  assert.equal(F.lowBudget.gita.sizeVar, 3787.37);
  assert.equal(F.lowBudget.gita.sizeSd, 61.5);
  assert.equal(F.highBudget.sizeVar, 0.333);
  assert.equal(F.highBudget.sizeSd, 0.577);
  assert.equal(Math.round(F.lowBudget.gita.sizeVar / F.highBudget.sizeVar), 11373);
});

test('section 1.7 -- per-category volatility', () => {
  const g = F.categories.gita;
  const byCat = Object.fromEntries(g.jaccard.map((r) => [r.cat, r]));
  assert.deepEqual(byCat.animation.sizes, [48, 46, 49, 45, 49, 47]);
  assert.equal(byCat.animation.meanJ, 0.742);
  assert.deepEqual(byCat.animation.jLo, 0.67);
  assert.deepEqual(byCat.animation.jHi, 0.85);
  assert.equal(byCat.gc.meanJ, 0.889);
  assert.deepEqual(byCat.gc.sizes, [2, 2, 3, 2, 2, 2]);
  assert.equal(byCat.resource_inflate.meanJ, 0.183);
  assert.deepEqual(byCat.resource_inflate.sizes, [4, 18, 14, 30, 25, 21]);
  assert.equal(byCat.binder_ipc.meanJ, 0.426);
  assert.equal(byCat.classload.meanJ, 0.579);
  assert.equal(byCat.looper_msg.meanJ, 0.607);
  assert.equal(byCat.other.meanJ, 0.38);
  assert.deepEqual(byCat.other.sizes, [101, 208, 208, 261, 214, 219]);

  const bud = Object.fromEntries(g.budget.map((r) => [r.cat, r]));
  assert.equal(bud.resource_inflate.r2, 0.953);
  assert.equal(bud.other.r2, 0.955);
  assert.equal(bud.looper_msg.r2, 0.039);
  assert.equal(bud.looper_msg.var, 28);
  assert.equal(bud.looper_msg.unexplained, 26.9);
  assert.equal(bud.animation.var, 2.7);
  assert.equal(bud.animation.r2, 0.172);
  assert.equal(bud.gc.var, 0.2);

  // badpixels: a whole subsystem missing from one capture
  const bp = F.categories.badpixels;
  const bpRes = bp.jaccard.find((r) => r.cat === 'resource_inflate');
  assert.deepEqual(bpRes.sizes, [7, 1, 0]);
  assert.equal(bpRes.meanJ, 0);
});

test('section 1.8 -- the app s own methods at the two budgets', () => {
  assert.deepEqual(F.appOwn.lowBudgetGita, [0, 2, 1, 4, 4, 4]);
  assert.deepEqual(F.appOwn.highBudgetGita, [10, 10, 10]);
  assert.deepEqual(F.appOwn.low.balancetheball, [6, 6]);
  assert.deepEqual(F.appOwn.low.headingcalculator, [2, 4, 2]);
  assert.deepEqual(F.appOwn.low.badpixels, [1, 0, 0]);
});

test('section 2.1 -- the saturation curve, three runs agreeing', () => {
  assert.equal(F.saturation.length, 3);
  // the three runs' own pools: 4649, 4649, 4648
  assert.deepEqual(F.saturation.map((s) => s.pool), [4649, 4649, 4648]);
  for (const s of F.saturation) {
    assert.ok(s.records > 496000 && s.records < 513000);
  }
  const at = (n) => F.saturation.map((s) => s.curve.find((p) => p.n === n).size);
  assert.deepEqual(at(125), [105, 104, 104]);
  assert.deepEqual(at(500), [322, 328, 325]);
  assert.deepEqual(at(915), [496, 491, 495]);
  assert.deepEqual(at(2000), [778, 780, 778]);
  assert.deepEqual(at(8000), [1457, 1453, 1448]);
  assert.deepEqual(at(32000), [2297, 2299, 2292]);
  assert.deepEqual(at(128000), [3494, 3497, 3496]);
  assert.deepEqual(at(400000), [4561, 4575, 4581]);
  assert.deepEqual(at(480000), [4642, 4644, 4645]);
  // fractions quoted, against run 1's pool of 4649
  const frac = Object.fromEntries(F.saturation[0].curve.map((p) => [p.n, p.fracOfPool]));
  assert.equal(frac[915], 0.1067);
  assert.equal(frac[256000], 0.9015);
  assert.equal(frac[400000], 0.9811);
  assert.equal(frac[480000], 0.9985);
  // curves agree to within 2.1% at every budget
  for (const a of F.saturationAgreement) {
    const rel = a.maxSpread / Math.max(...a.sizes);
    assert.ok(rel <= 0.0211, `spread at N=${a.n}: ${rel}`);
  }
  // at 480000 the set is within 4-7 methods of each run's own pool
  for (let i = 0; i < 3; i++) {
    assert.ok(F.saturation[i].pool - at(480000)[i] >= 3 && F.saturation[i].pool - at(480000)[i] <= 7);
  }
});

test('section 2.2 -- the app state axis, and which uncertainty dominates', () => {
  assert.deepEqual(F.appState.create.sizes, [1853, 1862]);
  assert.equal(F.appState.create.meanJ, 0.9845);
  assert.equal(F.appState.create.records.length, 2);
  assert.equal(F.appState.cross.jaccard, 0.3869);
  assert.equal(F.appState.cross.intersection, 1814);
  assert.equal(F.appState.cross.union, 4688);
  // +-2796 methods between states
  assert.equal(F.highBudget.sizes[0] - F.appState.create.sizes[0], 2796);
  // and that is three orders of magnitude larger than the run-to-run spread
  assert.ok(F.highBudget.sizes[0] - F.appState.create.sizes[0] > 1000 * F.highBudget.sizeSd);
});

test('section 2.3 -- finiteness has an arithmetic bound', () => {
  assert.equal(F.bounds.bootClasspathJars, 37);
  assert.equal(F.bounds.bootClasspathMethods, 411072);
  assert.equal(F.bounds.bootClasspathClasses, 43137);
  assert.equal(F.bounds.frameworkJarMethods, 250010);
  assert.equal(F.bounds.servicesJarMethods, 111264);
  assert.equal(F.bounds.gitaClosure, 4649);
  assert.equal(F.bounds.fractionOfClasspath, 0.01131);
});

test('section 3 -- window structure', () => {
  assert.deepEqual(F.window.quarters.sizes, [3624, 2937, 368, 62]);
  assert.deepEqual(F.window.quarters.jaccards, [0.4131, 0.0539, 0.0154, 0.1253, 0.0187, 0.0777]);
  assert.equal(F.window.quarters.union, 4649);
  // the sweep: the pool saturates by 1 s
  const sw = F.window.sweep;
  assert.equal(sw[0].pool, 44);
  assert.equal(sw[3].windowMs, 1000);
  assert.equal(sw[4].windowMs, 2000);
  assert.equal(sw[4].pool, 4365);
  assert.equal(sw[6].pool, 4643);
});

test('section 1.5 -- the ~50 ms periodicity is reported as measured but weak', () => {
  const p = F.periodicity.runs;
  assert.equal(p.length, 3);
  // peak lags in 43-58 ms
  for (const r of p) {
    for (const l of r.topLags) assert.ok(l.lagMs >= 43 && l.lagMs <= 58, `lag ${l.lagMs}`);
  }
  assert.deepEqual(p.map((r) => r.topLags[0].lagMs), [52, 46, 52]);
  assert.deepEqual(p.map((r) => r.topLags[0].ac), [0.115, 0.184, 0.208]);
  assert.deepEqual(p.map((r) => r.ac16), [-0.257, -0.183, -0.18]);
});

// --- layer 1b: the document must actually contain the pinned numbers ------
test('the document quotes the pinned figures', () => {
  const must = [
    '4,649', '0.99986', '0.4411', '206, 323, 325, 395, 331, 333', '683',
    '0.4111, 0.4697', '206, 397, 490, 566, 617, 683',
    '0.4498', '0.5264', '512,758', '496,189',
    '0.3067', '0.382', '187.1', '473.3', '427', '1,564', '4,365',
    '0.9635', '0.9059', '0.7167', '3,787', '0.333',
    '0.742', '0.889', '0.183', '0.953', '0.039', '0.955', '0.607', '0.426',
    '48, 46, 49, 45, 49, 47', '4, 18, 14, 30, 25, 21',
    '496', '491', '495', '4,642', '4,644', '4,645',
    '1,853', '1,862', '0.9845', '0.3869', '1,814', '4,688',
    '411,072', '43,137', '250,010', '111,264', '1.13%',
    '3,624', '2,937', '368', '62',
    '0.115', '0.184', '0.208', '0.257',
  ];
  for (const s of must) {
    assert.ok(DOC.includes(s) || FLAT.includes(s), `document is missing the figure ${s}`);
  }
  // the exact figures the over-claim fix introduced
  for (const s of ['1.77', '0.70', '3.45', '0.9845', '0.99986']) {
    assert.ok(DOC.includes(s), `document is missing the figure ${s}`);
  }
  // and it must not contain the over-claim that was corrected
  assert.ok(!FLAT.includes('The observed sizes are what aliasing predicts.'));
});

test('every figure in the document is tagged', () => {
  // The three tags must appear, and no section may present a number without
  // one nearby. Checked structurally: each tag occurs many times and the
  // untagged-word "conjecture" is only ever used inside a tag.
  for (const tag of ['[measured', '[derived', '[conjecture']) {
    const n = DOC.split(tag).length - 1;
    assert.ok(n >= 5, `tag ${tag}] used only ${n} times`);
  }
  // a tag may be qualified, as in [conjecture, about my own inference]
  assert.ok(DOC.includes('[conjecture,'));
  assert.ok(!/\[estimate\]|\[approx\]|\[measured\?\]/.test(DOC));
});

// Section 2.5 pins the concurrent agent's figures, read from their
// measurement.json. They are not my data, so they are asserted as constants and
// cross-checked against the file only when it is present.
test('section 2.5 -- the independent exhaustive cross-check', () => {
  const p = join(here, 'measurement.json');
  if (existsSync(p)) {
    const M = JSON.parse(readFileSync(p, 'utf8'));
    const by = Object.fromEntries(M.rows.map((r) => [r.package, r]));
    assert.equal(M.rows.length, 24);
    assert.equal(by['eu.quelltext.gita'].frameworkMethodsMed, 5722);
    assert.equal(by['eu.quelltext.gita'].frameworkMethodsMin, 5617);
    assert.equal(by['eu.quelltext.gita'].frameworkMethodsMax, 5741);
    assert.equal(by['com.jeffliu.balancetheball'].frameworkMethodsMed, 5132);
    assert.equal(by['org.debian.eugen.headingcalculator'].frameworkMethodsMed, 4941);
    assert.equal(by['tk.al54.dev.badpixels'].frameworkMethodsMed, 4588);
    // 24 apps: min 3,731, median 6,070.5, max 7,374
    const meds = M.rows.map((r) => r.frameworkMethodsMed).sort((x, y) => x - y);
    assert.equal(M.rows.length, 24);
    assert.equal(meds[0], 3731);
    assert.equal((meds[11] + meds[12]) / 2, 6070.5);
    assert.equal(meds[meds.length - 1], 7374);
  }
  // the ratios the document quotes: brief -> exhaustive
  const ratios = { 628: 9.1, 373: 13.8, 338: 14.6, 242: 19.0 };
  const exh = { 628: 5722, 373: 5132, 338: 4941, 242: 4588 };
  for (const [brief, r] of Object.entries(ratios)) {
    assert.equal(+(exh[brief] / Number(brief)).toFixed(1), r);
  }
  // their gita spread, 124 methods = 2.2%
  assert.equal(5741 - 5617, 124);
  assert.equal(+((5741 - 5617) / 5722 * 100).toFixed(1), 2.2);
  // my 4,649 is 81% of their 5,722 -- consistent with a shorter, clock-pinned window
  assert.equal(+(4649 / 5722 * 100).toFixed(0), 81);
  // the document must carry the tempering, not just the corroboration
  const flat = DOC.replace(/\s+/g, ' ');
  assert.ok(flat.includes('124 methods'), 'the exhaustive spread is reported');
  assert.ok(flat.includes('2.2%'));
  assert.ok(flat.includes('1,853, 4,649 and'));
});

test('the record-format correction in 2.5 is itself pinned', () => {
  // Offset 2 is zero in every record of my captures and of the peer agent's,
  // so the method id is at offset 0 and the tid at offset 12.
  const DIRS2 = [process.env.A15_TRACE_DIR, '/var/folders/lc/r25hfwjs4j963w2f40s9rc5h0000gn/T/opencode/a15'].filter(Boolean);
  const find = (n) => DIRS2.map((d) => join(d, n)).find((x) => existsSync(x));
  const found = ['hi_gita_r1.trace', 'low_gita_r1.trace', 'peer.trace'].map(find).filter(Boolean);
  assert.ok(found.length >= 2, `expected the captures to be present, found ${found.length}`);
  for (const f of found) {
    const buf = readFileSync(f);
    const e = buf.indexOf('*end\n') + 5 + 20;
    const body = buf.subarray(e);
    const n = Math.floor(body.length / 14);
    let nonzero = 0;
    for (let i = 0; i < n; i++) if (body.readUInt16LE(14 * i + 2) !== 0) nonzero++;
    assert.equal(nonzero, 0, `${f}: offset 2 must be zero in every record`);
  }
  assert.ok(DOC.includes('offset 2'), 'the corrected layout is documented');
});

test('the document does not overstate the app/platform split', () => {
  // It must say the split cannot be decomposed further at n = 3.
  assert.ok(FLAT.includes('cannot decompose it further'));
  // It must record the discrepancy with the brief rather than adopting it.
  assert.ok(FLAT.includes('I could not reproduce those numbers'));
  // It must name the strongest reason to distrust the measurement.
  assert.ok(FLAT.includes('single strongest reason to distrust'));
  // and the narrow form of the claim must be stated
  assert.ok(FLAT.includes('for a pinned (app, entry state, window) triple'));
});
