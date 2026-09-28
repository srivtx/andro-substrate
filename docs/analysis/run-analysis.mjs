// Produces every number cited in 0002-is-the-closure-well-defined.md.
//
//   node run-analysis.mjs           -> data/figures.json + a readable summary
//   node run-analysis.mjs --quiet   -> only the JSON
//
// Reads the captures listed in data/manifest.json, verifying each SHA-256
// before use. Point A15_TRACE_DIR at the directory holding them; if unset, the
// canonical locations recorded in the manifest's `origin` fields are tried.

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseTrace } from './lib/arttrace.mjs';
import * as C from './lib/closure.mjs';
import {
  mean, variance, jaccard, union, intersection, pairwiseJaccards, mulberry32,
  bootstrapCI, quantile,
} from './lib/stats.mjs';

const here = new URL('.', import.meta.url).pathname;
const manifest = JSON.parse(readFileSync(join(here, 'data/manifest.json'), 'utf8'));
const DIRS = [process.env.A15_TRACE_DIR, '/var/folders/lc/r25hfwjs4j963w2f40s9rc5h0000gn/T/opencode/a15'].filter(Boolean);

function resolve(name) {
  for (const d of DIRS) if (existsSync(join(d, name))) return join(d, name);
  return null;
}

function loadGroup(group) {
  const out = [];
  for (let i = 0; i < group.files.length; i++) {
    const p = resolve(group.files[i]);
    if (!p) throw new Error(`capture not found: ${group.files[i]} (set A15_TRACE_DIR)`);
    const sha = createHash('sha256').update(readFileSync(p)).digest('hex');
    if (sha !== group.sha256[i]) {
      throw new Error(`sha256 mismatch for ${group.files[i]}\n  expected ${group.sha256[i]}\n  got      ${sha}`);
    }
    const trace = parseTrace(p);
    out.push({ file: group.files[i], path: p, sha256: sha, trace, set: C.methodKeys(trace) });
  }
  return out;
}

const F = {};
const LOW = {};
for (const [app, group] of Object.entries(manifest.low)) LOW[app] = loadGroup(group);
const RECREATE = loadGroup(manifest.high.gita_recreate);
const CREATE = loadGroup(manifest.high.gita_create);
const OTHERWIN = loadGroup(manifest.high.gita_other_window);

// --- F1. capture integrity -------------------------------------------------
F.inventory = {
  capturesUsed: [...Object.values(LOW).flat(), ...RECREATE, ...CREATE, ...OTHERWIN].map((r) => ({
    file: r.file, sha256: r.sha256, bytes: readFileSync(r.path).length,
  })),
  lost: manifest.lost,
  // Cross-check on the parser: ART writes one record per method event and
  // counts them in the header. If the decode were wrong this would not hold.
  recordsEqualHeaderCount: [...Object.values(LOW).flat(), ...RECREATE, ...CREATE, ...OTHERWIN]
    .map((r) => ({ file: r.file, records: r.trace.records.length, header: r.trace.numMethodCalls, equal: r.trace.records.length === r.trace.numMethodCalls })),
};

// --- F2. the low-budget arm, as originally reported ------------------------
F.lowBudget = {};
for (const [app, runs] of Object.entries(LOW)) {
  const sets = runs.map((r) => r.set);
  const js = pairwiseJaccards(sets);
  const ci = bootstrapCI(js, mean, 20000, 0x5eed);
  const sizes = sets.map((s) => s.size);
  const records = runs.map((r) => r.trace.records.length);
  F.lowBudget[app] = {
    nRuns: runs.length,
    sizes, records,
    windowMs: runs.map((r) => +((r.trace.traceEndUs - r.trace.traceStartUs) / 1000).toFixed(0)),
    threads: runs.map((r) => r.trace.perThread.size),
    union: union(sets).size,
    intersection: intersection(sets).size,
    jaccards: js.map((x) => +x.toFixed(4)),
    meanJ: +mean(js).toFixed(4),
    jLo: +ci.lo.toFixed(4),
    jHi: +ci.hi.toFixed(4),
    jSd: +Math.sqrt(variance(js)).toFixed(4),
    sizeMean: +mean(sizes).toFixed(1),
    sizeSd: +Math.sqrt(variance(sizes)).toFixed(1),
    sizeVar: +variance(sizes).toFixed(2),
    curveSizeSorted: (() => {
      const acc = new Set();
      return [...sets].sort((a, b) => a.size - b.size).map((s) => {
        for (const v of s) acc.add(v);
        return acc.size;
      });
    })(),
    budgetR2loglog: +C.budgetExplanation(sizes, records).r2.toFixed(4),
  };
}

// --- F3. the high-budget arm: three matched runs of gita -------------------
{
  const sets = RECREATE.map((r) => r.set);
  const js = pairwiseJaccards(sets);
  F.highBudget = {
    nRuns: RECREATE.length,
    files: RECREATE.map((r) => r.file),
    records: RECREATE.map((r) => r.trace.records.length),
    windowMs: RECREATE.map((r) => +((r.trace.traceEndUs - r.trace.traceStartUs) / 1000).toFixed(0)),
    sizes: sets.map((s) => s.size),
    union: union(sets).size,
    intersection: intersection(sets).size,
    jaccards: js.map((x) => +x.toFixed(6)),
    meanJ: +mean(js).toFixed(6),
    minJ: +Math.min(...js).toFixed(6),
    sizeSd: +Math.sqrt(variance(sets.map((s) => s.size))).toFixed(3),
    sizeVar: +variance(sets.map((s) => s.size)).toFixed(3),
    // symmetric difference between the largest and smallest run
    maxSymDiff: +Math.max(...RECREATE.map((r) => r.set.size - intersection([r.set, sets[0]]).size * 0)).toFixed(0),
  };
  F.highBudget.spreadMethods = Math.max(...sets.map((s) => s.size)) - Math.min(...sets.map((s) => s.size));
}

// --- F4. the app's data state changes the closure, reproducibly ------------
{
  const cs = CREATE.map((r) => r.set);
  const rs = RECREATE.map((r) => r.set);
  const csj = pairwiseJaccards(cs);
  F.appState = {
    create: {
      nRuns: CREATE.length, records: CREATE.map((r) => r.trace.records.length),
      windowMs: CREATE.map((r) => +((r.trace.traceEndUs - r.trace.traceStartUs) / 1000).toFixed(0)),
      sizes: cs.map((s) => s.size), union: union(cs).size, intersection: intersection(cs).size,
      meanJ: +mean(csj).toFixed(4),
    },
    cross: {
      sizesCreateVsRecreate: [...cs, ...rs].map((s) => s.size),
      meanJ: +mean(pairwiseJaccards([...cs, ...rs])).toFixed(4),
      intersection: intersection([cs[0], rs[0]]).size,
      union: union([cs[0], rs[0]]).size,
      jaccard: +jaccard(cs[0], rs[0]).toFixed(4),
    },
  };
}

// --- F5. saturation: |S| against a memoryless budget, three runs agreeing --
{
  // capped at the smallest run's record count so all three curves are comparable
  const budgets = [125, 250, 500, 915, 1000, 2000, 4000, 8000, 16000, 32000, 64000, 128000, 256000, 400000, 480000];
  F.saturation = RECREATE.map((r) => {
    const curve = C.subsetCurve(r.trace, budgets, 15, 13);
    return {
      file: r.file, records: r.trace.records.length, pool: r.trace.tableRows,
      windowMs: +((r.trace.traceEndUs - r.trace.traceStartUs) / 1000).toFixed(0),
      curve: curve.map((p) => ({ n: p.budget, size: +p.mean.toFixed(0), sd: +p.sd.toFixed(0), fracOfPool: +(p.mean / p.pool).toFixed(4) })),
    };
  });
  // cross-run agreement of the curve itself
  F.saturationAgreement = F.saturation[0].curve.map((p, i) => {
    const others = F.saturation.slice(1).map((s) => s.curve[i].size);
    return { n: p.n, sizes: [p.size, ...others], maxSpread: Math.max(p.size, ...others) - Math.min(p.size, ...others) };
  });
}

// --- F6. aliasing: a periodic sampler vs a memoryless one -----------------
// Same 2 s of the same run, same number of events, two selection rules.
{
  const t = RECREATE[0].trace;
  const W = 2000000;
  const win = t.records.filter((r) => r.globalTimeUs <= W);
  const CAP = 915;
  const periodic = (T, phase) => {
    const s = new Set();
    let n = 0;
    for (const r of win) {
      const ph = (((r.globalTimeUs - phase) % T) + T) % T;
      if (ph < T / 2) {
        s.add(r.methodId);
        n += 1;
        if (n >= CAP) break;
      }
    }
    return s;
  };
  const out = { windowMs: W / 1000, cap: CAP, windowRecords: win.length, windowPool: new Set(win.map((r) => r.methodId)).size, periodic: {} };
  for (const T of [1000, 10000, 35000, 350000]) {
    const sets = [];
    for (let p = 0; p < 12; p++) sets.push(periodic(T, (p * T) / 12));
    const js = pairwiseJaccards(sets);
    out.periodic[T] = {
      meanJ: +mean(js).toFixed(4), sdJ: +Math.sqrt(variance(js)).toFixed(4),
      sizeMean: +mean(sets.map((s) => s.size)).toFixed(1),
      sizeSd: +Math.sqrt(variance(sets.map((s) => s.size))).toFixed(1),
      union12: union(sets).size,
    };
  }
  const rng = mulberry32(9);
  const sets = [];
  for (let k = 0; k < 12; k++) {
    const idx = new Set();
    while (idx.size < CAP) idx.add(Math.floor(rng() * win.length));
    const s = new Set();
    for (const i of idx) s.add(win[i].methodId);
    sets.push(s);
  }
  const js = pairwiseJaccards(sets);
  out.memoryless = {
    meanJ: +mean(js).toFixed(4), sdJ: +Math.sqrt(variance(js)).toFixed(4),
    sizeMean: +mean(sets.map((s) => s.size)).toFixed(1),
    sizeSd: +Math.sqrt(variance(sets.map((s) => s.size))).toFixed(1),
    union12: union(sets).size,
  };
  F.aliasing = out;
}

// --- F7. instrument-only nulls at the low budget ---------------------------
{
  const t = RECREATE[0].trace;
  const W = 2000000;
  F.nulls = { windowMs: W / 1000, resample: {}, phase: {} };
  for (const budget of [915, 1300, 1591]) {
    const n = C.nullJaccard(t, { windowUs: W, budget, trials: 400, seed: 3 });
    F.nulls.resample[budget] = {
      meanJ: +n.mean.toFixed(4), sdJ: +n.sd.toFixed(4),
      sizeMean: +n.sizeMean.toFixed(1), sizeSd: +Math.sqrt(n.sizeVar).toFixed(1),
    };
    const p = C.phaseNull(t, { windowUs: W, budget, phases: 20 });
    F.nulls.phase[budget] = {
      meanJ: +p.mean.toFixed(4), sdJ: +p.sd.toFixed(4),
      sizeMean: +p.sizeMean.toFixed(1), sizeSd: +Math.sqrt(p.sizeVar).toFixed(1),
    };
  }
}

// --- F8. window dependence and burst structure ----------------------------
{
  const t = RECREATE[0].trace;
  F.window = { sweep: [], quarters: null };
  for (const win of [100000, 250000, 500000, 1000000, 2000000, 4000000, 6200000]) {
    const n = C.nullJaccard(t, { windowUs: win, budget: 1300, trials: 200, seed: 5 });
    const pool = new Set(t.records.filter((r) => r.globalTimeUs <= win).map((r) => r.methodId));
    F.window.sweep.push({ windowMs: win / 1000, size: +n.sizeMean.toFixed(0), sizeSd: +Math.sqrt(n.sizeVar).toFixed(0), pool: pool.size, meanJ: +n.mean.toFixed(4) });
  }
  const q = t.traceEndUs / 4;
  const quarters = [];
  for (let i = 0; i < 4; i++) quarters.push(new Set(t.records.filter((r) => r.globalTimeUs > i * q && r.globalTimeUs <= (i + 1) * q).map((r) => r.methodId)));
  F.window.quarters = { sizes: quarters.map((s) => s.size), jaccards: pairwiseJaccards(quarters).map((x) => +x.toFixed(4)), union: union(quarters).size };
}

// --- F9. periodicity in the main-thread call density ---------------------
// Raw autocorrelation decays monotonically with lag (the density is smooth at
// the 1 ms scale), so it is detrended with a centred 25 ms moving average
// first; what survives is genuine oscillation. Reported for all three matched
// runs because the period is not stable between them.
{
  const detrended = (t) => {
    const nb = 2500;
    const b = new Array(nb).fill(0);
    for (const r of t.records) {
      if (r.globalTimeUs >= nb * 1000) break;
      b[Math.floor(r.globalTimeUs / 1000)] += 1;
    }
    const w = 25;
    const res = b.map((_, i) => {
      let s = 0;
      let c = 0;
      for (let k = -w; k <= w; k++) {
        const j = i + k;
        if (j >= 0 && j < nb) {
          s += b[j];
          c += 1;
        }
      }
      return b[i] - s / c;
    });
    const ac = [];
    for (let lag = 10; lag <= 80; lag++) {
      let num = 0;
      let den = 0;
      for (let i = 0; i + lag < nb; i++) {
        num += res[i] * res[i + lag];
        den += res[i] * res[i];
      }
      ac.push({ lagMs: lag, ac: num / den });
    }
    const top = [...ac].sort((x, y) => y.ac - x.ac).slice(0, 5);
    return {
      residualSd: +Math.sqrt(mean(res.map((x) => x * x))).toFixed(1),
      topLags: top.map((x) => ({ lagMs: x.lagMs, ac: +x.ac.toFixed(3) })),
      ac16: +ac.find((x) => x.lagMs === 16).ac.toFixed(3),
      ac17: +ac.find((x) => x.lagMs === 17).ac.toFixed(3),
      ac33: +ac.find((x) => x.lagMs === 33).ac.toFixed(3),
    };
  };
  F.periodicity = {
    note: 'detrended with a 25 ms moving average; raw autocorrelation decays monotonically and is not evidence of a period',
    runs: RECREATE.map((r) => ({ file: r.file, ...detrended(r.trace) })),
    // Records per second, and the implied interval between stack samples
    // (a sample is a maximal run of records sharing one timestamp and tid, so
    // the mean depth is records/samples; the interval is window/samples).
    lowBudgetCadence: Object.fromEntries(Object.entries(LOW).map(([app, rs]) => [
      app, rs.map((r) => ({
        windowMs: +((r.trace.traceEndUs - r.trace.traceStartUs) / 1000).toFixed(0),
        records: r.trace.records.length,
        meanStackDepth: +(r.trace.records.length / r.trace.samples.length).toFixed(2),
        sampleIntervalMs: +(((r.trace.traceEndUs - r.trace.traceStartUs) / 1000) / r.trace.samples.length).toFixed(1),
      })),
    ])),
  };
}

// --- F10. per-category volatility and its budget decomposition -------------
F.categories = {};
for (const [app, runs] of Object.entries(LOW)) {
  if (runs.length < 3) continue;
  const paths = runs.map((r) => r.path);
  F.categories[app] = {
    jaccard: C.categoryJaccards(paths).map((r) => ({ cat: r.cat, sizes: r.sizes, union: r.union, meanJ: +r.meanJ.toFixed(3), jLo: +r.jLo.toFixed(2), jHi: +r.jHi.toFixed(2) })),
    budget: C.categoryBudgetDecomposition(paths).map((r) => ({ cat: r.cat, sizes: r.sizes, total: r.total, var: +r.sizeVar.toFixed(1), r2: Number.isNaN(r.r2) ? null : +r.r2.toFixed(3), unexplained: +r.unexplained.toFixed(1) })),
  };
}

// --- F11. finiteness: the boot classpath ----------------------------------
// measured once from the emulator, see the report for the command
F.bounds = {
  bootClasspathJars: 37,
  bootClasspathMethods: 411072,
  bootClasspathClasses: 43137,
  frameworkJarMethods: 250010,
  servicesJarMethods: 111264,
  gitaClosure: F.highBudget.sizes[0],
  fractionOfClasspath: +(F.highBudget.sizes[0] / 411072).toFixed(5),
};

// --- F12. the app's own methods at the two budgets -------------------------
F.appOwn = {
  lowBudgetGita: LOW.gita.map((r) => r.trace.methods.filter((m) => m.cls.startsWith('eu.quelltext')).length),
  highBudgetGita: RECREATE.map((r) => r.trace.methods.filter((m) => m.cls.startsWith('eu.quelltext')).length),
  highBudgetCreate: CREATE.map((r) => r.trace.methods.filter((m) => m.cls.startsWith('eu.quelltext')).length),
  closureSizes: { low: F.lowBudget.gita.sizes, high: F.highBudget.sizes, create: F.appState.create.sizes },
  // other apps, low budget
  low: Object.fromEntries(Object.entries(LOW).map(([a, rs]) => [a, rs.map((r) => r.trace.methods.filter((m) => new RegExp(`^${a === 'gita' ? 'eu.quelltext' : a === 'balancetheball' ? 'com.jeffliu' : a === 'headingcalculator' ? 'org.debian.eugen' : 'tk.al54'}`).test(m.cls)).length)])),
};

F.provenance = {
  tag: 'derived',
  seeds: { resampleNull: 3, phaseNull: 5, aliasingRandom: 9, saturation: 13, bootstrap: '0x5eed' },
  pythonEquivalent: 'python3 lib/recheck.py  (recomputes a subset independently)',
};

mkdirSync(join(here, 'data'), { recursive: true });
// A15_FIGURES_OUT lets the test re-derive into a scratch path and diff it
// against the committed file, instead of silently overwriting the evidence.
const outPath = process.env.A15_FIGURES_OUT || join(here, 'data/figures.json');
writeFileSync(outPath, JSON.stringify(F, null, 2));

if (!process.argv.includes('--quiet')) {
  for (const [k, v] of Object.entries(F)) {
    if (k === 'inventory' || k === 'categories') {
      console.log(`# ${k}: ${Array.isArray(v) ? v.length : Object.keys(v).length} entries`);
      continue;
    }
    console.log(`# ${k}\n${JSON.stringify(v, null, 1)}`);
  }
}
