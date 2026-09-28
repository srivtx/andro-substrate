// The closure experiments for docs/analysis/0002-is-the-closure-well-defined.md.
//
// Every number the report cites is produced here, from the ART traces, with an
// explicit seed for anything randomised.

import { existsSync } from 'node:fs';
import { parseTrace } from './arttrace.mjs';
import {
  mulberry32, jaccard, union, intersection, pairwiseJaccards, mean, variance,
  quantile, bootstrapCI, unionCurve, fitPowerLaw, fitSaturating, logspace,
} from './stats.mjs';

export const RUNS = {
  gita: [1, 2, 3, 4, 5, 6].map((i) => `/tmp/run${i}.trace`),
  balancetheball: [
    '/tmp/cand_com.jeffliu.balancetheball_1.trace',
    '/tmp/cand_com.jeffliu.balancetheball_3.trace',
  ],
  headingcalculator: [1, 2, 3].map(
    (i) => `/tmp/cand_org.debian.eugen.headingcalculator_${i}.trace`),
  badpixels: [1, 2, 3].map((i) => `/tmp/cand_tk.al54.dev.badpixels_${i}.trace`),
};

export const LONG_RUNS = {
  gita_a: '/Users/zen/Desktop/uni/andro-substrate/trace/scratch/gita_full.trace',
  gita_b: '/Users/zen/Desktop/uni/andro-substrate/trace/scratch/clean.trace',
};

export function methodKeys(trace) {
  return new Set(trace.methods.map((m) => `${m.cls}#${m.name}${m.sig}`));
}

export function load(paths) {
  const out = [];
  for (const p of paths) {
    if (!existsSync(p)) continue;
    try {
      out.push({ path: p, trace: parseTrace(p) });
    } catch (e) {
      // A truncated or empty capture is a fact about the capture, not an
      // error: record it in `rejected` and carry on.
    }
  }
  return out;
}

export function rejected(paths) {
  const out = [];
  for (const p of paths) {
    if (!existsSync(p)) {
      out.push({ file: p.split('/').pop(), why: 'absent' });
      continue;
    }
    try {
      parseTrace(p);
    } catch (e) {
      out.push({ file: p.split('/').pop(), why: e.message });
    }
  }
  return out;
}

// --------------------------------------------------------------------------
// E1. Per-app run-to-run distribution.
// --------------------------------------------------------------------------
export function perApp(paths) {
  const runs = load(paths);
  const sets = runs.map((r) => methodKeys(r.trace));
  const u = union(sets);
  const x = intersection(sets);
  const js = pairwiseJaccards(sets);
  const ci = js.length ? bootstrapCI(js, mean, 20000, 0x5eed) : null;
  return {
    files: runs.map((r) => r.path),
    sizes: sets.map((s) => s.size),
    records: runs.map((r) => r.trace.records.length),
    windowMs: runs.map((r) => (r.trace.traceEndUs - r.trace.traceStartUs) / 1000),
    union: u.size,
    intersection: x.size,
    jaccards: js,
    meanJ: js.length ? mean(js) : NaN,
    jLo: ci ? ci.lo : NaN,
    jHi: ci ? ci.hi : NaN,
    jVar: js.length > 1 ? variance(js) : 0,
    sizeMean: mean(sets.map((s) => s.size)),
    sizeVar: variance(sets.map((s) => s.size)),
    curveSizeSorted: unionCurve([...sets].sort((a, b) => a.size - b.size)),
  };
}

// --------------------------------------------------------------------------
// E2. The measurement null: resample one fixed run and ask how much
// run-to-run instability appears with the app held constant.
// --------------------------------------------------------------------------
function samplesInWindow(trace, windowUs) {
  const start = trace.traceStartUs;
  return trace.samples.filter((s) => s.timeUs - start <= windowUs);
}

// Resample whole samples (stacks) with replacement until the record budget is
// reached. Returns the set of method keys seen.
export function resampleBudget(samples, budget, rng) {
  const out = new Set();
  let n = 0;
  if (!samples.length) return { set: out, records: 0 };
  while (n < budget) {
    const s = samples[Math.floor(rng() * samples.length)];
    for (const m of s.stack) out.add(m);
    n += s.stack.length;
  }
  return { set: out, records: n };
}

export function nullJaccard(trace, { windowUs, budget, trials = 400, seed = 1 }) {
  const samples = windowUs ? samplesInWindow(trace, windowUs) : trace.samples;
  const rng = mulberry32(seed);
  const js = [];
  const sizes = [];
  for (let t = 0; t < trials; t++) {
    const a = resampleBudget(samples, budget, rng);
    const b = resampleBudget(samples, budget, rng);
    js.push(jaccard(a.set, b.set));
    sizes.push(a.set.size);
  }
  return {
    js, mean: mean(js), var: variance(js), sd: Math.sqrt(variance(js)),
    p05: quantile(js, 0.05), p50: quantile(js, 0.5), p95: quantile(js, 0.95),
    sizeMean: mean(sizes), sizeVar: variance(sizes), trials,
  };
}

export function budgetSweep(trace, { windowUs, budgets, trials = 300, seed = 7 }) {
  return budgets.map((budget) => {
    const r = nullJaccard(trace, { windowUs, budget, trials, seed });
    return { budget, mean: r.mean, sd: r.sd, p05: r.p05, p95: r.p95, sizeMean: r.sizeMean, sizeVar: r.sizeVar };
  });
}

// --------------------------------------------------------------------------
// E3. Saturation: |S(N)| as a function of the record budget, and whether it
// approaches a finite asymptote.
// --------------------------------------------------------------------------
export function saturationCurve(trace, { windowUs, budgets, reps = 20, seed = 11 }) {
  const samples = windowUs ? samplesInWindow(trace, windowUs) : trace.samples;
  const rng = mulberry32(seed);
  return budgets.map((budget) => {
    const sizes = [];
    for (let r = 0; r < reps; r++) sizes.push(resampleBudget(samples, budget, rng).set.size);
    return { budget, mean: mean(sizes), sd: Math.sqrt(variance(sizes)), min: Math.min(...sizes), max: Math.max(...sizes) };
  });
}

export function fits(curve) {
  const points = curve.map((p) => [p.budget, p.mean]);
  const pow = fitPowerLaw(points);
  const sat = fitSaturating(points);
  return { power: { a: pow.a, b: pow.b, rmse: pow.rmse }, saturating: { a: sat.a, k: sat.k, rmse: sat.rmse } };
}

// --------------------------------------------------------------------------
// E4. Real two-run Jaccard at the high budget.
// --------------------------------------------------------------------------
export function realJaccard(pathA, pathB) {
  const a = methodKeys(parseTrace(pathA));
  const b = methodKeys(parseTrace(pathB));
  return { a: a.size, b: b.size, jaccard: jaccard(a, b), inter: intersection([a, b]).size, union: union([a, b]).size };
}

// --------------------------------------------------------------------------
// E5. Cause attribution: which categories of framework call are volatile?
// --------------------------------------------------------------------------
export const CATEGORIES = [
  ['gc', /^(java\.lang\.ref\.|java\.lang\.System\.gc|java\.lang\.Runtime\.gc|java\.lang\.GC_|jdk\.internal\.gc)/],
  ['finalize', /^(java\.lang\.ref\.Finalizer|java\.lang\.ref\.ReferenceQueue|java\.lang\.ref\.Phantom)/],
  ['animation', /(Choreographer|hwui|HWUI|ThreadedRenderer|RenderThread|SurfaceFlinger|ViewRootImpl|doFrame|AnimationHandler|ValueAnimator|ObjectAnimator)/],
  ['network', /^(java\.net\.|javax\.net\.|org\.apache\.http|okhttp|okio|java\.io\..*Stream)/],
  ['binder_ipc', /^(android\.os\.(Binder|IBinder|Parcel|RemoteException|ServiceManager|Parcelable)|android\.os\.IInterface)/],
  ['resource_inflate', /^android\.(content\.res|view\.inflater|app\.Resources|content\.Context\.get)/],
  ['classload', /^(java\.lang\.ClassLoader|dalvik\.system\.|java\.lang\.reflect\.)/],
  ['looper_msg', /^(android\.os\.(Looper|Handler|Message)|android\.app\.ActivityThread|android\.app\.servertransaction)/],
  ['collection', /^(java\.util\.(?!HashMap\$)|java\.lang\.StringBuilder)/],
  ['logging', /^(android\.util\.Log|java\.util\.logging)/],
];

export function categorise(cls, name) {
  const key = `${cls}.${name}`;
  for (const [cat, re] of CATEGORIES) if (re.test(key)) return cat;
  return 'other';
}

export function categoryJaccards(paths, minSize = 1) {
  const runs = load(paths);
  const byRun = runs.map((r) => {
    const m = new Map();
    for (const x of r.trace.methods) {
      const cat = categorise(x.cls, x.name);
      if (!m.has(cat)) m.set(cat, new Set());
      m.get(cat).add(`${x.cls}#${x.name}${x.sig}`);
    }
    return m;
  });
  const cats = new Set();
  for (const m of byRun) for (const c of m.keys()) cats.add(c);
  const out = [];
  for (const cat of cats) {
    const sets = byRun.map((m) => m.get(cat) || new Set());
    if (mean(sets.map((s) => s.size)) < minSize) continue;
    const js = pairwiseJaccards(sets);
    const u = union(sets);
    // variance of the per-run size across runs
    const sizes = sets.map((s) => s.size);
    out.push({
      cat,
      sizes,
      union: u.size,
      meanJ: js.length ? mean(js) : NaN,
      jLo: js.length ? quantile(js, 0.05) : NaN,
      jHi: js.length ? quantile(js, 0.95) : NaN,
      sizeMean: mean(sizes),
      sizeVar: variance(sizes),
      sizeCV: mean(sizes) ? Math.sqrt(variance(sizes)) / mean(sizes) : NaN,
    });
  }
  return out.sort((a, b) => b.sizeMean - a.sizeMean);
}

// --------------------------------------------------------------------------
// E6. How much of the size variance is explained by the sample budget alone?
// --------------------------------------------------------------------------
export function budgetExplanation(sizes, records) {
  const xs = records.map(Math.log);
  const ys = sizes.map(Math.log);
  const mx = mean(xs);
  const my = mean(ys);
  let num = 0;
  let den = 0;
  for (let i = 0; i < xs.length; i++) {
    num += (xs[i] - mx) * (ys[i] - my);
    den += (xs[i] - mx) ** 2;
  }
  const b = num / den;
  const a = my - b * mx;
  let sse = 0;
  for (let i = 0; i < xs.length; i++) sse += (ys[i] - (a + b * xs[i])) ** 2;
  const sst = ys.reduce((acc, y) => acc + (y - my) ** 2, 0);
  return { slope: b, intercept: a, r2: sst === 0 ? 1 : 1 - sse / sst, n: xs.length };
}

// --------------------------------------------------------------------------
// E7. The cadence-matched null.
//
// E2's null resamples stacks uniformly, which destroys the temporal correlation
// of a real sampler (ART samples one thread every `interval`, so consecutive
// stacks in a run are near-identical). That makes E2 too pessimistic. This
// null instead decimates one fixed run at the *same cadence and window* as the
// real runs and varies only the sample phase: the app, the window and the
// sampler rate are all held fixed, and the only thing that differs is which
// stacks the sampler lands on.
// --------------------------------------------------------------------------
export function decimateSet(samples, budget, phase) {
  const out = new Set();
  const total = samples.reduce((a, s) => a + s.stack.length, 0);
  const m = Math.max(1, Math.floor(total / budget));
  let n = 0;
  for (let i = phase; i < samples.length && n < budget; i += m) {
    for (const x of samples[i].stack) out.add(x);
    n += samples[i].stack.length;
  }
  return { set: out, records: n };
}

export function phaseNull(trace, { windowUs, budget, phases = 24 }) {
  const samples = windowUs ? samplesInWindow(trace, windowUs) : trace.samples;
  const sets = [];
  const recs = [];
  for (let p = 0; p < phases; p++) {
    const d = decimateSet(samples, budget, p);
    sets.push(d.set);
    recs.push(d.records);
  }
  const js = pairwiseJaccards(sets);
  const sizes = sets.map((s) => s.size);
  return {
    sets, js, records: recs,
    mean: mean(js), sd: Math.sqrt(variance(js)), var: variance(js),
    sizeMean: mean(sizes), sizeVar: variance(sizes),
  };
}

// --------------------------------------------------------------------------
// E8. Budget decomposition of the per-category variance.
//
// For each category, regress the per-run observed count on the per-run record
// count (the sampler's budget). R^2 is the fraction of the run-to-run variance
// in that count that the budget alone explains. A category whose variance is
// not explained by the budget is the only place genuine app-side variation can
// be hiding.
// --------------------------------------------------------------------------
export function budgetR2(xs, ys) {
  const n = xs.length;
  if (n < 3) return NaN;
  const mx = mean(xs);
  const my = mean(ys);
  let num = 0;
  let den = 0;
  for (let i = 0; i < n; i++) {
    num += (xs[i] - mx) * (ys[i] - my);
    den += (xs[i] - mx) ** 2;
  }
  if (den === 0) return NaN;
  const b = num / den;
  const a = my - b * mx;
  let sse = 0;
  let sst = 0;
  for (let i = 0; i < n; i++) {
    sse += (ys[i] - (a + b * xs[i])) ** 2;
    sst += (ys[i] - my) ** 2;
  }
  return sst === 0 ? NaN : 1 - sse / sst;
}

export function categoryBudgetDecomposition(paths) {
  const runs = load(paths);
  const records = runs.map((r) => r.trace.records.length);
  const byRun = runs.map((r) => {
    const m = new Map();
    for (const x of r.trace.methods) {
      const cat = categorise(x.cls, x.name);
      if (!m.has(cat)) m.set(cat, new Set());
      m.get(cat).add(`${x.cls}#${x.name}${x.sig}`);
    }
    return m;
  });
  const cats = new Set();
  for (const m of byRun) for (const c of m.keys()) cats.add(c);
  const out = [];
  for (const cat of cats) {
    const sizes = byRun.map((m) => (m.get(cat) || new Set()).size);
    const tot = sizes.reduce((a, b) => a + b, 0);
    if (tot < 6) continue;
    out.push({
      cat, sizes, records, total: tot,
      r2: budgetR2(records, sizes),
      sizeVar: variance(sizes),
      unexplained: variance(sizes) * (1 - (budgetR2(records, sizes) || 0)),
    });
  }
  return out.sort((a, b) => b.total - a.total);
}

// --------------------------------------------------------------------------
// E9. Saturation without replacement.
//
// E7 resamples stacks *with* replacement, which wastes budget: drawing N
// records from a pool of M distinct records only sees M(1-e^(-N/M)) of them.
// This one draws a simple random subset of N distinct records, so |S|(N) is the
// curve a perfectly memoryless sampler of budget N would produce, and it
// reaches the pool exactly at N = M.
// --------------------------------------------------------------------------
export function subsetCurve(trace, budgets, reps = 20, seed = 13) {
  const M = trace.records.length;
  const rng = mulberry32(seed);
  const out = [];
  for (const budget of budgets) {
    if (budget > M) continue;
    const sizes = [];
    for (let r = 0; r < reps; r++) {
      // reservoir-free: partial Fisher-Yates over indices, budget of them
      const idx = new Set();
      let need = budget;
      while (need > 0) {
        const i = Math.floor(rng() * M);
        if (!idx.has(i)) {
          idx.add(i);
          need -= 1;
        }
      }
      const s = new Set();
      for (const i of idx) s.add(trace.records[i].methodId);
      sizes.push(s.size);
    }
    out.push({ budget, mean: mean(sizes), sd: Math.sqrt(variance(sizes)), min: Math.min(...sizes), max: Math.max(...sizes), pool: trace.tableRows });
  }
  return out;
}
