// Statistics used by the closure analysis. Deterministic: every randomised
// routine takes an explicit seed so the test can pin the numbers.

export function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function jaccard(a, b) {
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  let inter = 0;
  for (const v of small) if (large.has(v)) inter += 1;
  const union = a.size + b.size - inter;
  return union === 0 ? 1 : inter / union;
}

export function union(sets) {
  const u = new Set();
  for (const s of sets) for (const v of s) u.add(v);
  return u;
}

export function intersection(sets) {
  if (!sets.length) return new Set();
  const out = new Set(sets[0]);
  for (const v of [...out]) {
    for (let i = 1; i < sets.length; i++) {
      if (!sets[i].has(v)) {
        out.delete(v);
        break;
      }
    }
  }
  return out;
}

export function pairs(n) {
  const out = [];
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) out.push([i, j]);
  return out;
}

export function pairwiseJaccards(sets) {
  return pairs(sets.length).map(([i, j]) => jaccard(sets[i], sets[j]));
}

export function mean(xs) {
  return xs.reduce((a, b) => a + b, 0) / xs.length;
}

export function variance(xs) {
  if (xs.length < 2) return 0;
  const m = mean(xs);
  return xs.reduce((a, b) => a + (b - m) ** 2, 0) / (xs.length - 1);
}

export function quantile(xs, q) {
  const s = [...xs].sort((a, b) => a - b);
  if (!s.length) return NaN;
  const pos = (s.length - 1) * q;
  const lo = Math.floor(pos);
  const hi = Math.ceil(pos);
  return lo === hi ? s[lo] : s[lo] + (s[hi] - s[lo]) * (pos - lo);
}

// Percentile bootstrap over the *pairs* of runs. Resampling pairs keeps the
// dependence structure (a run appears in many pairs) approximately intact and
// is the honest interval for a 6-run design.
export function bootstrapCI(values, stat, iters, seed) {
  const rng = mulberry32(seed);
  const draws = [];
  for (let b = 0; b < iters; b++) {
    const s = Array.from({ length: values.length }, () => values[Math.floor(rng() * values.length)]);
    draws.push(stat(s));
  }
  return { lo: quantile(draws, 0.025), hi: quantile(draws, 0.975), draws };
}

// Marginal-addition curve: |union of k runs| for k = 1..n, adding runs in a
// fixed (caller-supplied) order.
export function unionCurve(sets) {
  const acc = new Set();
  const out = [];
  for (const s of sets) {
    for (const v of s) acc.add(v);
    out.push(acc.size);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Saturation models for |S(N)|, N = number of stack records sampled.
//
// powerlaw:  |S| = a * N^b            (no finite asymptote for b > 0)
// saturating: |S| = a * (N/(N+k))     (finite asymptote a)
//
// Fitted by log-space grid search + local refinement, then a parametric
// bootstrap over the residuals for the asymptote interval.
// ---------------------------------------------------------------------------

export function fitPowerLaw(points) {
  // log|S| = log a + b log N  -> ordinary least squares on the log points.
  const xs = points.map(([n, s]) => Math.log(n));
  const ys = points.map(([, s]) => Math.log(s));
  const mx = mean(xs);
  const my = mean(ys);
  let num = 0;
  let den = 0;
  for (let i = 0; i < xs.length; i++) {
    num += (xs[i] - mx) * (ys[i] - my);
    den += (xs[i] - mx) ** 2;
  }
  const b = num / den;
  const a = Math.exp(my - b * mx);
  const resid = points.map(([n, s], i) => Math.log(s) - (Math.log(a) + b * Math.log(n)));
  return { a, b, logResiduals: resid, rmse: Math.sqrt(mean(resid.map((r) => r ** 2))) };
}

export function fitSaturating(points) {
  // |S| = a * N/(N+k). For fixed k this is linear in a, so scan k and keep
  // the least-squares a. Refine k on a log grid.
  let best = null;
  for (let e = -1; e <= 8; e += 0.02) {
    const k = Math.exp(e) * 100;
    let num = 0;
    let den = 0;
    for (const [n, s] of points) {
      const f = n / (n + k);
      num += f * s;
      den += f * f;
    }
    const a = num / den;
    let sse = 0;
    for (const [n, s] of points) {
      sse += (s - a * (n / (n + k))) ** 2;
    }
    if (!best || sse < best.sse) best = { a, k, sse };
  }
  const { a, k } = best;
  const resid = points.map(([n, s]) => s - a * (n / (n + k)));
  return { a, k, residuals: resid, sse: best.sse, rmse: Math.sqrt(best.sse / points.length) };
}

export function logspace(lo, hi, count) {
  const out = [];
  for (let i = 0; i < count; i++) out.push(Math.exp(Math.log(lo) + ((Math.log(hi) - Math.log(lo)) * i) / (count - 1)));
  return out;
}
