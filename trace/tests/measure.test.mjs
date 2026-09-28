/**
 * Tests for `trace/measure.mjs`.
 *
 *   node --test trace/tests/
 *
 * Three jobs, in order of how much they protect:
 *
 * 1. **A failed capture is never a zero.** The most consequential bug this file
 *    could have is counting a 0-byte trace as "this app needed no framework
 *    methods". `a_failed_capture_is_not_a_zero` constructs exactly that case.
 * 2. **Capture modes are never pooled.** `recreate` counts creation plus
 *    teardown and `idle` counts almost nothing; intersecting them would report
 *    a number describing no app.
 * 3. **Set arithmetic and ordering.** The convergence curve depends on run
 *    order, so it is averaged over every ordering; and grouping must not depend
 *    on the order the filesystem happened to return.
 *
 * Everything here is pure. No device, no trace file, no network.
 */

import assert from 'node:assert/strict';
import { test, describe } from 'node:test';

import {
  MAX_ENUMERATED_RUNS,
  buildReport,
  convergence,
  convergenceAcrossOrderings,
  groupCoverage,
  groupRuns,
  intersectAll,
  jaccard,
  pairwiseJaccard,
  permutations,
  reportGroup,
  samplingLabel,
  teardownConfound,
  unionAll,
  weakestCoverage,
} from '../measure.mjs';

const S = (...xs) => new Set(xs);

describe('jaccard', () => {
  test('identical sets are 1 and empty-union is undefined, not 1', () => {
    assert.equal(jaccard(S(1, 2), S(1, 2)), 1);
    // Two empty sets share nothing, and calling that "perfectly similar" is how
    // a failed capture turns into a perfect score.
    assert.equal(jaccard(new Set(), new Set()), null);
  });

  test('disjoint and partial overlap', () => {
    assert.equal(jaccard(S(1, 2), S(3, 4)), 0);
    assert.equal(jaccard(S(1, 2, 3), S(2, 3, 4)), 2 / 4);
  });

  test('is symmetric', () => {
    const a = S('x', 'y');
    const b = S('y', 'z');
    assert.equal(jaccard(a, b), jaccard(b, a));
  });
});

describe('pairwiseJaccard', () => {
  test('one pair per unordered combination, in order', () => {
    const p = pairwiseJaccard([S(1, 2), S(2, 3), S(3, 4)]);
    assert.equal(p.length, 3);
    assert.deepEqual(p.map((x) => [x.i, x.j]), [[0, 1], [0, 2], [1, 2]]);
  });

  test('a single run has no pairs', () => {
    assert.deepEqual(pairwiseJaccard([S(1)]), []);
  });
});

describe('convergence', () => {
  test('is monotone and ends at the union', () => {
    const c = convergence([S(1, 2), S(2, 3), S(1, 2, 3, 4)]);
    assert.deepEqual(c, [2, 3, 4]);
    assert.deepEqual([...c].sort((a, b) => a - b), c);
    assert.equal(c.at(-1), unionAll([S(1, 2), S(2, 3), S(1, 2, 3, 4)]).size);
  });

  test('a later run can add nothing', () => {
    assert.deepEqual(convergence([S(1, 2), S(1, 2), S(1, 2)]), [2, 2, 2]);
  });
});

describe('convergenceAcrossOrderings', () => {
  test('enumerates every permutation when small', () => {
    const r = convergenceAcrossOrderings([S(1), S(2), S(3)]);
    assert.equal(r.enumerated, 6);
  });

  test('falls back to one ordering beyond the cap, and says so', () => {
    const many = Array.from({ length: MAX_ENUMERATED_RUNS + 1 }, (_, i) => S(i));
    const r = convergenceAcrossOrderings(many);
    assert.equal(r.enumerated, 1);
  });

  test('the mean curve does not depend on capture order', () => {
    const sets = [S('a'), S('b', 'c'), S('c', 'd')];
    const r = convergenceAcrossOrderings(sets);
    // |union of 1| varies with which run goes first, so min < max, but the
    // bracketing is tight and the final value is order-free.
    assert.ok(r.min[0] < r.max[0]);
    assert.ok(r.min.every((v, i) => v <= r.mean[i] + 1e-9));
    assert.ok(r.max.every((v, i) => v >= r.mean[i] - 1e-9));
    const last = sets.length - 1;
    assert.equal(r.mean[last], r.min[last]);
    assert.equal(r.mean[last], r.max[last]);
  });

  test('permutations is a complete enumeration', () => {
    const p = permutations([1, 2, 3]);
    assert.equal(p.length, 6);
    assert.equal(new Set(p.map((x) => x.join(''))).size, 6);
  });
});

describe('intersectAll and unionAll', () => {
  test('intersection and union', () => {
    assert.deepEqual([...intersectAll([S(1, 2, 3), S(2, 3, 4), S(3, 4, 5)])], [3]);
    assert.deepEqual([...unionAll([S(1), S(2)])].sort(), [1, 2]);
  });

  test('an empty group is a no-op, no groups is empty', () => {
    assert.equal(intersectAll([]).size, 0);
    assert.equal(intersectAll([S(1, 2), new Set()]).size, 0);
  });
});

describe('groupRuns', () => {
  const rec = (packageName, captureMode, run) => ({ package: packageName, captureMode, run });

  test('orders by package, mode, then run — not by input order', () => {
    const input = [rec('b', 'recreate', 2), rec('a', 'idle', 1), rec('b', 'recreate', 1), rec('a', 'recreate', 3)];
    const g = groupRuns(input);
    assert.deepEqual(
      g.map((x) => `${x.package}/${x.captureMode}/${x.runs.map((r) => r.run).join('')}`),
      ['a/idle/1', 'a/recreate/3', 'b/recreate/12'],
    );
  });

  test('is insensitive to a shuffle of its input', () => {
    const input = [rec('a', 'recreate', 1), rec('b', 'recreate', 1), rec('a', 'idle', 1)];
    const once = JSON.stringify(groupRuns(input));
    const twice = JSON.stringify(groupRuns([...input].reverse()));
    assert.equal(once, twice);
  });
});

describe('coverage labelling', () => {
  test('a data-file-overflow run makes the group a truncated lower bound', () => {
    // ART's ring buffer filled and entries were dropped. The method table is a
    // subset of what ran, so the group is a lower bound however it was
    // instrumented. 8 of 64 usable captures in this study hit this.
    assert.equal(
      groupCoverage([{ mode: 'exhaustive', dataFileOverflow: true }]),
      'TRUNCATED (data-file-overflow in 1/1 run(s)) — lower bound',
    );
    assert.equal(
      groupCoverage([{ mode: 'exhaustive', dataFileOverflow: false }, { mode: 'exhaustive', dataFileOverflow: true }]),
      'TRUNCATED (data-file-overflow in 1/2 run(s)) — lower bound',
    );
    assert.equal(groupCoverage([{ mode: 'exhaustive', dataFileOverflow: false }]), 'exhaustive');
    // Truncation outranks a run whose mode is not even known.
    assert.match(
      groupCoverage([{ mode: 'undetermined', dataFileOverflow: true }]),
      /^TRUNCATED/,
    );
  });



  test('the continuous layout cannot certify absence of truncation', () => {
    // It has no preamble, so no `data-file-overflow` flag exists. Absence of a
    // warning is absence of evidence.
    assert.equal(
      groupCoverage([{ mode: 'exhaustive', layout: 'continuous', dataFileOverflow: null }]),
      'exhaustive (overflow NOT verifiable: continuous layout carries no flag) — unverifiable',
    );
    // A batched run alongside it does NOT restore the claim: the union
    // inherits the weakest check of its parts, exactly as a union inherits the
    // weakest coverage.
    assert.equal(
      groupCoverage([
        { mode: 'exhaustive', layout: 'continuous', dataFileOverflow: null },
        { mode: 'exhaustive', layout: 'batched', dataFileOverflow: false },
      ]),
      'exhaustive (overflow NOT verifiable: continuous layout carries no flag) — unverifiable',
    );
    // Only if every run is batched-and-verified can the strong claim be made.
    assert.equal(
      groupCoverage([
        { mode: 'exhaustive', layout: 'batched', dataFileOverflow: false },
        { mode: 'exhaustive', layout: 'batched', dataFileOverflow: false },
      ]),
      'exhaustive',
    );
  });

  test('a group is exhaustive only if every run is', () => {
    assert.equal(groupCoverage([{ mode: 'exhaustive' }, { mode: 'exhaustive' }]), 'exhaustive');
    assert.equal(groupCoverage([{ mode: 'exhaustive' }, { mode: 'sampled', sampling_us: 100 }]), 'sampled@100us (lower bound)');
    assert.equal(groupCoverage([{ mode: 'undetermined' }]), 'undetermined (lower bound)');
  });

  test('weakest coverage wins across apps', () => {
    assert.equal(weakestCoverage(['exhaustive', 'exhaustive']), 'exhaustive');
    assert.equal(weakestCoverage(['exhaustive', 'sampled@100us (lower bound)']), 'sampled@100us (lower bound)');
  });
});

describe('teardownConfound', () => {
  const grp = (packageName, captureMode, keys, sampling = 'full') => ({
    package: packageName,
    captureMode,
    sampling,
    runsUsed: 1,
    keys: S(...keys),
  });

  test('attributes to teardown exactly what creation alone does not explain', () => {
    // R = creation {a,b} + teardown {c,d}; C = creation only {a,b}.
    const r = teardownConfound([grp('p', 'recreate', ['a', 'b', 'c', 'd']), grp('p', 'create', ['a', 'b'])])[0];
    assert.equal(r.recreate, 4);
    assert.equal(r.create, 2);
    assert.equal(r.explainedByCreation, 2);
    assert.equal(r.teardownAttributable, 2);
    assert.equal(r.shareOfRecreate, 0.5);
  });

  test('a recreate window that creation fully explains attributes nothing to teardown', () => {
    const r = teardownConfound([grp('p', 'recreate', ['a', 'b']), grp('p', 'create', ['a', 'b', 'c'])])[0];
    assert.equal(r.teardownAttributable, 0);
    assert.equal(r.explainedByCreation, 2);
    assert.equal(r.shareOfRecreate, 0);
  });

  test('skips apps with no usable create run rather than guessing', () => {
    // balancetheball consumes BACK, so it has a recreate run and no create run.
    const r = teardownConfound([grp('p', 'recreate', ['a', 'b', 'c'])]);
    assert.deepEqual(r, []);
  });

  test('ignores sampled recreate groups and reports teardown/idle when present', () => {
    const r = teardownConfound([
      grp('p', 'recreate', ['a', 'b', 'c'], 's?us'),
      grp('p', 'recreate', ['a', 'b', 'c']),
      grp('p', 'create', ['a', 'b']),
      grp('p', 'teardown', ['c']),
      grp('p', 'idle', ['a']),
    ]);
    assert.equal(r.length, 1, 'the sampled recreate group must not be measured');
    assert.equal(r[0].teardown, 1);
    assert.equal(r[0].idle, 1);
    assert.equal(r[0].teardownAttributable, 1);
    assert.equal(r[0].teardownVsAttributableJaccard, 1);
  });

  test('the BACK teardown set is a proxy and its disagreement is reported', () => {
    const r = teardownConfound([
      grp('p', 'recreate', ['a', 'b', 'c', 'd']),
      grp('p', 'create', ['a', 'b']),
      grp('p', 'teardown', ['c', 'e']),
    ])[0];
    // R\C = {c,d}; T = {c,e}. They are not the same set, and the number that
    // says so is in the record.
    assert.equal(r.teardownAttributable, 2);
    assert.equal(jaccard(new Set(['c', 'd']), S('c', 'e')), 1 / 3);
    assert.equal(r.teardownVsAttributableJaccard, 1 / 3);
  });
});

describe('failed captures', () => {
  const run = (over) => ({
    name: 'r', run: 1, outcome: 'ok', mode: 'exhaustive', frameworkMethods: 100,
    keys: S('a'), distinctMethods: 110, appMethods: 10, sha256: 'x', size: 10,
    dataFileOverflow: false,
    layout: 'batched',
    ...over,
  });

  test('a 0-byte run is excluded, not counted as zero methods', () => {
    const group = {
      package: 'p',
      captureMode: 'recreate',
      runs: [
        run({ run: 1, keys: S('a', 'b', 'c'), frameworkMethods: 3 }),
        // The balancetheball case: the capture produced nothing at all.
        run({ run: 2, outcome: 'failed-zero-bytes', keys: new Set(), frameworkMethods: 0, size: 0 }),
      ],
    };
    const r = reportGroup(group);
    assert.equal(r.runsUsed, 1);
    assert.equal(r.runsFailed, 1);
    // The union is the union of what was actually observed, not 3 and not 0.
    assert.equal(r.union, 3);
    assert.deepEqual(r.perRunCounts, [3]);
    assert.equal(r.failed[0].outcome, 'failed-zero-bytes');
  });

  test('a group whose every run failed contributes nothing but is still listed', () => {
    const r = reportGroup({
      package: 'p',
      captureMode: 'startprof',
      runs: [run({ outcome: 'failed-zero-bytes', keys: new Set(), frameworkMethods: 0, size: 0 })],
    });
    assert.equal(r.runsUsed, 0);
    assert.equal(r.union, 0);
    assert.equal(r.runsFailed, 1);
  });

  test('a run with no capture record is not trusted', () => {
    // `readCaptures` defaults a missing sidecar to outcome "unknown"; that must
    // behave like a failure, not like a good capture with an unknown count.
    const r = reportGroup({
      package: 'p',
      captureMode: 'recreate',
      runs: [run({ outcome: 'unknown', keys: S('a'), frameworkMethods: 1 })],
    });
    assert.equal(r.runsUsed, 0);
  });
});

describe('buildReport', () => {
  const cap = (packageName, captureMode, run, keys, mode = 'exhaustive', outcome = 'ok') => ({
    package: packageName,
    captureMode,
    run,
    mode,
    outcome,
    keys: S(...keys),
    frameworkMethods: keys.length,
    appMethods: 0,
    name: `${packageName}.${captureMode}.run${run}.trace`,
    sha256: 'deadbeef',
    size: 100,
    layout: 'batched',
    distinctMethods: keys.length,
    numMethodCalls: keys.length * 3,
    dataFileOverflow: false,
    layout: 'batched',
    rejected: {},
    sampling_us: null,
    apkSha256: 'cafe',
    component: `${packageName}/.Main`,
  });

  test('capture modes are not pooled into one intersection', () => {
    const r = buildReport([
      cap('a', 'recreate', 1, ['x', 'y', 'z']),
      cap('b', 'recreate', 1, ['x', 'y']),
      cap('a', 'idle', 1, ['q']),
      cap('b', 'idle', 1, ['r']),
    ]);
    const modes = Object.fromEntries(r.byMode.map((m) => [m.captureMode, m]));
    assert.equal(modes['recreate full'].comparable, true);
    assert.equal(modes['recreate full'].intersection, 2);
    assert.equal(modes['idle full'].comparable, true);
    // `idle` shares nothing; pooling it with `recreate` would have reported 0
    // "methods common to all apps", which is a statement about the capture
    // method and not about the apps.
    assert.equal(modes['idle full'].intersection, 0);
  });

  test('a mode with one app is reported as not comparable rather than pooled', () => {
    const r = buildReport([cap('a', 'recreate', 1, ['x']), cap('b', 'startprof', 1, ['x', 'y'])]);
    const modes = Object.fromEntries(r.byMode.map((m) => [m.captureMode, m]));
    assert.equal(modes['recreate full'].comparable, false);
    assert.match(modes['recreate full'].reason, /needs at least 2/);
    assert.equal(modes['startprof full'].comparable, false);
  });

  test('per-app union and pairwise Jaccard across apps', () => {
    const r = buildReport([
      cap('a', 'recreate', 1, ['x', 'y', 'z']),
      cap('b', 'recreate', 1, ['x', 'y', 'w']),
    ]);
    const m = r.byMode.find((x) => x.captureMode === 'recreate full');
    assert.equal(m.intersection, 2);
    assert.equal(m.unionSize, 4);
    assert.deepEqual(m.appSizes, { a: 3, b: 3 });
    assert.equal(m.jaccard['a vs b'], 2 / 4);
  });

  test('a sampled run makes the whole mode a lower bound', () => {
    const r = buildReport([
      cap('a', 'recreate', 1, ['x', 'y']),
      cap('b', 'recreate', 1, ['x', 'y'], 'sampled'),
    ]);
    const m = r.byMode.find((x) => x.captureMode === 'recreate s?us');
    assert.equal(m.coverage, 'sampled@?us (lower bound)');
  });

  test('a sampled run is NOT pooled with the exhaustive runs of the same app', () => {
    // Regression: `recreate` and `recreate-s100` are different measurements of
    // the same app. Grouping them put a 100us trace in the same set as the
    // exhaustive ones and relabelled all of them "sampled (lower bound)".
    const r = buildReport([
      cap('a', 'recreate', 1, ['x', 'y']),
      cap('a', 'recreate', 2, ['x', 'y', 'z']),
      cap('a', 'recreate', 3, ['x'], 'sampled'),
    ]);
    const full = r.groups.find((g) => g.sampling === 'full');
    const sampled = r.groups.find((g) => g.sampling === 's?us');
    assert.ok(full && sampled, 'the two sampling levels must be separate groups');
    assert.equal(full.runsUsed, 2);
    assert.equal(full.coverage, 'exhaustive');
    assert.equal(full.union, 3);
    assert.equal(sampled.runsUsed, 1);
    assert.equal(sampled.union, 1);
  });

  test('sampled and exhaustive runs of the same mode are not intersected together', () => {
    const r = buildReport([
      cap('a', 'recreate', 1, ['x', 'y']),
      cap('b', 'recreate', 1, ['x', 'y']),
      cap('a', 'recreate', 2, ['q'], 'sampled'),
      cap('b', 'recreate', 2, ['q'], 'sampled'),
    ]);
    const keys = r.byMode.map((m) => m.captureMode);
    assert.deepEqual(keys, ['recreate full', 'recreate s?us']);
    assert.equal(r.byMode.find((m) => m.captureMode === 'recreate full').intersection, 2);
  });

  test('multi-run groups report a curve and pairwise Jaccard', () => {
    const r = buildReport([
      cap('a', 'recreate', 1, ['x', 'y']),
      cap('a', 'recreate', 2, ['y', 'z']),
    ]);
    const g = r.groups[0];
    assert.deepEqual(g.perRunCounts, [2, 2]);
    assert.equal(g.union, 3);
    assert.equal(g.convergence.enumerated, 2);
    assert.deepEqual(g.convergence.mean, [2, 3]);
    assert.equal(g.pairwise.length, 1);
    assert.equal(g.pairwise[0].jaccard, 1 / 3);
  });

  test('keys are not serialised into the report body', () => {
    const r = buildReport([cap('a', 'recreate', 1, ['x'])]);
    assert.equal(r.groups[0].keys, undefined);
    assert.equal(JSON.stringify(r).includes('"keys"'), false);
  });

  test('provenance lists each package once', () => {
    const r = buildReport([
      cap('a', 'recreate', 1, ['x']),
      cap('a', 'create', 1, ['x']),
      cap('b', 'recreate', 1, ['y']),
    ]);
    assert.deepEqual(r.provenance.map((p) => p.package), ['a', 'b']);
    assert.equal(r.provenance[0].apkSha256, 'cafe');
  });
});
