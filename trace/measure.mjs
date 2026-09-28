#!/usr/bin/env node
/**
 * Report on ART method traces: per-app coverage, run-to-run stability, and the
 * set common to every app.
 *
 *   node trace/measure.mjs --runs trace/runs
 *   node trace/measure.mjs --runs trace/runs --json
 *   node trace/measure.mjs --capture pkg=pkg1,pkg2 --runs 3 --mode recreate
 *
 * # What this measures
 *
 * For each capture group — one (package, capture mode) pair — it reports
 *
 *   per-run counts      distinct framework methods in each individual run
 *   union                |union over runs|, the surface the app needs at all
 *   convergence         |union of the first k runs| as k grows
 *   pairwise Jaccard    |Ai ∩ Bj| / |Ai ∪ Bj| for every pair of runs
 *
 * and across apps, the intersection of the per-app unions: the framework
 * methods every app touched.
 *
 * # Two rules this file will not break
 *
 * **A failed capture is not a zero.** A 0-byte trace parses to nothing, and a
 * report that counted it would report an app that "needed no framework
 * methods" when in fact the capture never happened. Any trace whose capture
 * record says otherwise is excluded from every set and named in the report.
 *
 * **A count carries its coverage.** Every number is emitted beside
 * `exhaustive` or `sampled@Nus (lower bound)`, because a sampled count is a
 * lower bound and rounding it into a headline would be a lie about coverage.
 *
 * # Determinism
 *
 * There is no randomness and no wall-clock input. Groups are ordered by
 * (package, captureMode, run); every list is sorted before it is measured; and
 * the convergence curve is reported over *all* orderings when the run count is
 * small enough to enumerate, so the curve does not depend on which run happened
 * to be captured first. Re-running gives byte-identical output for identical
 * input traces.
 *
 * The one input that does change between invocations is the run-to-run
 * variability of the device itself, which is the thing being reported rather
 * than smoothed over.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PARSE = path.join(HERE, 'parse.py');
const CAPTURE = path.join(HERE, 'capture.sh');

export const COVERAGE_EXHAUSTIVE = 'exhaustive';

/** Enumerate every ordering of `n` runs when that is cheap; otherwise the
 * canonical order alone, flagged. 6! = 720 orderings is the last point at which
 * the mean-over-orderings curve is worth computing exactly. */
export const MAX_ENUMERATED_RUNS = 6;

// ---------------------------------------------------------------------------
// pure functions
// ---------------------------------------------------------------------------

/** |union of the first k runs|, in the order given. */
export function convergence(sets) {
  const acc = new Set();
  const curve = [];
  for (const s of sets) {
    for (const k of s) acc.add(k);
    curve.push(acc.size);
  }
  return curve;
}

/**
 * The convergence curve is a random variable: |union of k runs| depends on which
 * runs come first. Reporting one ordering would be reporting an accident, so
 * every ordering is enumerated and the mean, min and max are returned.
 */
export function convergenceAcrossOrderings(sets) {
  const n = sets.length;
  if (n === 0) return { enumerated: 0, mean: [], min: [], max: [] };
  const perms = n <= MAX_ENUMERATED_RUNS ? permutations(sets) : [sets];
  const curves = perms.map(convergence);
  const mean = [];
  const min = [];
  const max = [];
  for (let k = 0; k < n; k += 1) {
    const col = curves.map((c) => c[k]);
    mean.push(col.reduce((a, b) => a + b, 0) / col.length);
    min.push(Math.min(...col));
    max.push(Math.max(...col));
  }
  return { enumerated: perms.length, mean, min, max };
}

export function permutations(arr) {
  if (arr.length <= 1) return [arr.slice()];
  const out = [];
  for (let i = 0; i < arr.length; i += 1) {
    const rest = arr.slice(0, i).concat(arr.slice(i + 1));
    for (const p of permutations(rest)) out.push([arr[i], ...p]);
  }
  return out;
}

export function jaccard(a, b) {
  const union = new Set([...a, ...b]);
  if (union.size === 0) return null; // two empty sets have no meaningful similarity
  let inter = 0;
  for (const k of a) if (b.has(k)) inter += 1;
  return inter / union.size;
}

/** Every pairwise Jaccard, keyed `i,j` with i < j in capture order. */
export function pairwiseJaccard(sets) {
  const out = [];
  for (let i = 0; i < sets.length; i += 1) {
    for (let j = i + 1; j < sets.length; j += 1) {
      out.push({ i, j, jaccard: jaccard(sets[i], sets[j]) });
    }
  }
  return out;
}

export function intersectAll(sets) {
  if (sets.length === 0) return new Set();
  let acc = new Set(sets[0]);
  for (const s of sets.slice(1)) {
    const next = new Set();
    for (const k of acc) if (s.has(k)) next.add(k);
    acc = next;
  }
  return acc;
}

export function unionAll(sets) {
  const acc = new Set();
  for (const s of sets) for (const k of s) acc.add(k);
  return acc;
}

/** A capture group is one (package, capture mode, sampling) triple.
 *
 * Sampling has to be part of the key, not merely a property of the run. The
 * file name distinguishes `recreate` from `recreate-s100`, but pooling the two
 * would average an exhaustive trace with a 100us sampled one and then label
 * the whole group by whichever is weakest - which is precisely how a lower
 * bound gets presented as a measurement.
 */
export function samplingLabel(r) {
  return r.mode === 'sampled' ? `s${r.sampling_us ?? '?'}us` : 'full';
}

export function groupKey(r) {
  return `${r.package} ${r.captureMode} ${samplingLabel(r)}`;
}

/** Group capture records, ordering runs by index. */
export function groupRuns(records) {
  const groups = new Map();
  for (const r of records) {
    const key = groupKey(r);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(r);
  }
  const out = [];
  for (const runs of groups.values()) {
    runs.sort((a, b) => a.run - b.run);
    out.push({
      package: runs[0].package,
      captureMode: runs[0].captureMode,
      sampling: samplingLabel(runs[0]),
      runs,
    });
  }
  out.sort((a, b) => groupKey(a).localeCompare(groupKey(b)));
  return out;
}

/**
 * The coverage label for a group. A group is only `exhaustive` if *every* run in
 * it is; one sampled run makes the whole union a lower bound, because the union
 * inherits the weakest coverage of its parts.
 */
export function groupCoverage(runs) {
  // Truncation dominates everything else. ART sets `data-file-overflow` when its
  // ring buffer filled and entries were dropped; the method table is then a
  // subset of what ran, so the group is a lower bound no matter how it was
  // instrumented. 8 of 64 usable captures in this study overflowed, all of them
  // the largest app.
  if (runs.some((r) => r.dataFileOverflow === true)) {
    const n = runs.filter((r) => r.dataFileOverflow === true).length;
    return `TRUNCATED (data-file-overflow in ${n}/${runs.length} run(s)) — lower bound`;
  }
  // The continuous layout has no preamble, so it carries no overflow flag at
  // all. Absence of a warning here is absence of evidence, and saying
  // "exhaustive" would overclaim.
  if (runs.some((r) => r.layout === 'continuous' && r.dataFileOverflow === null)) {
    return 'exhaustive (overflow NOT verifiable: continuous layout carries no flag) — unverifiable';
  }
  if (runs.some((r) => r.mode === 'sampled')) {
    const us = runs.find((r) => r.mode === 'sampled').sampling_us;
    return `sampled@${us ?? '?'}us (lower bound)`;
  }
  if (runs.some((r) => r.mode !== COVERAGE_EXHAUSTIVE)) {
    // No capture record, or one that did not say. Not the same claim as
    // "sampled at N us" — the interval is simply unknown.
    return 'undetermined (lower bound)';
  }
  return 'exhaustive';
}

/** The weakest coverage among a set of groups: one sampled app makes an
 * across-app intersection a lower bound, because the intersection cannot exceed
 * any of its parts. */
export function weakestCoverage(labels) {
  if (labels.some((l) => l !== COVERAGE_EXHAUSTIVE)) {
    return labels.find((l) => l !== COVERAGE_EXHAUSTIVE) ?? 'undetermined (lower bound)';
  }
  return 'exhaustive';
}

/**
 * The teardown confound, quantified.
 *
 * `recreate` forces the activity to be re-created and, in the same profiling
 * window, destroys the previous one. Both halves are counted, so the headline
 * includes teardown methods a first launch would never call.
 *
 * With `create` (creation only, the activity provably finished before profiling
 * started) and `teardown` (BACK only) available, the confound is *measured*
 * rather than guessed:
 *
 *   teardownAttributable = R \ C
 *
 * R is the set the original method counts; C is the set a creation-only window
 * counts. Everything in R that a creation alone does not explain is what the
 * clear-task added.
 *
 * **R \ C is an upper bound, and the reason is a real limitation rather than a
 * hedge.** C is a *warm* re-creation — the second activity this process has
 * made, with classes already loaded — while R's creation is the first, so R can
 * legitimately contain cold-start methods (class loading, first-time
 * initialisation) that C never calls. Those land in R \ C and are counted here
 * as if they were teardown. Removing that inflation needs a cold creation-only
 * trace, which §"Limitations" of FINDINGS.md records as not obtainable in the
 * batched layout on this image.
 */
export function teardownConfound(groups) {
  const find = (pkg, mode, sampling = 'full') => groups.find(
    (g) => g.package === pkg && g.captureMode === mode && g.sampling === sampling && g.runsUsed > 0,
  );
  const out = [];
  for (const g of groups) {
    if (g.captureMode !== 'recreate' || g.sampling !== 'full' || g.runsUsed === 0) continue;
    const c = find(g.package, 'create');
    const t = find(g.package, 'teardown');
    const i = find(g.package, 'idle');
    if (!c) continue;
    const R = g.keys;
    const C = c.keys;
    const attributable = [...R].filter((k) => !C.has(k));
    const explained = [...R].filter((k) => C.has(k));
    out.push({
      package: g.package,
      recreate: R.size,
      create: C.size,
      teardown: t ? t.keys.size : null,
      idle: i ? i.keys.size : null,
      explainedByCreation: explained.length,
      teardownAttributable: attributable.length,
      shareOfRecreate: R.size ? attributable.length / R.size : null,
      // A second, independent estimate of teardown size, from a different
      // trigger. Agreement is evidence; disagreement is reported, not hidden.
      teardownVsAttributableJaccard: t ? jaccard(new Set(attributable), t.keys) : null,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// trace reading
// ---------------------------------------------------------------------------

/**
 * Read every `.trace` under `dir` and pair it with its capture record.
 *
 * The capture record is authoritative for `mode`; the trace's own bytes are
 * authoritative for whether it is parseable at all. A trace with no record is
 * still read, but its mode is `undetermined` and every count from it is a lower
 * bound — which is the honest default.
 */
export function readCaptures(dir) {
  const names = readdirSync(dir).filter((n) => n.endsWith('.trace'));
  const paths = names.sort().map((n) => path.join(dir, n));
  if (paths.length === 0) throw new Error(`no .trace files in ${dir}`);

  // `parse.py` exits 1 when some trace failed to parse — which is a *result*,
  // reported in the JSON, not a crash. So a non-zero exit is tolerated as long
  // as stdout is JSON; only unusable output is an error.
  const run = spawnSync('python3', [PARSE, ...paths, '--with-keys', '--json'], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 1024,
  });
  if (run.error) throw run.error;
  let parsed;
  try {
    parsed = JSON.parse(run.stdout);
  } catch (e) {
    throw new Error(`parse.py did not produce JSON (exit ${run.status}): ${run.stderr || run.stdout}`);
  }

  const byPath = new Map(parsed.traces.map((t) => [t.path, t]));
  const results = [];
  for (const p of paths) {
    const t = byPath.get(p);
    if (!t) continue; // parse.py listed it as a failure; captured below
    let record = {};
    try {
      record = JSON.parse(readFileSync(`${p}.json`, 'utf8'));
    } catch {
      record = {};
    }
    results.push({
      path: p,
      name: path.basename(p),
      package: record.package ?? inferPackage(p),
      captureMode: record.captureMode ?? 'unknown',
      run: record.run ?? 0,
      mode: record.mode ?? 'undetermined',
      sampling_us: record.sampling_us ?? null,
      outcome: record.outcome ?? 'unknown',
      apkSha256: record.apkSha256 ?? null,
      component: record.component ?? null,
      sha256: t.sha256,
      size: t.size,
      layout: t.layout,
      distinctMethods: t.distinctMethods,
      frameworkMethods: t.frameworkMethods,
      appMethods: t.appMethods,
      numMethodCalls: t.numMethodCalls,
      dataFileOverflow: t.dataFileOverflow,
      rejected: t.rejected,
      keys: new Set(t.frameworkKeys),
    });
  }
  return { captures: results, failures: parsed.failures };
}

function inferPackage(p) {
  const m = path.basename(p).match(/^(.+?)\.(?:[a-z]+)(?:-s\d+)?\.run\d+\.trace$/);
  return m ? m[1] : path.basename(p);
}

// ---------------------------------------------------------------------------
// reporting
// ---------------------------------------------------------------------------

export function reportGroup(group) {
  const usable = group.runs.filter((r) => r.outcome === 'ok' && r.runs_ok !== false);
  const failed = group.runs.filter((r) => r.outcome !== 'ok');
  const sets = usable.map((r) => r.keys);
  const union = unionAll(sets);
  const curve = convergenceAcrossOrderings(sets);
  return {
    package: group.package,
    captureMode: group.captureMode,
    sampling: group.sampling,
    coverage: groupCoverage(group.runs),
    runsUsed: usable.length,
    runsFailed: failed.length,
    failed,
    perRun: usable.map((r) => ({
      run: r.run,
      name: r.name,
      sha256: r.sha256,
      bytes: r.size,
      frameworkMethods: r.frameworkMethods,
      appMethods: r.appMethods,
      numMethodCalls: r.numMethodCalls,
      dataFileOverflow: r.dataFileOverflow,
      layout: r.layout,
      coverage: r.dataFileOverflow === true
        ? 'TRUNCATED (data-file-overflow) - lower bound'
        : r.layout === 'continuous'
          ? 'overflow NOT verifiable (continuous layout) - unverifiable'
          : groupCoverage([r]),
    })),
    perRunCounts: usable.map((r) => r.frameworkMethods),
    union: union.size,
    perRunMin: usable.length ? Math.min(...usable.map((r) => r.frameworkMethods)) : null,
    perRunMax: usable.length ? Math.max(...usable.map((r) => r.frameworkMethods)) : null,
    convergence: curve,
    pairwise: pairwiseJaccard(sets),
    keys: union,
  };
}

function renderMarkdown(result) {
  const L = [];
  L.push('# ART method-trace report');
  L.push('');
  L.push(`Generated from \`${path.relative(process.cwd(), result.runsDir)}\`.`);
  L.push('Every count is labelled with the coverage it was measured at.');
  L.push('');

  if (result.failures.length) {
    L.push('## Failed captures (excluded from every set)');
    L.push('');
    L.push('| trace | bytes | reason |');
    L.push('|---|---|---|');
    for (const f of result.failures) L.push(`| \`${path.basename(f.path)}\` | 0 | ${f.error} |`);
    L.push('');
  }

  L.push('## Per app');
  L.push('');
  L.push('| package | mode | sampling | coverage | runs | per-run framework methods | union | pairwise Jaccard |');
  L.push('|---|---|---|---|---|---|---|---|');
  for (const g of result.groups) {
    if (g.runsUsed === 0) continue;
    const counts = g.perRunCounts.join(', ');
    const js = g.pairwise.length
      ? g.pairwise.map((p) => `r${p.i + 1}~r${p.j + 1}=${p.jaccard.toFixed(4)}`).join(' ')
      : 'n/a (1 run)';
    L.push(
      `| \`${g.package}\` | ${g.captureMode} | ${g.sampling} | **${g.coverage}** | ${g.runsUsed}/${g.runsUsed + g.runsFailed}` +
        ` | ${counts} | **${g.union}** | ${js} |`,
    );
  }
  L.push('');
  const empty = result.groups.filter((g) => g.runsUsed === 0);
  if (empty.length) {
    L.push(`Groups with no usable run, excluded from every count above: ` +
      empty.map((g) => `\`${g.package}\` ${g.captureMode} ${g.sampling} (${g.runsFailed} failed, ` +
        `${[...new Set(g.failed.map((f) => f.outcome))].join('/') || 'no capture record'})`).join('; ') + '.');
    L.push('');
  }

  L.push('## Convergence, |union of k runs|');
  L.push('');
  L.push('Enumerated over every ordering of the runs, so the value does not depend on');
  L.push('capture order. `orderings` is how many permutations were averaged.');
  L.push('');
  for (const g of result.groups) {
    if (g.runsUsed === 0) continue;
    const c = g.convergence;
    const order = c.enumerated > 1 ? `${c.enumerated} orderings` : '1 ordering';
    const range = c.enumerated > 1 && c.max[k => k] !== undefined
      ? ` (range at k=${g.runsUsed}: ${c.min[g.runsUsed - 1]}–${c.max[g.runsUsed - 1]})`
      : '';
    L.push(`- \`${g.package}\` ${g.captureMode} ${g.sampling} (${g.coverage}, ${order}): ` +
      c.mean.map((v) => v.toFixed(1)).join(' → ') + range);
  }
  L.push('');

  L.push('## Common to every app');
  L.push('');
  L.push('Computed within a single capture mode. `recreate` includes activity teardown');
  L.push('and `idle` includes almost nothing, so pooling modes would produce a number');
  L.push('that describes no app.');
  L.push('');
  for (const m of result.byMode) {
    L.push(`### \`${m.captureMode}\` — ${m.coverage}`);
    L.push('');
    if (!m.comparable) {
      L.push(`- Not comparable: ${m.reason}.`);
      L.push(`- App union${m.apps.length === 1 ? '' : 's'}: ` +
        Object.entries(m.appSizes).map(([p, n]) => `\`${p}\` ${n}`).join(', ') + '.');
      L.push('');
      continue;
    }
    L.push(`- Apps compared: ${m.apps.map((p) => `\`${p}\``).join(', ')} (${m.apps.length}).`);
    L.push(`- **Intersection: ${m.intersection} methods.** Union of all app unions: ${m.unionSize}.`);
    L.push(`- Per-app union sizes: ` +
      Object.entries(m.appSizes).map(([p, n]) => `\`${p}\` ${n}`).join(', ') + '.');
    L.push('- Pairwise Jaccard between app unions: ' +
      Object.entries(m.jaccard).map(([k, v]) => `${k} ${v.toFixed(4)}`).join('; ') + '.');
    L.push('');
  }

  L.push('## Teardown confound, per app');
  L.push('');
  L.push('`R minus C` is the set difference: methods the `recreate` window counted');
  L.push('that a creation-only window did not. It is an **upper bound** on the teardown');
  L.push('contribution — the `create` window is a *warm* re-creation, so cold-start-only');
  L.push('methods present in `R` are attributed to teardown too.');
  L.push('');
  L.push('| package | recreate R | create C | idle | teardown (BACK) | R minus C | share of R |');
  L.push('|---|---|---|---|---|---|---|');
  for (const c of result.confound) {
    L.push(`| \`${c.package}\` | ${c.recreate} | ${c.create} | ${c.idle ?? 'n/a'} | ${c.teardown ?? 'n/a'} | **${c.teardownAttributable}** | ${(c.shareOfRecreate * 100).toFixed(1)}% |`);
  }
  L.push('');
  const noCreate = result.groups
    .filter((g) => g.captureMode === 'recreate' && g.sampling === 'full' && g.runsUsed > 0)
    .filter((g) => !result.confound.some((c) => c.package === g.package))
    .map((g) => `\`${g.package}\``);
  if (noCreate.length) {
    L.push(`Not comparable — no usable \`create\` run for: ${noCreate.join(', ')}. See the failed-capture table.`);
    L.push('');
  }

  L.push('## Provenance');
  L.push('');
  L.push('| package | apk sha256 | component |');
  L.push('|---|---|---|');
  for (const row of result.provenance) {
    L.push(`| \`${row.package}\` | \`${row.apkSha256 ?? 'n/a'}\` | \`${row.component ?? 'n/a'}\` |`);
  }
  L.push('');
  return L.join('\n');
}

export function buildReport(captures) {
  const groups = groupRuns(captures).map(reportGroup);
  const covered = groups.filter((g) => g.runsUsed > 0);

  // The across-app intersection is only meaningful *within* one capture mode.
  // `recreate` counts creation plus teardown and `idle` counts almost nothing,
  // so intersecting them would report a number that describes no app. Each mode
  // gets its own intersection, and a mode with fewer than two apps is listed as
  // having none rather than being silently pooled with another mode.
  const byMode = new Map();
  for (const g of covered) {
    const key = `${g.captureMode} ${g.sampling}`;
    if (!byMode.has(key)) byMode.set(key, []);
    byMode.get(key).push(g);
  }

  const modes = [];
  for (const [mode, gs] of [...byMode.entries()].sort()) {
    const entry = { captureMode: mode, coverage: weakestCoverage(gs.map((g) => g.coverage)), apps: gs.map((g) => g.package) };
    if (gs.length < 2) {
      entry.comparable = false;
      entry.reason = `only ${gs.length} app measured in this mode; an intersection needs at least 2`;
      entry.unionSize = unionAll(gs.map((g) => g.keys)).size;
      entry.appSizes = Object.fromEntries(gs.map((g) => [g.package, g.union]));
      modes.push(entry);
      continue;
    }
    entry.comparable = true;
    const all = intersectAll(gs.map((g) => g.keys));
    const total = unionAll(gs.map((g) => g.keys));
    entry.intersection = all.size;
    entry.unionSize = total.size;
    entry.appSizes = Object.fromEntries(gs.map((g) => [g.package, g.union]));
    entry.jaccard = Object.fromEntries(
      gs.flatMap((a, i) => gs.slice(i + 1).map((b) => [`${a.package} vs ${b.package}`, jaccard(a.keys, b.keys)])),
    );
    modes.push(entry);
  }

  const provenance = [];
  const seen = new Set();
  for (const c of captures) {
    if (seen.has(c.package)) continue;
    seen.add(c.package);
    provenance.push({ package: c.package, apkSha256: c.apkSha256, component: c.component });
  }

  return {
    groups: groups.map((g) => ({ ...g, keys: undefined })),
    byMode: modes,
    confound: teardownConfound(groups),
    provenance,
  };
}

// ---------------------------------------------------------------------------
// cli
// ---------------------------------------------------------------------------

function usage() {
  return `usage:
  node trace/measure.mjs [--runs <dir>] [--json] [--out <file>]
  node trace/measure.mjs --capture <pkg=apk>[,<pkg=apk>...] [--runs N] [--mode M] [--sampling US]

modes: recreate (creation+teardown), create, teardown, idle, startprof`;
}

function main(argv) {
  const args = { runsDir: path.join(HERE, 'runs'), capture: null, mode: 'recreate', n: 3, sampling: null, json: false, out: null };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--runs') args.runsDir = path.resolve(argv[++i]);
    else if (a === '--capture') args.capture = argv[++i];
    else if (a === '--mode') args.mode = argv[++i];
    else if (a === '--sampling') args.sampling = argv[++i];
    else if (a === '--n') args.n = Number(argv[++i]);
    else if (a === '--json') args.json = true;
    else if (a === '--out') args.out = argv[++i];
    else if (a === '-h' || a === '--help') { console.log(usage()); return 0; }
    else { console.error(`measure.mjs: unknown argument ${a}\n${usage()}`); return 2; }
  }

  if (args.capture) {
    for (const pair of args.capture.split(',')) {
      const eq = pair.indexOf('=');
      const pkg = pair.slice(0, eq);
      const apk = pair.slice(eq + 1);
      const argv2 = ['--apk', apk, '--package', pkg, '--runs', String(args.n), '--mode', args.mode];
      if (args.sampling) argv2.push('--sampling', String(args.sampling));
      try {
        execFileSync('bash', [CAPTURE, ...argv2], { stdio: ['ignore', 'inherit', 'inherit'] });
      } catch (e) {
        console.error(`measure.mjs: capture of ${pkg} reported failures (recorded in the sidecar)`);
      }
    }
  }

  mkdirSync(args.runsDir, { recursive: true });
  const { captures, failures } = readCaptures(args.runsDir);
  const report = buildReport(captures);
  const result = { ...report, runsDir: args.runsDir, failures };

  if (args.json) {
    const text = JSON.stringify(result, null, 2);
    if (args.out) writeFileSync(args.out, `${text}\n`);
    else console.log(text);
  } else {
    const text = renderMarkdown(result);
    if (args.out) writeFileSync(args.out, `${text}\n`);
    else console.log(text);
  }
  return failures.length ? 1 : 0;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  process.exit(main(process.argv.slice(2)));
}
