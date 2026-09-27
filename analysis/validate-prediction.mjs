#!/usr/bin/env node
/**
 * Correlate the static prediction with observed behaviour.
 *
 * ## Current state: NOT VALIDATABLE, and it says so
 *
 * There is no set of apps that have been both statically predicted *and* run in
 * a substrate, because the substrate does not exist yet. This script therefore
 * exits non-zero with an explicit reason rather than printing an empty or
 * flattering correlation table. Two things can make it runnable, and it detects
 * each:
 *
 * 1. **A ground-truth recording exists.** `oracle/RECORDING.md` defines the
 *    recording format. If `../oracle/schema/examples/` contains real recordings
 *    (i.e. anything beyond the two committed `minimal.recording.json` and
 *    `full.recording.json` *templates*, which carry `"_template": true`), this
 *    script correlates the prediction against them.
 * 2. **A verified-running set is declared.** If
 *    `validation-set/observed.json` exists, correlating against that.
 *
 * Until then it also does something useful: it checks the *static* half of the
 * prediction against the 20 hand labels, and reports that result with the
 * caveats that make it a measure of implementation correctness rather than of
 * construct validity. Those are printed to stdout and are not a validation.
 *
 *   node analysis/validate-prediction.mjs
 *   node analysis/validate-prediction.mjs --observed validation-set/observed.json
 */

import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

const REPO = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const LABELS = path.join(REPO, 'analysis', 'validation-set', 'labels.json');
const OBSERVED = path.join(REPO, 'analysis', 'validation-set', 'observed.json');
const ORACLE_EXAMPLES = path.join(REPO, 'oracle', 'schema', 'examples');
const ROWS = path.join(REPO, 'analysis', 'sample', 'rows.jsonl');

/** The analyzer's answer to each hand-labelled feature, from the sample rows. */
const FEATURE_PREDICATE = {
  F1: (r) =>
    r.libEntries.length > 0 ||
    r.assetNativePayloads.length > 0 ||
    r.loadLibraryCalls > 0 ||
    r.nativeMethodsUnimplemented > 0,
  F2: (r) =>
    r.invoke.invoke_polymorphic > 0 ||
    r.invoke.invoke_custom > 0 ||
    r.invoke.const_method_handle > 0,
  F3: (r) =>
    r.playServicesClasses.length > 0 ||
    r.playIntegrityClasses.length > 0 ||
    r.integrityLiterals.length > 0 ||
    r.drmLiterals.length > 0 ||
    r.licensingClasses > 0,
  F4: (r) => r.buildFieldReads > 0,
  F5: (r) => r.reflectionCallSites > 0,
  F6: (r) => r.dynamicCodeClasses.length > 0,
};

async function readJsonl(p) {
  if (!existsSync(p)) return [];
  const text = await readFile(p, 'utf8');
  return text.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
}

/** Real oracle recordings, excluding the committed templates. */
async function realRecordings() {
  if (!existsSync(ORACLE_EXAMPLES)) return [];
  const names = await readdir(ORACLE_EXAMPLES);
  const out = [];
  for (const n of names) {
    if (!n.endsWith('.json')) continue;
    try {
      const r = JSON.parse(await readFile(path.join(ORACLE_EXAMPLES, n), 'utf8'));
      // The two committed examples are hand-authored *specifications* of
      // interesting captures, not captures. `oracle/RECORDING.md` marks them
      // `synthetic: true` and their own `provenance.execution_performed` is
      // false. Treating either as evidence is exactly the mistake the project
      // pre-registered against, so they are filtered here rather than trusted.
      if (r?.synthetic === true) continue;
      if (r?.provenance?.execution_performed === false) continue;
      if (r?.record_format?.startsWith('andro-substrate.ground-truth/') !== true) continue;
      out.push({ file: n, recording: r });
    } catch {
      // A file that is not JSON is not a recording.
    }
  }
  return out;
}

function confusion(rows, feature) {
  const pred = FEATURE_PREDICATE[feature];
  const m = { yes_yes: 0, yes_no: 0, no_yes: 0, no_no: 0, unknown: 0 };
  const disagreements = [];
  for (const { app, labels } of rows) {
    const label = labels[feature];
    if (label !== 'yes' && label !== 'no') { m.unknown += 1; continue; }
    const p = pred(app);
    const key = `${label}_${p ? 'yes' : 'no'}`;
    m[key] = (m[key] ?? 0) + 1;
    if (label !== (p ? 'yes' : 'no')) disagreements.push({ app: app.packageName, label, predicted: p });
  }
  return { m, disagreements };
}

function agreement(m) {
  const n = m.yes_yes + m.yes_no + m.no_yes + m.no_no;
  if (n === 0) return null;
  // Cohen's kappa on a 2x2 table with a degenerate single-class column is
  // undefined, so it is reported as null rather than as 0 or 1.
  const po = (m.yes_yes + m.no_no) / n;
  const pYes = (m.yes_yes + m.no_yes) / n;
  const pNo = (m.yes_no + m.no_no) / n;
  const pHatYes = (m.yes_yes + m.yes_no) / n;
  const pHatNo = (m.no_yes + m.no_no) / n;
  const pe = pHatYes * pYes + pHatNo * pNo;
  const kappa = Math.abs(1 - pe) < 1e-12 ? null : (po - pe) / (1 - pe);
  return { n, accuracy: po, kappa };
}

async function main() {
  const argv = process.argv.slice(2);
  let observedPath = OBSERVED;
  const i = argv.indexOf('--observed');
  if (i !== -1) observedPath = path.resolve(argv[i + 1]);

  if (!existsSync(LABELS)) {
    console.error(`missing ${LABELS}`);
    process.exitCode = 1;
    return;
  }
  const labels = JSON.parse(await readFile(LABELS, 'utf8'));
  const rows = await readJsonl(ROWS);
  const byPackage = new Map(rows.map((r) => [`${r.packageName}#${r.versionCode}`, r]));

  // ------------------------------------------------ the static half, runnable
  const labelled = [];
  let missing = 0;
  for (const a of labels.apps) {
    const row = byPackage.get(`${a.packageName}#${a.versionCode}`);
    if (!row) { missing += 1; continue; }
    labelled.push({ app: row, labels: a.labels, note: a.note });
  }
  console.log('=== static predictor vs 20 hand labels ===');
  console.log(`labelled apps: ${labelled.length}, analyzer rows found: ${labelled.length}, missing: ${missing}`);
  console.log('');
  const table = [];
  for (const f of Object.keys(labels.features)) {
    const { m, disagreements } = confusion(labelled, f);
    const a = agreement(m);
    table.push({ feature: f, ...m, ...(a ?? {}) });
    console.log(`${f}  agree ${m.yes_yes + m.no_no}/${m.yes_yes + m.yes_no + m.no_yes + m.no_no}` +
      `  kappa ${a && a.kappa !== null ? a.kappa.toFixed(3) : 'n/a'}` +
      `  (FN ${m.yes_no}, FP ${m.no_yes})`);
    for (const d of disagreements) console.log(`      disagreement: ${d.app}  hand=${d.label} predicted=${d.predicted ? 'yes' : 'no'}`);
  }
  console.log('');

  // ------------------------------------------- the honest reading of the above
  const positiveRates = table.map((t) => {
    const n = t.yes_yes + t.yes_no + t.no_yes + t.no_no;
    return n === 0 ? 0 : (t.yes_yes + t.no_yes) / n;
  });
  const degenerate = positiveRates.filter((p) => p > 0.9 || p < 0.1).length;
  console.log('READ THIS BEFORE QUOTING THE TABLE ABOVE');
  console.log(`  * ${degenerate} of ${table.length} features are >90% or <10% positive in a`);
  console.log('    20-app set. A feature that is almost always true has almost no power to');
  console.log('    distinguish apps, so "agreement" on it is close to meaningless.');
  console.log('  * These labels were produced by the same person who wrote the analyzer,');
  console.log('    from the same static artefacts the analyzer reads. Agreement therefore');
  console.log('    measures whether the implementation matches its intent. It does NOT');
  console.log('    measure whether the intent is the right predictor of runtime behaviour.');
  console.log('  * n = 20 cannot support a significance test on any of these cells.');
  console.log('    A single app flipping moves any rate by 5 percentage points.');
  console.log('');

  // ------------------------------------------------------ the real validation
  const observed = existsSync(observedPath) ? JSON.parse(await readFile(observedPath, 'utf8')) : null;
  const recordings = await realRecordings();

  if (observed || recordings.length > 0) {
    console.log('=== prediction vs observed behaviour ===');
    if (observed) {
      const preds = new Map(rows.map((r) => [`${r.packageName}#${r.versionCode}`, r]));
      for (const o of observed.apps ?? []) {
        const p = preds.get(`${o.packageName}#${o.versionCode}`);
        if (!p) { console.log(`  ${o.packageName}: no analyzer row`); continue; }
        console.log(`  ${o.packageName}  predicted=${p.band}/${p.score.toFixed(1)}  observed=${o.outcome ?? o.ladder ?? 'UNSPECIFIED'}`);
      }
    } else {
      console.log(`  ${recordings.length} oracle recording(s) found in oracle/schema/examples/`);
    }
    console.log('  NOTE: correlating a banded prediction with an observed outcome is only');
    console.log('  meaningful once both sides are defined on the same set of apps. See');
    console.log('  research-protocol.md §4 for the ladder this must use.');
  } else {
    console.log('=== prediction vs observed behaviour: NOT VALIDATABLE YET ===');
    console.log('  No observed data exists. Specifically:');
    console.log(`    * ${observedPath.replace(REPO + '/', '')} is absent — no app has been run in a substrate.`);
    console.log(`    * ${ORACLE_EXAMPLES.replace(REPO + '/', '')} contains only the two committed templates,`);
    console.log('      which carry `"_template": true` and record no real behaviour.');
    console.log('  The runtime agent has not produced a verified-running set, so there is');
    console.log('  nothing to correlate a prediction against. Any correlation printed at');
    console.log('  this point would be a number with no second quantity in it.');
    console.log('');
    console.log('  This script will correlate automatically once either of these appears:');
    console.log('    1. analysis/validation-set/observed.json');
    console.log('    2. a non-template recording in oracle/schema/examples/');
    process.exitCode = 3;
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
