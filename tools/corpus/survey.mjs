#!/usr/bin/env node
/**
 * Corpus survey driver.
 *
 * Fetches the F-Droid index, takes a deterministic sample of apps, classifies
 * each one from HTTP range reads only, writes one JSONL row per app and then
 * prints the aggregate. Every figure in corpus/report.md is either printed by
 * this script or recomputable from corpus/survey.jsonl.
 *
 *   node tools/corpus/survey.mjs --n 3000 --seed 20260928
 */

import { createWriteStream } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { once } from 'node:events';

import { RangeFetcher } from './range-fetch.mjs';
import {
  downloadIndex,
  listApps,
  sampleApps,
  attachLicenses,
  DEFAULT_INDEX_FORMAT,
  REPO_BASE,
} from './fdroid-index.mjs';
import { classifyApk, TAIL_BYTES } from './classify.mjs';

export const DEFAULT_SEED = 20260928;

function parseArgs(argv) {
  const args = {
    n: 3000,
    seed: DEFAULT_SEED,
    concurrency: 8,
    withManifest: true,
    tailBytes: TAIL_BYTES,
    out: 'corpus/survey.jsonl',
    summary: 'corpus/summary.json',
    indexFormat: DEFAULT_INDEX_FORMAT,
    base: REPO_BASE,
    refreshIndex: false,
    progressEvery: 100,
    subsampleReport: 3000,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf('=');
    const key = eq === -1 ? a : a.slice(0, eq);
    const inlineValue = eq === -1 ? null : a.slice(eq + 1);
    const next = () => inlineValue ?? argv[++i];
    switch (key) {
      case '--n': args.n = Number(next()); break;
      case '--seed': args.seed = Number(next()); break;
      case '--concurrency': args.concurrency = Number(next()); break;
      case '--tail-bytes': args.tailBytes = Number(next()); break;
      case '--out': args.out = next(); break;
      case '--summary': args.summary = next(); break;
      case '--index-format': args.indexFormat = next(); break;
      case '--base': args.base = next(); break;
      case '--progress-every': args.progressEvery = Number(next()); break;
      case '--subsample-report': args.subsampleReport = Number(next()); break;
      case '--no-manifest': args.withManifest = false; break;
      case '--refresh-index': args.refreshIndex = true; break;
      case '--help': args.help = true; break;
      default:
        throw new Error(`unknown argument: ${a}`);
    }
  }
  return args;
}

const USAGE = `Usage: node tools/corpus/survey.mjs [options]

  --n <count>              sample size (default 3000; >= population means census)
  --seed <int>             PRNG seed (default ${DEFAULT_SEED})
  --concurrency <int>      parallel range readers (default 8)
  --tail-bytes <int>       suffix range size for the EOCD (default ${TAIL_BYTES})
  --out <path>             JSONL output (default corpus/survey.jsonl)
  --summary <path>         aggregate JSON (default corpus/summary.json)
  --index-format <v1|v2>   F-Droid index serialisation (default ${DEFAULT_INDEX_FORMAT})
  --refresh-index          re-download the index instead of using the cache
  --no-manifest            skip the AndroidManifest.xml range read
`;

/** Wilson score interval, two-sided 95%. The right way to bound a proportion. */
export function wilsonInterval(successes, total, z = 1.959963984540054) {
  if (total === 0) return { low: null, high: null };
  const p = successes / total;
  const z2 = z * z;
  const denom = 1 + z2 / total;
  const centre = p + z2 / (2 * total);
  const margin = z * Math.sqrt((p * (1 - p)) / total + z2 / (4 * total * total));
  return {
    low: Math.max(0, (centre - margin) / denom),
    high: Math.min(1, (centre + margin) / denom),
  };
}

function pct(n, d) {
  return d === 0 ? null : (100 * n) / d;
}

function fmtPct(v, digits = 2) {
  return v === null ? 'n/a' : `${v.toFixed(digits)}%`;
}

function bucketMinSdk(v) {
  if (v === null || v === undefined) return 'unknown';
  if (v < 16) return 'a: <16 (pre-Jelly Bean)';
  if (v < 21) return 'b: 16-20 (JB-JB MR1)';
  if (v < 24) return 'c: 21-23 (L-M)';
  if (v < 26) return 'd: 24-25 (N-N MR1)';
  if (v < 29) return 'e: 26-28 (O-P)';
  if (v < 33) return 'f: 29-32 (Q-T)';
  return 'g: 33+ (recent)';
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(USAGE);
    return;
  }

  const startedAt = new Date().toISOString();
  process.stderr.write(`[survey] fetching F-Droid index (${args.indexFormat}) ...\n`);
  const index = await downloadIndex({
    format: args.indexFormat,
    base: args.base,
    force: args.refreshIndex,
  });
  const population = listApps(index.json);
  const { sample, shuffled, population: popSize } = sampleApps(population, {
    n: args.n,
    seed: args.seed,
  });

  let apps = sample;
  let licenseSource = null;
  if (process.env.ANDRO_WITH_LICENSES === '1') {
    try {
      const v2 = await downloadIndex({ format: 'v2', base: args.base });
      apps = attachLicenses(index.json, v2.json)(apps);
      licenseSource = v2.identity;
    } catch (err) {
      process.stderr.write(`[survey] license join unavailable: ${err.message}\n`);
    }
  }

  process.stderr.write(
    `[survey] index version=${index.identity.version} timestamp=${index.identity.timestampISO} sha256=${index.identity.sha256.slice(0, 16)}...\n`,
  );
  process.stderr.write(
    `[survey] population=${popSize} sampling=${shuffled ? `seeded sample n=${sample.length}` : `census (all ${sample.length})`} seed=${args.seed}\n`,
  );

  await mkdir(path.dirname(path.resolve(args.out)), { recursive: true });
  const out = createWriteStream(path.resolve(args.out), { flags: 'w' });
  const outDone = once(out, 'close');

  const fetcher = new RangeFetcher({
    onEvent: (e) => {
      if (e.type === 'retry') process.stderr.write(`[survey] retry ${e.url} (${e.reason})\n`);
    },
  });

  const results = new Array(sample.length);
  let done = 0;
  let next = 0;
  const startedMs = Date.now();

  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= sample.length) return;
      const row = await classifyApk(sample[i], fetcher, {
        withManifest: args.withManifest,
        tailBytes: args.tailBytes,
      });
      row.sampleIndex = i;
      row.license = sample[i].license ?? null;
      results[i] = row;
      done += 1;
      if (args.progressEvery > 0 && done % args.progressEvery === 0) {
        const rate = done / ((Date.now() - startedMs) / 1000);
        const mb = (fetcher.bytesFetched / 1e6).toFixed(1);
        process.stderr.write(`[survey] ${done}/${sample.length} (${rate.toFixed(1)}/s, ${mb} MB)\n`);
      }
    }
  }

  const workers = Array.from({ length: Math.max(1, args.concurrency) }, () => worker());
  await Promise.all(workers);

  for (const row of results) out.write(`${JSON.stringify(row)}\n`);
  out.end();
  await outDone;

  const summary = buildSummary({
    rows: results,
    index,
    args,
    fetcher,
    startedAt,
    finishedAt: new Date().toISOString(),
    population: popSize,
    shuffled,
    licenseSource,
  });
  if (args.subsampleReport > 0 && results.length > args.subsampleReport) {
    summary.seededSubsample = subsampleAggregate(results, {
      n: args.subsampleReport,
      seed: args.seed,
    });
  }
  await mkdir(path.dirname(path.resolve(args.summary)), { recursive: true });
  await writeFile(path.resolve(args.summary), `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(`${renderReport(summary)}\n`);
}

export function buildSummary({
  rows,
  index,
  args,
  fetcher,
  startedAt,
  finishedAt,
  population,
  shuffled,
  licenseSource,
}) {
  const ok = rows.filter((r) => r.ok);
  const failed = rows.filter((r) => !r.ok);
  const pure = ok.filter((r) => !r.hasNativeCode);
  const native = ok.filter((r) => r.hasNativeCode);

  const abiTally = new Map();
  for (const r of ok) {
    for (const [abi, n] of Object.entries(r.nativeAbiCounts ?? {})) {
      abiTally.set(abi, (abiTally.get(abi) ?? 0) + n);
    }
  }
  const abiApps = new Map();
  for (const r of ok) {
    for (const abi of Object.keys(r.nativeAbiCounts ?? {})) {
      abiApps.set(abi, (abiApps.get(abi) ?? 0) + 1);
    }
  }

  const sdkBuckets = new Map();
  for (const r of ok) {
    const key = bucketMinSdk(r.minSdk);
    const b = sdkBuckets.get(key) ?? { total: 0, pure: 0 };
    b.total += 1;
    if (!r.hasNativeCode) b.pure += 1;
    sdkBuckets.set(key, b);
  }

  const declaredVsMeasured = ok.filter(
    (r) => Array.isArray(r.indexDeclaredAbis) && r.indexDeclaredAbis.length > 0,
  );
  const agreeBothNative = declaredVsMeasured.filter((r) => r.hasNativeCode).length;
  const measuredNativeNotDeclared = native.filter(
    (r) => !(r.indexDeclaredAbis ?? []).length,
  ).length;
  const declaredNativeNotMeasured = declaredVsMeasured.filter((r) => !r.hasNativeCode).length;

  const manifestOk = ok.filter((r) => r.manifestStatus === 'ok');
  const sdkDisagree = manifestOk.filter(
    (r) => r.minSdk !== null && r.indexMinSdk !== null && r.minSdk !== r.indexMinSdk,
  ).length;

  const apkBytes = ok.reduce((s, r) => s + (r.apkBytes ?? 0), 0);
  const dexBytes = ok.reduce((s, r) => s + (r.dexBytes ?? 0), 0);
  const dexUncompressed = ok.reduce((s, r) => s + (r.dexUncompressedBytes ?? 0), 0);

  const n = ok.length;
  const numerator = pure.length;
  const ci = wilsonInterval(numerator, n);

  return {
    schema: 1,
    run: {
      startedAt,
      finishedAt,
      durationSeconds: Number(
        ((new Date(finishedAt).getTime() - new Date(startedAt).getTime()) / 1000).toFixed(1),
      ),
      command: `node tools/corpus/survey.mjs --n ${args.n} --seed ${args.seed} --concurrency ${args.concurrency}${
        args.withManifest ? '' : ' --no-manifest'
      }`,
      seed: args.seed,
      requestedN: args.n,
      concurrency: args.concurrency,
      withManifest: args.withManifest,
      tailBytes: args.tailBytes,
      indexFormat: args.indexFormat,
    },
    index: index.identity,
    population: {
      packagesInIndex: population,
      sampled: rows.length,
      succeeded: n,
      failed: failed.length,
      samplingMethod: shuffled ? 'seeded-shuffle' : 'census',
    },
    headline: {
      metric: 'APKs with zero lib/<abi>/*.so entries',
      numerator: numerator,
      denominator: n,
      percentNoNativeCode: pct(numerator, n),
      percentWithNativeCode: pct(native.length, n),
      wilson95Low: ci.low === null ? null : ci.low * 100,
      wilson95High: ci.high === null ? null : ci.high * 100,
    },
    bytes: {
      totalFetched: fetcher.bytesFetched,
      totalFetchedMiB: Number((fetcher.bytesFetched / 1024 / 1024).toFixed(2)),
      sumOfRowBytes: rows.reduce((s, r) => s + (r.bytesFetched ?? 0), 0),
      sumOfRowRequests: rows.reduce((s, r) => s + (r.requests ?? 0), 0),
      fullDownloadWouldBeBytes: apkBytes,
      fullDownloadWouldBeGiB: Number((apkBytes / 1024 ** 3).toFixed(3)),
      fractionOfFullDownload: apkBytes === 0 ? null : fetcher.bytesFetched / apkBytes,
      indexDownloadBytes: index.bytes,
      perApkMeanBytes: n === 0 ? null : Math.round(fetcher.bytesFetched / n),
      perApkMeanApkBytes: n === 0 ? null : Math.round(apkBytes / n),
    },
    transfer: fetcher.stats(),
    dex: {
      meanDexCount: n === 0 ? null : Number((ok.reduce((s, r) => s + r.dexCount, 0) / n).toFixed(3)),
      meanCompressedDexBytes: n === 0 ? null : Math.round(dexBytes / n),
      meanUncompressedDexBytes: n === 0 ? null : Math.round(dexUncompressed / n),
      zeroDexApps: ok.filter((r) => r.dexCount === 0).length,
      multiDexApps: ok.filter((r) => r.dexCount > 1).length,
    },
    abis: {
      librariesByAbi: Object.fromEntries([...abiTally].sort((a, b) => b[1] - a[1])),
      appsByAbi: Object.fromEntries([...abiApps].sort((a, b) => b[1] - a[1])),
      straySharedObjectApps: ok.filter((r) => (r.straySharedObjects ?? []).length > 0).length,
    },
    minSdk: {
      buckets: Object.fromEntries(sdkBuckets),
      manifestParsed: manifestOk.length,
      manifestParseRate: n === 0 ? null : manifestOk.length / n,
      disagreementWithIndex: sdkDisagree,
    },
    crossChecks: {
      indexDeclaredNative: declaredVsMeasured.length,
      indexDeclaredAndMeasuredNative: agreeBothNative,
      indexDeclaredNativeButMeasuredNone: declaredNativeNotMeasured,
      measuredNativeButIndexDeclaredNone: measuredNativeNotDeclared,
    },
    resourcesArsc: {
      present: ok.filter((r) => r.resourcesArsc).length,
      absent: ok.filter((r) => !r.resourcesArsc).length,
    },
    entryCount: {
      mean: n === 0 ? null : Number((ok.reduce((s, r) => s + r.entryCount, 0) / n).toFixed(1)),
      max: ok.reduce((m, r) => Math.max(m, r.entryCount), 0),
    },
    zip64Apps: ok.filter((r) => r.zip64).length,
    twoFetchApps: ok.filter((r) => r.tailFetches === 2).length,
    serverIgnoredRange: ok.filter((r) => r.serverAcceptsRanges === false).length,
    failures: failed.map((r) => ({ packageName: r.packageName, error: r.error })).slice(0, 50),
    licenseSource,
  };
}

/**
 * Aggregate for the seeded subsample of the rows just measured, so the
 * headline can be quoted either as a census or as a fixed seeded sample.
 * Uses the same shuffle as listApps/sampleApps, so it is reproducible.
 */
export function subsampleAggregate(rows, { n, seed }) {
  const ordered = [...rows].sort((a, b) =>
    a.packageName < b.packageName ? -1 : a.packageName > b.packageName ? 1 : 0,
  );
  const take = Math.min(n, ordered.length);
  const { sample } = sampleApps(
    ordered.map((r) => ({ packageName: r.packageName, versionCode: r.versionCode })),
    { n: take, seed },
  );
  const chosen = new Set(sample.map((s) => `${s.packageName}:${s.versionCode}`));
  const sub = ordered.filter((r) => chosen.has(`${r.packageName}:${r.versionCode}`));
  const ok = sub.filter((r) => r.ok);
  const pure = ok.filter((r) => !r.hasNativeCode);
  const ci = wilsonInterval(pure.length, ok.length);
  return {
    seed,
    requestedN: take,
    inSample: sub.length,
    succeeded: ok.length,
    failed: sub.length - ok.length,
    numerator: pure.length,
    denominator: ok.length,
    percentNoNativeCode: pct(pure.length, ok.length),
    wilson95Low: ci.low === null ? null : ci.low * 100,
    wilson95High: ci.high === null ? null : ci.high * 100,
  };
}

export function renderReport(s) {
  const L = [];
  const p = (x = '') => L.push(x);
  const h = s.headline;
  p('F-Droid APK corpus survey');
  p('='.repeat(72));
  p(`index version        ${s.index.version}`);
  p(`index timestamp      ${s.index.timestampISO}  (epoch ms ${s.index.timestamp})`);
  p(`index sha256         ${s.index.sha256}`);
  p(`index bytes          ${s.index.bytes.toLocaleString('en-US')} (${s.run.indexFormat})`);
  p(`index retrieved      ${s.index.retrievedAt}`);
  p(`packages in index    ${s.population.packagesInIndex}`);
  p(`apps sampled         ${s.population.sampled} (${s.population.samplingMethod}, seed ${s.run.seed})`);
  p(`classified ok        ${s.population.succeeded}`);
  p(`failed               ${s.population.failed}`);
  p(`command              ${s.run.command}`);
  p(`duration             ${s.run.durationSeconds}s`);
  p('');
  p('HEADLINE');
  p('-'.repeat(72));
  p(`APKs with NO lib/<abi>/*.so entries: ${h.numerator} / ${h.denominator}`);
  p(`  = ${fmtPct(h.percentNoNativeCode)}   (Wilson 95% CI ${fmtPct(h.wilson95Low)} - ${fmtPct(h.wilson95High)})`);
  p(`APKs WITH native code:                  ${h.denominator - h.numerator} / ${h.denominator}`);
  p(`  = ${fmtPct(h.percentWithNativeCode)}`);
  if (s.seededSubsample) {
    const ss = s.seededSubsample;
    p('');
    p(`seeded subsample (n=${ss.inSample}, seed ${ss.seed}):`);
    p(`  no native code ${ss.numerator} / ${ss.denominator} = ${fmtPct(ss.percentNoNativeCode)}`);
    p(`  Wilson 95% CI ${fmtPct(ss.wilson95Low)} - ${fmtPct(ss.wilson95High)}`);
  }
  p('');
  p('BYTE COST');
  p('-'.repeat(72));
  p(`range reads fetched  ${s.bytes.totalFetched.toLocaleString('en-US')} B (${s.bytes.totalFetchedMiB} MiB)`);
  p(`full download would be ${s.bytes.fullDownloadWouldBeBytes.toLocaleString('en-US')} B (${s.bytes.fullDownloadWouldBeGiB} GiB)`);
  p(`fraction of a full download: ${s.bytes.fractionOfFullDownload === null ? 'n/a' : (100 * s.bytes.fractionOfFullDownload).toFixed(3) + '%'}`);
  p(`mean bytes per app   ${s.bytes.perApkMeanBytes} (APK mean ${s.bytes.perApkMeanApkBytes})`);
  p(`http requests        ${s.transfer.requestCount} (redirects ${s.transfer.redirectCount}, retries ${s.transfer.retryCount})`);
  p(`per-row byte sum     ${s.bytes.sumOfRowBytes.toLocaleString('en-US')} (must equal the total above)`);
  p(`per-row request sum  ${s.bytes.sumOfRowRequests} (must equal the request count above)`);
  p('');
  p('DEX');
  p('-'.repeat(72));
  p(`mean classes*.dex    ${s.dex.meanDexCount}`);
  p(`mean dex bytes       ${s.dex.meanCompressedDexBytes} compressed / ${s.dex.meanUncompressedDexBytes} uncompressed`);
  p(`apps with 0 dex      ${s.dex.zeroDexApps}`);
  p(`apps with >1 dex     ${s.dex.multiDexApps}`);
  p(`mean zip entries     ${s.entryCount.mean} (max ${s.entryCount.max})`);
  p(`zip64 archives       ${s.zip64Apps}`);
  p('');
  p('NATIVE ABIS');
  p('-'.repeat(72));
  p('libraries shipped, by ABI:');
  for (const [abi, n] of Object.entries(s.abis.librariesByAbi)) p(`  ${abi.padEnd(16)} ${n}`);
  p('apps shipping, by ABI:');
  for (const [abi, n] of Object.entries(s.abis.appsByAbi)) p(`  ${abi.padEnd(16)} ${n}`);
  p(`apps with a .so outside lib/: ${s.abis.straySharedObjectApps}`);
  p('');
  p('BY minSdkVersion (from each APK own AndroidManifest.xml)');
  p('-'.repeat(72));
  for (const [bucket, b] of Object.entries(s.minSdk.buckets)) {
    const w = b.total === 0 ? null : 100 * b.pure / b.total;
    p(`  ${bucket.padEnd(26)} no-native ${String(b.pure).padStart(5)} / ${String(b.total).padStart(5)}  ${fmtPct(w)}`);
  }
  p(`  manifest parsed: ${s.minSdk.manifestParsed}/${s.population.succeeded} (${fmtPct(100 * s.minSdk.manifestParseRate)})`);
  p(`  disagreements with the F-Droid index: ${s.minSdk.disagreementWithIndex}`);
  p('');
  p('CROSS-CHECK AGAINST THE INDEX DECLARATION');
  p('-'.repeat(72));
  p(`index says native            ${s.crossChecks.indexDeclaredNative}`);
  p(`  and we measured native      ${s.crossChecks.indexDeclaredAndMeasuredNative}`);
  p(`  but we measured none        ${s.crossChecks.indexDeclaredNativeButMeasuredNone}`);
  p(`we measured native, index said none  ${s.crossChecks.measuredNativeButIndexDeclaredNone}`);
  p('');
  p('OTHER');
  p('-'.repeat(72));
  p(`resources.arsc present       ${s.resourcesArsc.present}`);
  p(`needed 2 range requests      ${s.twoFetchApps}`);
  p(`server does not advertise ranges  ${s.serverIgnoredRange}`);
  if (s.failures.length) {
    p('');
    p('FAILURES (first 50)');
    for (const f of s.failures) p(`  ${f.packageName}: ${f.error}`);
  }
  return L.join('\n');
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname);
if (isMain) {
  main().catch((err) => {
    process.stderr.write(`[survey] fatal: ${err?.stack ?? err}\n`);
    process.exit(1);
  });
}
