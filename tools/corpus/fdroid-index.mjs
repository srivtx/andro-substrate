/**
 * F-Droid index access.
 *
 * Corpus choice and index format choice are argued in
 * docs/decisions/0001-corpus-and-scope.md. In short: index-v1.json is used
 * because it is the only serialisation that publishes an explicit
 * `repo.version` identifier, which is what pins a measurement to a named
 * index state. Both serialisations carry an identical `repo.timestamp`, so
 * nothing is lost by choosing v1.
 */

import { createHash } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readFile, rename, stat } from 'node:fs/promises';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

export const REPO_BASE = 'https://f-droid.org/repo';
export const DEFAULT_INDEX_FORMAT = 'v1';
export const SUPPORTED_INDEX_FORMATS = ['v1', 'v2'];

export function indexUrl(format = DEFAULT_INDEX_FORMAT, base = REPO_BASE) {
  if (!SUPPORTED_INDEX_FORMATS.includes(format)) {
    throw new Error(`unsupported index format: ${format}`);
  }
  return `${base}/index-${format}.json`;
}

/**
 * Cache lives under node_modules/.cache so that the repository's existing
 * .gitignore already excludes it and no ignore rule has to be edited.
 */
export function cacheDir() {
  return (
    process.env.ANDRO_INDEX_CACHE ??
    path.join(process.cwd(), 'node_modules', '.cache', 'fdroid')
  );
}

export function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

async function sha256File(file) {
  const hash = createHash('sha256');
  const buf = await readFile(file);
  hash.update(buf);
  return { sha256: hash.digest('hex'), bytes: buf.length };
}

async function exists(file) {
  try {
    await stat(file);
    return true;
  } catch {
    return false;
  }
}

/**
 * Download the index once and cache it by URL. Returns the identity of the
 * exact bytes on disk: byte count, SHA-256, retrieval time and the ETag /
 * Last-Modified the server reported.
 */
export async function downloadIndex({
  format = DEFAULT_INDEX_FORMAT,
  base = REPO_BASE,
  cache = cacheDir(),
  force = false,
  onProgress,
} = {}) {
  const url = indexUrl(format, base);
  const dir = path.join(cache, format);
  await mkdir(dir, { recursive: true });
  const file = path.join(dir, 'index.json');

  let fromCache = false;
  let httpMeta = null;

  if (!force && (await exists(file))) {
    fromCache = true;
  } else {
    const res = await fetch(url, { headers: { 'accept-encoding': 'identity' } });
    if (!res.ok) throw new Error(`index download failed: HTTP ${res.status} for ${url}`);
    httpMeta = {
      etag: res.headers.get('etag'),
      lastModified: res.headers.get('last-modified'),
      retrievedAt: new Date().toISOString(),
    };
    const tmp = `${file}.partial`;
    let seen = 0;
    const total = Number(res.headers.get('content-length') ?? 0);
    const source = Readable.fromWeb(res.body);
    source.on('data', (chunk) => {
      seen += chunk.length;
      onProgress?.({ url, seen, total });
    });
    await pipeline(source, createWriteStream(tmp));
    await rename(tmp, file);
  }

  const { sha256: digest, bytes } = await sha256File(file);
  const json = JSON.parse(await readFile(file, 'utf8'));
  const retrievedAt = httpMeta?.retrievedAt ?? (await stat(file)).mtime.toISOString();

  return {
    path: file,
    url,
    format,
    bytes,
    sha256: digest,
    fromCache,
    retrievedAt,
    etag: httpMeta?.etag ?? null,
    lastModified: httpMeta?.lastModified ?? null,
    json,
    identity: indexIdentity(json, { bytes, sha256: digest, retrievedAt, url }),
  };
}

export function indexIdentity(json, { bytes, sha256: digest, retrievedAt, url } = {}) {
  const repo = json?.repo ?? {};
  return {
    url: url ?? null,
    version: repo.version ?? null,
    maxage: repo.maxage ?? null,
    timestamp: repo.timestamp ?? null,
    timestampISO: repo.timestamp ? new Date(repo.timestamp).toISOString() : null,
    address: repo.address ?? null,
    bytes: bytes ?? null,
    sha256: digest ?? null,
    retrievedAt: retrievedAt ?? null,
  };
}

function versionRecordsOf(pkg) {
  const out = [];
  for (const key of Object.keys(pkg)) {
    const rec = pkg[key];
    if (rec && typeof rec === 'object' && typeof rec.versionCode === 'number') {
      out.push(rec);
    }
  }
  out.sort((a, b) => {
    if (a.versionCode !== b.versionCode) return a.versionCode - b.versionCode;
    const at = a.added ?? 0;
    const bt = b.added ?? 0;
    if (at !== bt) return at - bt;
    return a.apkName < b.apkName ? -1 : a.apkName > b.apkName ? 1 : 0;
  });
  return out;
}

export function apkUrl(app, { base = REPO_BASE } = {}) {
  if (app.apkName) return `${base}/${app.apkName}`;
  return `${base}/${app.packageName}_${app.versionCode}.apk`;
}

function toApp(pkgName, rec) {
  return {
    packageName: pkgName,
    versionCode: rec.versionCode,
    versionName: rec.versionName ?? null,
    apkName: rec.apkName ?? `${pkgName}_${rec.versionCode}.apk`,
    indexSha256: rec.hash ?? null,
    indexHashType: rec.hashType ?? null,
    indexSize: typeof rec.size === 'number' ? rec.size : null,
    indexMinSdk: typeof rec.minSdkVersion === 'number' ? rec.minSdkVersion : null,
    indexTargetSdk: typeof rec.targetSdkVersion === 'number' ? rec.targetSdkVersion : null,
    indexDeclaredAbis: Array.isArray(rec.nativecode) ? rec.nativecode : [],
    indexSourceName: rec.srcname ?? null,
    added: rec.added ?? null,
    apkUrl: apkUrl({ packageName: pkgName, apkName: rec.apkName, versionCode: rec.versionCode }),
  };
}

/**
 * Deterministic app list: every package in the index, reduced to its highest
 * versionCode, sorted by packageName with a code-unit comparison so the order
 * never depends on the host locale.
 */
export function listApps(json) {
  const packages = json?.packages ?? {};
  const apps = [];
  for (const pkgName of Object.keys(packages)) {
    const records = versionRecordsOf(packages[pkgName]);
    if (records.length === 0) continue;
    apps.push(toApp(pkgName, records[records.length - 1]));
  }
  apps.sort((a, b) => (a.packageName < b.packageName ? -1 : a.packageName > b.packageName ? 1 : 0));
  return apps;
}

/** Every (package, version) pair, deterministically ordered. */
export function listAllVersions(json) {
  const packages = json?.packages ?? {};
  const apps = [];
  for (const pkgName of Object.keys(packages)) {
    for (const rec of versionRecordsOf(packages[pkgName])) {
      apps.push(toApp(pkgName, rec));
    }
  }
  apps.sort((a, b) => {
    if (a.packageName !== b.packageName) return a.packageName < b.packageName ? -1 : 1;
    return a.versionCode - b.versionCode;
  });
  return apps;
}

/** mulberry32: 32-bit integer PRNG, identical on every platform and Node build. */
export function makeRng(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** In-place Fisher-Yates driven by `rng`. */
export function shuffleInPlace(items, rng) {
  for (let i = items.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    const tmp = items[i];
    items[i] = items[j];
    items[j] = tmp;
  }
  return items;
}

/**
 * Deterministic sample: sort first, then shuffle the sorted list with a
 * seeded PRNG, then take n. The same seed and index always produce the same
 * n apps in the same order.
 */
export function sampleApps(apps, { n, seed }) {
  const ordered = [...apps].sort((a, b) =>
    a.packageName < b.packageName ? -1 : a.packageName > b.packageName ? 1 : 0,
  );
  if (n >= ordered.length) return { sample: ordered, shuffled: false, population: ordered.length };
  return {
    sample: shuffleInPlace(ordered, makeRng(seed)).slice(0, n),
    shuffled: true,
    population: ordered.length,
  };
}

/**
 * Optional enrichment: index-v2 carries per-package metadata including
 * licence, which the v1 serialisation dropped. Purely additive, and keyed by
 * package name, which is common to both serialisations.
 */
export function attachLicenses(v1Json, v2Json) {
  const licenses = new Map();
  for (const pkgName of Object.keys(v2Json?.packages ?? {})) {
    const license = v2Json.packages[pkgName]?.metadata?.license;
    if (typeof license === 'string') licenses.set(pkgName, license);
  }
  return (apps) =>
    apps.map((app) => ({ ...app, license: licenses.get(app.packageName) ?? null }));
}
