import assert from 'node:assert/strict';
import test from 'node:test';
import { deflateRawSync } from 'node:zlib';

import {
  parseCentralDirectory,
  parseEocd,
  parseTailIfComplete,
  findEocdOffset,
  ZipFormatError,
  SIG_EOCD,
} from '../tools/corpus/zip-central-directory.mjs';
import { buildZip, RangeFetcher } from '../tools/corpus/range-fetch.mjs';
import { parseUsesSdk, summariseEntries, classifyApk } from '../tools/corpus/classify.mjs';

const NAMES = [
  'AndroidManifest.xml',
  'classes.dex',
  'classes2.dex',
  'resources.arsc',
  'res/drawable/icon.png',
  'assets/foo/bar.txt',
  'META-INF/CERT.RSA',
];

function readCdOf(zip, expectedCount) {
  return parseCentralDirectory(zip.buffer, { offset: zip.cdOffset, expectedCount });
}

test('recovers exact entry names from a synthetic archive', () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.from(name) })));
  const entries = readCdOf(zip, NAMES.length);
  assert.deepEqual(
    entries.map((e) => e.name),
    NAMES,
  );
  assert.equal(entries.every((e) => !e.isDirectory), true);
  assert.equal(entries[0].method, 0);
  assert.equal(entries[0].localHeaderOffset, 0);
});

test('detects lib/x86_64/libfoo.so and enumerates ABIs', () => {
  const names = [
    'AndroidManifest.xml',
    'classes.dex',
    'lib/x86_64/libfoo.so',
    'lib/arm64-v8a/libfoo.so',
    'lib/armeabi-v7a/libbar.so',
  ];
  const zip = buildZip(names.map((name) => ({ name, data: Buffer.alloc(7) })));
  const entries = readCdOf(zip, names.length);
  assert.ok(entries.some((e) => e.name === 'lib/x86_64/libfoo.so'));

  const summary = summariseEntries(entries);
  assert.equal(summary.hasNativeCode, true);
  assert.equal(summary.nativeLibraryCount, 3);
  assert.deepEqual(summary.nativeAbiCounts, {
    'arm64-v8a': 1,
    'armeabi-v7a': 1,
    x86_64: 1,
  });
  assert.equal(summary.dexCount, 1);
  assert.equal(summary.resourcesArsc, false);
  assert.deepEqual(summary.straySharedObjects, []);
});

test('an archive with no lib/ entry is reported as native-free', () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.from(name) })));
  const summary = summariseEntries(readCdOf(zip, NAMES.length));
  assert.equal(summary.hasNativeCode, false);
  assert.equal(Object.keys(summary.nativeAbiCounts).length, 0);
  assert.equal(summary.resourcesArsc, true);
  assert.equal(summary.dexCount, 2);
  assert.deepEqual(summary.dexNames, ['classes.dex', 'classes2.dex']);
});

test('a .so outside lib/ is surfaced separately, not as an ABI', () => {
  const names = ['classes.dex', 'assets/preload/libthing.so'];
  const zip = buildZip(names.map((name) => ({ name, data: Buffer.alloc(3) })));
  const summary = summariseEntries(readCdOf(zip, names.length));
  assert.equal(summary.hasNativeCode, false);
  assert.deepEqual(summary.straySharedObjects, ['assets/preload/libthing.so']);
});

test('directory entries are flagged and not counted as native code', () => {
  const zip = buildZip([
    { name: 'lib/', data: Buffer.alloc(0) },
    { name: 'lib/arm64-v8a/', data: Buffer.alloc(0) },
  ]);
  const entries = readCdOf(zip, 2);
  assert.equal(entries.every((e) => e.isDirectory), true);
  assert.equal(summariseEntries(entries).hasNativeCode, false);
});

test('deflated entries report both compressed and uncompressed sizes', () => {
  const payload = Buffer.from('dex\n035\0'.repeat(500), 'binary');
  const deflated = deflateRawSync(payload);
  const zip = buildZip([
    { name: 'classes.dex', data: deflated, method: 8, compressedSize: deflated.length, uncompressedSize: payload.length },
  ]);
  const entries = readCdOf(zip, 1);
  assert.equal(entries[0].method, 8);
  assert.equal(entries[0].compressedSize, deflated.length);
  assert.equal(entries[0].uncompressedSize, payload.length);
  const summary = summariseEntries(entries);
  assert.equal(summary.dexBytes, deflated.length);
  assert.equal(summary.dexUncompressedBytes, payload.length);
});

test('ZIP64 archives parse through the ZIP64 EOCD record', () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.alloc(5) })), { zip64: true });
  const eocd = parseEocd(zip.buffer, 0);
  assert.equal(eocd.zip64, true);
  assert.equal(eocd.entryCount, NAMES.length);
  assert.equal(eocd.cdOffset, zip.cdOffset);
  const entries = readCdOf(zip, NAMES.length);
  assert.deepEqual(
    entries.map((e) => e.name),
    NAMES,
  );
});

test('a large comment does not defeat EOCD discovery', () => {
  const comment = Buffer.alloc(5000, 0x2a);
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.alloc(1) })), { comment });
  const eocd = parseEocd(zip.buffer, 0);
  assert.equal(eocd.commentLength, 5000);
  assert.equal(eocd.entryCount, NAMES.length);
  assert.equal(eocd.comment.length, 5000);
});

test('a truncated buffer is rejected with a format error', () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.alloc(9) })));
  const truncated = zip.buffer.subarray(0, Math.floor(zip.buffer.length / 2));
  assert.throws(
    () => parseEocd(truncated, 0),
    (err) => err instanceof ZipFormatError && /no End Of Central Directory/.test(err.message),
  );
});

test('a buffer with no EOCD at all is rejected', () => {
  const junk = Buffer.alloc(4096, 0x41);
  assert.throws(
    () => parseEocd(junk, 0),
    (err) => err instanceof ZipFormatError && /no End Of Central Directory/.test(err.message),
  );
  assert.throws(
    () => findEocdOffset(Buffer.alloc(8)),
    (err) => err instanceof ZipFormatError && /too small/.test(err.message),
  );
});

test('a central directory that ends early is rejected against the EOCD count', () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.alloc(4) })));
  const cd = zip.buffer.subarray(zip.cdOffset, zip.cdOffset + zip.cdSize);
  const cut = cd.subarray(0, Math.floor(cd.length / 2));
  assert.throws(
    () => parseCentralDirectory(cut, { offset: 0, expectedCount: NAMES.length }),
    (err) => err instanceof ZipFormatError,
  );
});

test('a lying central directory offset is rejected', () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.alloc(4) })), { corruptCdOffset: 17 });
  const eocd = parseEocd(zip.buffer, 0);
  assert.equal(eocd.cdOffset, 17);
  assert.throws(
    () => parseCentralDirectory(zip.buffer, { offset: 17, expectedCount: NAMES.length }),
    (err) => err instanceof ZipFormatError && /signature mismatch/.test(err.message),
  );
});

test('a ZIP64 sentinel without a ZIP64 record is rejected', () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.alloc(4) })));
  const buf = Buffer.from(zip.buffer);
  buf.writeUInt16LE(0xffff, findEocdOffset(buf) + 10);
  assert.throws(
    () => parseEocd(buf, 0),
    (err) => err instanceof ZipFormatError && /ZIP64 sentinel/.test(err.message),
  );
});

test('parseTailIfComplete reads the directory when the tail already holds it', () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.alloc(6) })));
  const tail = { buffer: zip.buffer, start: 0 };
  const out = parseTailIfComplete(tail);
  assert.equal(out.complete, true);
  assert.deepEqual(
    out.entries.map((e) => e.name),
    NAMES,
  );
});

test('parseTailIfComplete reports incompleteness when the directory starts before the tail', () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.alloc(64) })));
  const tailStart = zip.cdOffset + 5;
  const tail = { buffer: zip.buffer.subarray(tailStart), start: tailStart };
  const out = parseTailIfComplete(tail);
  assert.equal(out.complete, false);
  assert.equal(out.entries, null);
  assert.equal(out.eocd.entryCount, NAMES.length);
  assert.equal(out.eocd.cdOffset, zip.cdOffset);
});

test('UTF-8 flagged entry names decode as UTF-8', () => {
  const name = 'assets/ünicode-\u{1f600}.txt';
  const zip = buildZip([{ name, data: Buffer.alloc(1), flags: 0x0800 }]);
  const entries = readCdOf(zip, 1);
  assert.equal(entries[0].name, name);
  assert.equal(entries[0].flags & 0x0800, 0x0800);
});

test('the EOCD signature is found only at a comment-consistent offset', () => {
  const zip = buildZip([{ name: 'a.txt', data: Buffer.alloc(1) }]);
  const buf = Buffer.from(zip.buffer);
  const at = findEocdOffset(buf);
  assert.equal(buf.readUInt32LE(at), SIG_EOCD);
  const lying = Buffer.from(buf);
  lying.writeUInt32LE(SIG_EOCD, 4);
  assert.equal(findEocdOffset(lying), at);
});

/* --------------------------------------------------- range fetch + AXML --- */

test('RangeFetcher follows a redirect and charges only the bytes of the final body', async () => {
  const payload = Buffer.from('hello range world');
  const impl = async (url) => {
    if (url.endsWith('/a.apk')) {
      return new Response(null, { status: 302, headers: { location: 'https://cdn.example/b.apk' } });
    }
    const body = payload.subarray(6, 11);
    return new Response(body, {
      status: 206,
      headers: { 'content-range': `bytes 6-10/${payload.length}` },
    });
  };
  const fetcher = new RangeFetcher({ fetchImpl: impl });
  const got = await fetcher.fetchRange('https://f-droid.org/repo/a.apk', 6, 10);
  assert.equal(got.buffer.toString(), 'range');
  assert.equal(got.start, 6);
  assert.equal(got.end, 10);
  assert.equal(got.totalSize, payload.length);
  assert.equal(fetcher.redirectCount, 1);
  assert.equal(fetcher.bytesFetched, 5);
});

test('RangeFetcher charges the whole body when the server ignores Range', async () => {
  const whole = Buffer.from('0123456789');
  const impl = async () => new Response(whole, { status: 200 });
  const fetcher = new RangeFetcher({ fetchImpl: impl });
  const got = await fetcher.fetchRange('https://x/a.apk', 2, 4);
  assert.equal(got.partial, false);
  assert.equal(got.buffer.toString(), '234');
  assert.equal(fetcher.bytesFetched, whole.length);
});

test('RangeFetcher retries a 503 and then succeeds', async () => {
  let calls = 0;
  const impl = async () => {
    calls += 1;
    if (calls < 3) return new Response('busy', { status: 503 });
    return new Response(Buffer.from('ok'), {
      status: 206,
      headers: { 'content-range': 'bytes 0-1/99' },
    });
  };
  const fetcher = new RangeFetcher({ fetchImpl: impl, retryBaseDelayMs: 1 });
  const got = await fetcher.fetchRange('https://x/a.apk', 0, 1);
  assert.equal(got.buffer.toString(), 'ok');
  assert.equal(calls, 3);
  assert.equal(fetcher.retryCount, 2);
});

test('RangeFetcher retries a connection-level failure and then succeeds', async () => {
  let calls = 0;
  const impl = async () => {
    calls += 1;
    if (calls < 3) throw new TypeError('fetch failed');
    return new Response(Buffer.from('ok'), {
      status: 206,
      headers: { 'content-range': 'bytes 0-1/99' },
    });
  };
  const fetcher = new RangeFetcher({ fetchImpl: impl, retryBaseDelayMs: 1 });
  const got = await fetcher.fetchRange('https://x/a.apk', 0, 1);
  assert.equal(got.buffer.toString(), 'ok');
  assert.equal(calls, 3);
  assert.equal(fetcher.retryCount, 2);
});

test('RangeFetcher does not retry a terminal 404', async () => {
  let calls = 0;
  const impl = async () => {
    calls += 1;
    return new Response('missing', { status: 404 });
  };
  const fetcher = new RangeFetcher({ fetchImpl: impl, retryBaseDelayMs: 1 });
  await assert.rejects(() => fetcher.fetchRange('https://x/a.apk', 0, 1));
  assert.equal(calls, 1);
  assert.equal(fetcher.retryCount, 0);
});

test('classifyApk derives native-code facts from a byte-range-only fetcher', async () => {
  const payload = Buffer.alloc(400 * 1024, 0x5a);
  const names = [
    'AndroidManifest.xml',
    'classes.dex',
    'classes2.dex',
    'resources.arsc',
    'lib/arm64-v8a/libfoo.so',
  ];
  const zip = buildZip(names.map((name) => ({ name, data: payload })));
  const whole = zip.buffer;
  const impl = async (url, init) => {
    const range = init?.headers?.range;
    if (init?.method === 'HEAD') {
      return new Response(null, {
        status: 200,
        headers: { 'content-length': String(whole.length), 'accept-ranges': 'bytes' },
      });
    }
    if (!range) return new Response(whole, { status: 200 });
    if (range.startsWith('bytes=-')) {
      const n = Number(range.slice('bytes=-'.length));
      const start = Math.max(0, whole.length - n);
      return new Response(whole.subarray(start), {
        status: 206,
        headers: { 'content-range': `bytes ${start}-${whole.length - 1}/${whole.length}` },
      });
    }
    const m = /bytes=(\d+)-(\d+)/.exec(range);
    return new Response(whole.subarray(Number(m[1]), Number(m[2]) + 1), {
      status: 206,
      headers: { 'content-range': `bytes ${m[1]}-${m[2]}/${whole.length}` },
    });
  };
  const fetcher = new RangeFetcher({ fetchImpl: impl });
  const row = await classifyApk(
    { packageName: 'com.example', versionCode: 1, apkName: 'com.example_1.apk', apkUrl: 'https://x/com.example_1.apk' },
    fetcher,
    { withManifest: false },
  );
  assert.equal(row.ok, true);
  assert.equal(row.hasNativeCode, true);
  assert.deepEqual(row.nativeAbiCounts, { 'arm64-v8a': 1 });
  assert.equal(row.dexCount, 2);
  assert.equal(row.resourcesArsc, true);
  assert.equal(row.entryCount, names.length);
  assert.equal(row.centralDirectorySha256.length, 64);
  assert.ok(row.bytesFetched < whole.length, 'range reads must cost less than a full download');
});

test('per-row byte accounting is exact when many rows share one fetcher', async () => {
  const zip = buildZip(NAMES.map((name) => ({ name, data: Buffer.alloc(4096) })));
  const whole = zip.buffer;
  const impl = async (url, init) => {
    const range = init?.headers?.range;
    if (init?.method === 'HEAD') {
      return new Response(null, {
        status: 200,
        headers: { 'content-length': String(whole.length), 'accept-ranges': 'bytes' },
      });
    }
    if (range.startsWith('bytes=-')) {
      const n = Number(range.slice('bytes=-'.length));
      const start = Math.max(0, whole.length - n);
      return new Response(whole.subarray(start), {
        status: 206,
        headers: { 'content-range': `bytes ${start}-${whole.length - 1}/${whole.length}` },
      });
    }
    const m = /bytes=(\d+)-(\d+)/.exec(range);
    return new Response(whole.subarray(Number(m[1]), Number(m[2]) + 1), {
      status: 206,
      headers: { 'content-range': `bytes ${m[1]}-${m[2]}/${whole.length}` },
    });
  };
  const fetcher = new RangeFetcher({ fetchImpl: impl });
  const apps = Array.from({ length: 24 }, (_, i) => ({
    packageName: `pkg${i}`,
    versionCode: 1,
    apkName: `pkg${i}.apk`,
    apkUrl: `https://x/pkg${i}.apk`,
  }));
  const rows = await Promise.all(apps.map((a) => classifyApk(a, fetcher, { withManifest: true })));
  assert.equal(rows.every((r) => r.ok), true);
  const rowSum = rows.reduce((s, r) => s + r.bytesFetched, 0);
  const reqSum = rows.reduce((s, r) => s + r.requests, 0);
  assert.equal(rowSum, fetcher.bytesFetched, 'per-row bytes must sum to the global total');
  assert.equal(reqSum, fetcher.requestCount, 'per-row requests must sum to the global total');
});

test('parseUsesSdk rejects a non-AXML buffer instead of inventing values', () => {
  assert.throws(() => parseUsesSdk(Buffer.from('not axml at all')));
  const declared = Buffer.alloc(16);
  declared.writeUInt16LE(0x0003, 0);
  declared.writeUInt16LE(8, 2);
  declared.writeUInt32LE(16, 4);
  assert.deepEqual(parseUsesSdk(declared), { minSdkVersion: null, targetSdkVersion: null });
});

/**
 * Build a minimal Android binary-XML document: a string pool plus one
 * start-element node, in either string-pool encoding. Only as much of
 * ResourceTypes.h as parseUsesSdk consumes.
 */
function buildAxml(strings, { element, attributes, utf8 }) {
  const encoded = [];
  const offsets = [];
  let dataLen = 0;
  for (const s of strings) {
    offsets.push(dataLen);
    if (utf8) {
      const bytes = Buffer.from(s, 'utf8');
      const varLen = (v) => (v < 0x80 ? Buffer.from([v]) : Buffer.from([0x80 | (v >> 8), v & 0xff]));
      const head = Buffer.concat([varLen(s.length), varLen(bytes.length)]);
      const chunk = Buffer.concat([head, bytes, Buffer.from([0])]);
      encoded.push(chunk);
      dataLen += chunk.length;
    } else {
      const chars = Buffer.from(s, 'utf16le');
      const chunk = Buffer.concat([chars.length === 0 ? Buffer.alloc(0) : (() => {
        const l = Buffer.alloc(2);
        l.writeUInt16LE(s.length, 0);
        return l;
      })(), chars, Buffer.alloc(2)]);
      encoded.push(chunk);
      dataLen += chunk.length;
    }
  }

  const poolHeaderSize = 28;
  const offsetsLen = strings.length * 4;
  const stringsStart = poolHeaderSize + offsetsLen;
  const poolSize = stringsStart + dataLen;
  const pool = Buffer.alloc(poolSize);
  pool.writeUInt16LE(0x0001, 0);
  pool.writeUInt16LE(poolHeaderSize, 2);
  pool.writeUInt32LE(poolSize, 4);
  pool.writeUInt32LE(strings.length, 8);
  pool.writeUInt32LE(0, 12);
  pool.writeUInt32LE(utf8 ? 0x0100 : 0, 16);
  pool.writeUInt32LE(stringsStart, 20);
  pool.writeUInt32LE(0, 24);
  offsets.forEach((o, i) => pool.writeUInt32LE(o, poolHeaderSize + i * 4));
  let cursor = stringsStart;
  for (const c of encoded) {
    c.copy(pool, cursor);
    cursor += c.length;
  }

  const extSize = 20;
  const attrSize = 20;
  const nodeSize = 16 + extSize + attributes.length * attrSize;
  const node = Buffer.alloc(nodeSize);
  node.writeUInt16LE(0x0102, 0);
  node.writeUInt16LE(16, 2);
  node.writeUInt32LE(nodeSize, 4);
  node.writeUInt32LE(1, 8);
  node.writeInt32LE(-1, 12);
  node.writeInt32LE(-1, 16);
  node.writeInt32LE(element, 20);
  node.writeUInt16LE(extSize, 24);
  node.writeUInt16LE(attrSize, 26);
  node.writeUInt16LE(attributes.length, 28);
  node.writeUInt16LE(0, 30);
  node.writeUInt16LE(0, 32);
  node.writeUInt16LE(0, 34);
  attributes.forEach((a, i) => {
    const at = 16 + extSize + i * attrSize;
    node.writeInt32LE(-1, at);
    node.writeInt32LE(a.name, at + 4);
    node.writeInt32LE(-1, at + 8);
    node.writeUInt16LE(8, at + 12);
    node.writeUInt8(0, at + 14);
    node.writeUInt8(a.dataType, at + 15);
    node.writeInt32LE(a.data, at + 16);
  });

  const total = 8 + poolSize + nodeSize;
  const file = Buffer.alloc(total);
  file.writeUInt16LE(0x0003, 0);
  file.writeUInt16LE(8, 2);
  file.writeUInt32LE(total, 4);
  pool.copy(file, 8);
  node.copy(file, 8 + poolSize);
  return file;
}

const SDK_STRINGS = ['uses-sdk', 'minSdkVersion', 'targetSdkVersion', 'other'];

for (const utf8 of [false, true]) {
  test(`parseUsesSdk reads uses-sdk from a ${utf8 ? 'UTF-8' : 'UTF-16'} string pool`, () => {
    const axml = buildAxml(SDK_STRINGS, {
      element: 0,
      attributes: [
        { name: 1, dataType: 0x10, data: 21 },
        { name: 2, dataType: 0x10, data: 34 },
        { name: 3, dataType: 0x10, data: 99 },
      ],
      utf8,
    });
    assert.deepEqual(parseUsesSdk(axml), { minSdkVersion: 21, targetSdkVersion: 34 });
  });
}

test('parseUsesSdk accepts a string-typed api level', () => {
  const axml = buildAxml(SDK_STRINGS, {
    element: 0,
    attributes: [
      { name: 1, dataType: 0x03, data: 0 },
      { name: 2, dataType: 0x10, data: 30 },
    ],
    utf8: true,
  });
  assert.deepEqual(parseUsesSdk(axml), { minSdkVersion: null, targetSdkVersion: 30 });
});

test('parseUsesSdk returns nulls when there is no uses-sdk element', () => {
  const axml = buildAxml(SDK_STRINGS, {
    element: 3,
    attributes: [{ name: 1, dataType: 0x10, data: 21 }],
    utf8: false,
  });
  assert.deepEqual(parseUsesSdk(axml), { minSdkVersion: null, targetSdkVersion: null });
});
