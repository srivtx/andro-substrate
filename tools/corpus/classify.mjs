/**
 * APK classifier built on the central directory reader.
 *
 * Everything reported here is derived from ZIP entry names plus, optionally,
 * the raw bytes of AndroidManifest.xml fetched with one extra small range
 * request. No entry payload is ever downloaded in full, and no APK is
 * downloaded in full.
 */

import { inflateRawSync } from 'node:zlib';
import { createHash } from 'node:crypto';

import { parseEocd, parseCentralDirectory, parseTailIfComplete } from './zip-central-directory.mjs';

export const TAIL_BYTES = 131_072;
const METHOD_STORED = 0;
const METHOD_DEFLATED = 8;
const LOCAL_HEADER_SIZE = 30;
const SIG_LOCAL = 0x04034b50;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;

const NATIVE_LIB_RE = /^lib\/([^/]+)\/(.+)$/;
const SO_NAME_RE = /\.so$/;
const DEX_NAME_RE = /(^|\/)classes(\d*)\.dex$/;

export function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function summariseEntries(entries) {
  const abis = new Map();
  const dex = [];
  let resourcesArsc = false;
  let manifest = null;
  let straySharedObjects = [];
  let otherDexCount = 0;
  let totalUncompressed = 0;
  let totalCompressed = 0;

  for (const e of entries) {
    totalUncompressed += e.uncompressedSize;
    totalCompressed += e.compressedSize;
    if (e.name === 'resources.arsc') resourcesArsc = true;
    if (e.name === 'AndroidManifest.xml') manifest = e;
    if (DEX_NAME_RE.test(e.name)) {
      dex.push(e);
    } else if (e.name.endsWith('.dex')) {
      otherDexCount += 1;
    }
    const lib = NATIVE_LIB_RE.exec(e.name);
    if (lib && SO_NAME_RE.test(lib[2]) && !e.isDirectory) {
      abis.set(lib[1], (abis.get(lib[1]) ?? 0) + 1);
    } else if (SO_NAME_RE.test(e.name) && !lib && !e.isDirectory) {
      straySharedObjects.push(e.name);
    }
  }

  dex.sort((a, b) => a.name.localeCompare(b.name));
  return {
    nativeAbiCounts: Object.fromEntries([...abis.entries()].sort()),
    nativeLibraryCount: [...abis.values()].reduce((s, n) => s + n, 0),
    hasNativeCode: abis.size > 0,
    dexCount: dex.length,
    dexBytes: dex.reduce((s, e) => s + e.compressedSize, 0),
    dexUncompressedBytes: dex.reduce((s, e) => s + e.uncompressedSize, 0),
    dexNames: dex.map((e) => e.name),
    otherDexCount,
    resourcesArsc,
    hasManifest: manifest !== null,
    manifest,
    straySharedObjects,
    totalUncompressedBytes: totalUncompressed,
    totalCompressedBytes: totalCompressed,
  };
}

/* ---------------------------------------------------------------- AXML --- */

const RES_STRING_POOL = 0x0001;
const RES_XML = 0x0003;
const RES_XML_START_ELEMENT = 0x0102;
const TYPE_STRING = 0x03;
const TYPE_INT_DEC = 0x10;
const TYPE_INT_HEX = 0x11;
/** ResStringPool.flags UTF8_FLAG, which is 1 << 8 and not the ZIP flag. */
const AXML_UTF8_FLAG = 0x0100;

/**
 * AOSP variable-length integer used in string pools: one byte when the high
 * bit is clear, otherwise two bytes with the high bit of the first cleared.
 */
function readLength(buf, pos) {
  const b0 = buf[pos] ?? 0;
  if (b0 & 0x80) {
    return { value: ((b0 & 0x7f) << 8) | (buf[pos + 1] ?? 0), size: 2 };
  }
  return { value: b0 & 0x7f, size: 1 };
}

/**
 * Parse just enough of the Android binary XML resource format to recover the
 * `uses-sdk` element's minSdkVersion and targetSdkVersion.
 * Layout follows the AOSP ResourceTypes.h ResChunk / ResStringPool headers.
 */
export function parseUsesSdk(xmlBuf) {
  const buf = xmlBuf;
  if (buf.length < 8 || buf.readUInt16LE(0) !== RES_XML) {
    throw new Error('not an AXML document');
  }
  const fileSize = buf.readUInt32LE(4);
  const limit = Math.min(fileSize, buf.length);

  let strings = null;
  let pos = buf.readUInt16LE(2);

  const getString = (index) => {
    if (!strings) return null;
    if (index < 0 || index >= strings.count) return null;
    const { data, starts } = strings;
    const start = starts[index];
    if (start === undefined || start < 0 || start >= data.length) return null;
    if (strings.utf8) {
      // UTF-8 pool entries are: u16 length, u8 length, bytes, 0x00.
      const utf16Len = readLength(data, start);
      const utf8Len = readLength(data, start + utf16Len.size);
      let p = start + utf16Len.size + utf8Len.size;
      const bytes = [];
      for (let i = 0; i < utf8Len.value; i++) {
        if (p >= data.length) break;
        const b = data[p];
        if (b === 0) break;
        if ((b & 0x80) === 0) {
          bytes.push(b);
          p += 1;
        } else {
          if (p + 1 >= data.length) break;
          bytes.push(((b & 0x1f) << 6) | (data[p + 1] & 0x3f));
          p += 2;
        }
      }
      return Buffer.from(bytes).toString('utf8');
    }
    // UTF-16 pool entries are: u16 length, UTF-16LE code units, 0x0000.
    // The length prefix here is a plain 16-bit field, not a variable-width
    // one, so it is always two bytes.
    const charLen = data.readUInt16LE(start);
    const from = start + 2;
    const end = Math.min(data.length, from + charLen * 2);
    const units = Buffer.from(data.subarray(from, end));
    const even = units.length % 2 === 0 ? units : units.subarray(0, units.length - 1);
    return even.toString('utf16le').replace(/\0+$/, '');
  };

  while (pos + 8 <= limit) {
    const type = buf.readUInt16LE(pos);
    const headerSize = buf.readUInt16LE(pos + 2);
    const chunkSize = buf.readUInt32LE(pos + 4);
    if (chunkSize < 8 || pos + chunkSize > limit) break;

    if (type === RES_STRING_POOL) {
      const count = buf.readUInt32LE(pos + 8);
      const flags = buf.readUInt32LE(pos + 16);
      const stringsStart = buf.readUInt32LE(pos + 20);
      const isUtf8 = (flags & AXML_UTF8_FLAG) !== 0;
      // Offsets are u32 byte offsets into the string data for both encodings.
      const startsOffset = pos + headerSize;
      const starts = new Array(count);
      for (let i = 0; i < count; i++) {
        starts[i] = buf.readUInt32LE(startsOffset + i * 4);
      }
      strings = {
        count,
        utf8: isUtf8,
        starts,
        data: buf.subarray(pos + stringsStart, pos + chunkSize),
      };
    } else if (type === RES_XML_START_ELEMENT) {
      const extOffset = pos + headerSize;
      const nameIndex = buf.readInt32LE(extOffset + 4);
      const attributeStart = buf.readUInt16LE(extOffset + 8);
      const attributeSize = buf.readUInt16LE(extOffset + 10);
      const attributeCount = buf.readUInt16LE(extOffset + 12);
      const elementName = getString(nameIndex);
      if (elementName === 'uses-sdk') {
        const values = {};
        const base = extOffset + attributeStart;
        for (let i = 0; i < attributeCount; i++) {
          const a = base + i * attributeSize;
          if (a + 20 > pos + chunkSize) break;
          const attrNameIndex = buf.readInt32LE(a + 4);
          const attrName = getString(attrNameIndex);
          if (attrName !== 'minSdkVersion' && attrName !== 'targetSdkVersion') continue;
          const dataType = buf.readUInt8(a + 15);
          const data = buf.readInt32LE(a + 16);
          if (dataType === TYPE_INT_DEC || dataType === TYPE_INT_HEX) {
            values[attrName] = data;
          } else if (dataType === TYPE_STRING) {
            const s = getString(data);
            const n = s === null ? null : Number.parseInt(s, 10);
            if (Number.isInteger(n)) values[attrName] = n;
          }
        }
        return {
          minSdkVersion: values.minSdkVersion ?? null,
          targetSdkVersion: values.targetSdkVersion ?? null,
        };
      }
    }
    pos += chunkSize;
  }
  return { minSdkVersion: null, targetSdkVersion: null };
}

/**
 * Fetch and parse AndroidManifest.xml for one entry, using the local header
 * to find the payload offset. Returns null on any failure: a missing
 * manifest must never abort a survey.
 */
export async function readUsesSdk(fetcher, apkUrl, entry) {
  let charged = 0;
  let chargedRequests = 0;
  try {
    if (!Number.isSafeInteger(entry.localHeaderOffset) || entry.localHeaderOffset < 0) {
      return { ok: false, reason: 'no local header offset', bytesCharged: 0, requestsCharged: 0 };
    }
    const nameLen = Buffer.byteLength(entry.name, 'utf8');
    const slack = 512;
    const fetchLen = Math.min(
      LOCAL_HEADER_SIZE + nameLen + slack + entry.compressedSize,
      MAX_MANIFEST_BYTES,
    );
    const got = await fetcher.fetchRange(
      apkUrl,
      entry.localHeaderOffset,
      entry.localHeaderOffset + fetchLen - 1,
    );
    charged = got.bytesCharged ?? 0;
    chargedRequests = got.requestsCharged ?? 1;
    const head = got.buffer;
    if (head.length < LOCAL_HEADER_SIZE || head.readUInt32LE(0) !== SIG_LOCAL) {
      return { ok: false, reason: 'local header signature mismatch', bytesCharged: charged };
    }
    const localNameLen = head.readUInt16LE(26);
    const extraLen = head.readUInt16LE(28);
    const method = head.readUInt16LE(8);
    const dataStart = LOCAL_HEADER_SIZE + localNameLen + extraLen;
    if (dataStart + entry.compressedSize > head.length) {
      return {
        ok: false,
        reason: 'manifest payload not in fetched range',
        bytesCharged: charged,
      };
    }
    const payload = head.subarray(dataStart, dataStart + entry.compressedSize);
    let xml;
    if (method === METHOD_STORED) xml = Buffer.from(payload);
    else if (method === METHOD_DEFLATED) xml = inflateRawSync(payload, { maxOutputLength: MAX_MANIFEST_BYTES });
    else {
      return {
        ok: false,
        reason: `unsupported compression method ${method}`,
        bytesCharged: charged,
      };
    }
    return {
      ok: true,
      ...parseUsesSdk(xml),
      bytesCharged: charged,
      requestsCharged: chargedRequests,
    };
  } catch (err) {
    return {
      ok: false,
      reason: String(err?.message ?? err),
      bytesCharged: charged,
      requestsCharged: chargedRequests,
    };
  }
}

/* ------------------------------------------------------------ classify --- */

async function readCentralDirectory(fetcher, url, fileSize, { tailBytes = TAIL_BYTES } = {}) {
  const want = fileSize === null ? tailBytes : Math.min(tailBytes, fileSize);
  const tail = await fetcher.fetchTail(url, want);
  const absoluteSize = fileSize ?? tail.totalSize ?? tail.end + 1;
  const attempt = parseTailIfComplete({ buffer: tail.buffer, start: tail.start });
  if (attempt.complete) {
    const cdBuffer = tail.buffer.subarray(attempt.cdStartInBuf, attempt.cdEndInBuf);
    return {
      entries: attempt.entries,
      eocd: attempt.eocd,
      cdBuffer,
      fetches: 1,
      size: absoluteSize,
      bytesCharged: tail.bytesCharged ?? tail.buffer.length,
      requestsCharged: tail.requestsCharged ?? 1,
    };
  }
  if (attempt.eocd.cdSize > 64 * 1024 * 1024) {
    throw new Error(`central directory implausibly large: ${attempt.eocd.cdSize} bytes`);
  }
  const cd = await fetcher.fetchRange(url, attempt.eocd.cdOffset, attempt.eocd.cdOffset + attempt.eocd.cdSize - 1);
  const entries = parseCentralDirectory(cd.buffer, {
    offset: 0,
    expectedCount: attempt.eocd.entryCount,
    baseOffset: attempt.eocd.cdOffset,
  });
  return {
    entries,
    eocd: attempt.eocd,
    cdBuffer: cd.buffer,
    fetches: 2,
    size: absoluteSize,
    bytesCharged: (tail.bytesCharged ?? 0) + (cd.bytesCharged ?? 0),
    requestsCharged: (tail.requestsCharged ?? 1) + (cd.requestsCharged ?? 1),
  };
}

/**
 * Classify one APK from range reads only.
 *
 * @returns {object} one row of corpus/survey.jsonl
 */
export async function classifyApk(app, fetcher, opts = {}) {
  const { withManifest = true, tailBytes = TAIL_BYTES } = opts;
  const url = app.apkUrl;
  let rowBytes = 0;
  let rowRequests = 0;
  const row = {
    packageName: app.packageName,
    versionCode: app.versionCode,
    versionName: app.versionName,
    apkName: app.apkName,
    apkUrl: url,
    indexSha256: app.indexSha256 ?? null,
    indexSize: app.indexSize ?? null,
    indexMinSdk: app.indexMinSdk ?? null,
    indexTargetSdk: app.indexTargetSdk ?? null,
    indexDeclaredAbis: app.indexDeclaredAbis ?? [],
    ok: false,
    error: null,
  };

  try {
    const stat = await fetcher.stat(url);
    rowBytes += stat.bytesCharged ?? 0;
    rowRequests += stat.requestsCharged ?? 1;
    const size = stat.size ?? stat.totalSize ?? app.indexSize ?? null;
    const cdRead = await readCentralDirectory(fetcher, url, size, { tailBytes });
    const { entries, eocd, cdBuffer, fetches, size: resolvedSize } = cdRead;
    rowBytes += cdRead.bytesCharged;
    rowRequests += cdRead.requestsCharged;
    const summary = summariseEntries(entries);
    const cdBytes = cdRead.bytesCharged;

    Object.assign(row, {
      ok: true,
      apkBytes: resolvedSize,
      serverAcceptsRanges: stat.acceptsRanges ?? null,
      entryCount: entries.length,
      eocdEntryCount: eocd.entryCount,
      zip64: eocd.zip64,
      zipCommentBytes: eocd.commentLength,
      centralDirectoryOffset: eocd.cdOffset,
      centralDirectorySize: eocd.cdSize,
      centralDirectorySha256: sha256(cdBuffer),
      cdBytesFetched: cdBytes,
      tailFetches: fetches,
      hasNativeCode: summary.hasNativeCode,
      nativeAbiCounts: summary.nativeAbiCounts,
      nativeLibraryCount: summary.nativeLibraryCount,
      straySharedObjects: summary.straySharedObjects,
      dexCount: summary.dexCount,
      dexBytes: summary.dexBytes,
      dexUncompressedBytes: summary.dexUncompressedBytes,
      dexNames: summary.dexNames,
      otherDexCount: summary.otherDexCount,
      resourcesArsc: summary.resourcesArsc,
      hasManifest: summary.hasManifest,
      minSdk: null,
      targetSdk: null,
      manifestStatus: 'skipped',
    });

    if (withManifest && summary.manifest) {
      const sdk = await readUsesSdk(fetcher, url, summary.manifest);
      rowBytes += sdk.bytesCharged ?? 0;
      rowRequests += sdk.requestsCharged ?? 0;
      row.manifestStatus = sdk.ok ? 'ok' : `error: ${sdk.reason}`;
      row.minSdk = sdk.ok ? sdk.minSdkVersion : null;
      row.targetSdk = sdk.ok ? sdk.targetSdkVersion : null;
    } else if (withManifest && !summary.manifest) {
      row.manifestStatus = 'error: no AndroidManifest.xml entry';
    }
    row.bytesFetched = rowBytes;
    row.requests = rowRequests;
  } catch (err) {
    row.error = String(err?.message ?? err);
    row.bytesFetched = rowBytes;
    row.requests = rowRequests;
  }
  return row;
}

export { readCentralDirectory, summariseEntries };
