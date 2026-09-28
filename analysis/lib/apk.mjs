/**
 * Read-only APK inspection for candidate selection.
 *
 * Everything here answers a question that the corpus census could not, because
 * the census had only the ZIP central directory and a 128 KiB tail:
 *
 * 1. does the archive contain a shared object **anywhere**, not just under
 *    `lib/<abi>/` (`corpus/survey.jsonl` has `straySharedObjects` for the
 *    `.so`-named cases, and one row in the corpus, `org.bitbucket.watashi564.combapp`,
 *    is a DEX-only app that ships two);
 * 2. does any entry *begin* with the ELF magic, whatever it is called;
 * 3. what does the manifest actually declare — components, launchers,
 *    permissions;
 * 4. is there a `res/layout/` at all, and does the DEX call `setContentView`
 *    or `LayoutInflater.inflate`.
 *
 * The ZIP reading is delegated to `tools/corpus/zip-central-directory.mjs`
 * (imported, not copied) so the entry inventory cannot disagree with the
 * census's; the DEFLATE implementation is `node:zlib`. Nothing here writes.
 */

import * as zlib from 'node:zlib';
import {
  findEocdOffset,
  parseCentralDirectory,
  parseEocd,
} from '../../tools/corpus/zip-central-directory.mjs';
import { parseAxml, summariseManifest } from './axml.mjs';

const SIG_LOCAL = 0x04034b50;
const METHOD_STORED = 0;
const METHOD_DEFLATED = 8;
/** Refuse to inflate anything larger than this; the manifest is far smaller. */
const MAX_INFLATE_BYTES = 8 * 1024 * 1024;
const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);

/**
 * Inventory every entry, and read one of them if asked.
 *
 * @param {Buffer} buf the whole APK
 * @returns {{entries: Array<object>, totalBytes: number, zip64: boolean}}
 */
export function readApk(buf) {
  const eocd = parseEocd(buf, 0);
  const entries = parseCentralDirectory(buf, {
    offset: eocd.cdOffset,
    expectedCount: eocd.entryCount,
  });
  return { entries, totalBytes: buf.length, zip64: eocd.zip64 === true, eocd };
}

/**
 * Read one stored/deflated entry's bytes by its local header offset.
 *
 * The local header's own name/extra lengths are used, not the central
 * directory's: a writer that pads one and not the other would otherwise shift
 * the payload, and the failure would look like a corrupt archive rather than a
 * bug.
 */
export function readEntry(buf, entry) {
  if (entry.isDirectory) return Buffer.alloc(0);
  if (entry.compressedSize > MAX_INFLATE_BYTES) {
    throw new Error(`entry ${entry.name} is ${entry.compressedSize} bytes, over the inflate cap`);
  }
  const lh = entry.localHeaderOffset;
  if (buf.readUInt32LE(lh) !== SIG_LOCAL) {
    throw new Error(`entry ${entry.name}: local header signature mismatch`);
  }
  const nameLen = buf.readUInt16LE(lh + 26);
  const extraLen = buf.readUInt16LE(lh + 28);
  const start = lh + 30 + nameLen + extraLen;
  const raw = buf.subarray(start, start + entry.compressedSize);
  if (entry.method === METHOD_STORED) return Buffer.from(raw);
  if (entry.method === METHOD_DEFLATED) return zlib.inflateRawSync(raw);
  throw new Error(`entry ${entry.name}: unsupported compression method ${entry.method}`);
}

/** Every entry name that is a shared object, wherever it sits. */
export function sharedObjectEntries(entries) {
  return entries.filter((e) => !e.isDirectory && /\.so$/.test(e.name)).map((e) => e.name);
}

/** Every entry under `lib/<abi>/`, matching the census's definition A. */
export function libEntries(entries) {
  return entries.filter((e) => /^lib\/[^/]+\//.test(e.name)).map((e) => e.name);
}

/**
 * Entries whose decompressed bytes *begin* with the ELF magic, at any path and
 * under any name.
 *
 * This is the check `lib/<abi>/*.so` cannot make, and it is not redundant with
 * the `.so`-extension check: in the corpus, `sh.haven.app` ships
 * `assets/haven-usb/arm64-v8a/haven-usb-probe` and `se.leap.riseupvpn` ships
 * `assets/pie_openvpn.arm64-v8a`, neither of which ends in `.so`, and
 * `corpus/survey.jsonl`'s `straySharedObjects` — which is extension-based —
 * lists neither.
 *
 * **Bounded, and the bound is reported.** Each deflated entry is inflated only
 * far enough to produce 4 KiB of output, from at most `inputWindow` compressed
 * bytes. The first implementation instead skipped deflated entries whose
 * *compressed* size exceeded 1 MiB, which silently missed
 * `org.bitbucket.watashi564.combapp`'s two payloads — a 7.3 MB and a 17.8 MB ELF
 * named `res/5x.so` and `res/yG.so`. The extension check still caught them, so
 * no verdict changed, but a content check weaker than the name check is a trap
 * for the next reader. A failed inflate is *counted* in `skipped`, never
 * treated as "not ELF".
 */
export function sniffElf(buf, entries, { maxEntries = 8192, inputWindow = 4096 } = {}) {
  const found = [];
  let scanned = 0;
  let skipped = 0;
  let budgetExhausted = false;

  for (const e of entries) {
    if (e.isDirectory) continue;
    if (e.uncompressedSize < 4) continue;
    if (scanned >= maxEntries) {
      budgetExhausted = true;
      break;
    }
    scanned++;
    let head = null;
    try {
      const lh = e.localHeaderOffset;
      const nameLen = buf.readUInt16LE(lh + 26);
      const extraLen = buf.readUInt16LE(lh + 28);
      const start = lh + 30 + nameLen + extraLen;
      if (e.method === METHOD_STORED) {
        head = buf.subarray(start, start + 4);
      } else if (e.method === METHOD_DEFLATED) {
        head = deflatedHead(buf.subarray(start, start + Math.min(inputWindow, e.compressedSize)));
      } else {
        skipped++;
        continue;
      }
    } catch {
      skipped++;
      continue;
    }
    if (head && head.length >= 4 && head.equals(ELF_MAGIC)) found.push(e.name);
  }

  return { found: found.sort(), scanned, skipped, budgetExhausted };
}

/**
 * The first bytes of a raw DEFLATE stream, without inflating the whole thing.
 *
 * `maxOutputLength` is what bounds the materialised output, and it has a sharp
 * edge worth writing down: node compares it against the **input** chunk length
 * and throws `ERR_BUFFER_TOO_LARGE` when the input exceeds it, so it must be
 * set above `inputWindow`. It is not the cap on how much of the archive is
 * read — `inputWindow` is — only on how much output is held in memory.
 */
function deflatedHead(raw) {
  return zlib.inflateRawSync(raw, {
    finishFlush: zlib.constants.Z_SYNC_FLUSH,
    maxOutputLength: 64 * 1024,
  }).subarray(0, 4);
}

/**
 * Parse `AndroidManifest.xml` out of an APK.
 *
 * @returns {{summary: object, elements: Array<object>}|null} `null` when the
 *   archive has no manifest entry, which is a real state and not an error.
 */
export function readManifest(buf, entries) {
  const e = entries.find((x) => x.name === 'AndroidManifest.xml');
  if (!e) return null;
  const doc = parseAxml(readEntry(buf, e));
  return { summary: summariseManifest(doc), elements: doc.elements, stringPoolSize: doc.stringPoolSize };
}

/** `res/layout/*.xml` inventory. Directory prefixes vary by build, so match loosely. */
export function layoutEntries(entries) {
  return entries.filter((e) => !e.isDirectory && /^res\/[^\/]*layout[^\/]*\/.*\.xml$/.test(e.name)).map((e) => e.name);
}

/** Every `classes*.dex` entry, sorted. */
export function dexEntries(entries) {
  return entries
    .filter((e) => !e.isDirectory && /(^|\/)classes(\d*)\.dex$/.test(e.name))
    .map((e) => e.name)
    .sort();
}
