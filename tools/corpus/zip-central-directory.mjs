/**
 * Dependency-free ZIP central directory parser.
 *
 * Reads the End Of Central Directory record, the ZIP64 End Of Central
 * Directory record and the central directory file headers, from a byte
 * range that was fetched over HTTP. Nothing is read from the filesystem
 * except by the caller, and no entry payload is ever decompressed here.
 *
 * Layout offsets follow APPNOTE.TXT 6.3.16 and 4.4.16.
 */

export const SIG_EOCD = 0x06054b50;
export const SIG_CENTRAL = 0x02014b50;
export const SIG_EOCD64 = 0x06064b50;
export const SIG_EOCD64_LOCATOR = 0x07064b50;
export const SIG_LOCAL = 0x04034b50;

const EOCD_MIN_SIZE = 22;
const CENTRAL_FIXED_SIZE = 46;
const ZIP64_EXTRA_ID = 0x0001;
const MAX_COMMENT = 0xffff;
const UTF8_FLAG = 0x0800;

export class ZipFormatError extends Error {
  constructor(message, detail = {}) {
    super(message);
    this.name = 'ZipFormatError';
    Object.assign(this, detail);
  }
}

const cp437 = new TextDecoder('ibm866');
const utf8 = new TextDecoder('utf-8', { fatal: false });

function decodeName(bytes, flags) {
  if (bytes.length === 0) return '';
  if (flags & UTF8_FLAG) return utf8.decode(bytes);
  if (bytes.every((b) => b < 0x80)) return utf8.decode(bytes);
  return cp437.decode(bytes);
}

/**
 * Locate the EOCD by scanning backwards. The record is the last thing in the
 * file, so the scan window is bounded by the maximum comment length.
 *
 * @param {Buffer} buf tail of the archive
 * @returns {number} absolute-in-buffer offset of the EOCD signature
 */
export function findEocdOffset(buf) {
  const minSize = Math.max(EOCD_MIN_SIZE, buf.length);
  if (buf.length < EOCD_MIN_SIZE) {
    throw new ZipFormatError('buffer too small to contain an EOCD record', {
      bufferLength: buf.length,
      required: EOCD_MIN_SIZE,
    });
  }
  const lowest = Math.max(0, buf.length - minSize);
  for (let i = buf.length - EOCD_MIN_SIZE; i >= lowest; i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) {
      const commentLength = buf.readUInt16LE(i + 20);
      if (i + EOCD_MIN_SIZE + commentLength === buf.length) return i;
    }
  }
  throw new ZipFormatError('no End Of Central Directory record found', {
    bufferLength: buf.length,
    searchedFrom: buf.length - EOCD_MIN_SIZE,
    searchedTo: lowest,
  });
}

/**
 * Parse the EOCD (and ZIP64 EOCD when present) into a directory descriptor.
 * `baseOffset` is the absolute file offset of byte 0 of `buf`, so all
 * reported offsets are absolute within the whole archive.
 */
export function parseEocd(buf, baseOffset = 0) {
  const eocdOffset = findEocdOffset(buf);
  const commentLength = buf.readUInt16LE(eocdOffset + 20);

  let entryCount = buf.readUInt16LE(eocdOffset + 10);
  let cdSize = buf.readUInt32LE(eocdOffset + 12);
  let cdOffset = buf.readUInt32LE(eocdOffset + 16);
  let zip64 = false;

  const locatorAt = eocdOffset - 20;
  if (locatorAt >= 0 && buf.readUInt32LE(locatorAt) === SIG_EOCD64_LOCATOR) {
    const z64Offset = Number(buf.readBigUInt64LE(locatorAt + 8));
    const z64InBuf = z64Offset - baseOffset;
    if (z64InBuf < 0 || z64InBuf + 56 > buf.length) {
      throw new ZipFormatError('ZIP64 EOCD record lies outside the supplied byte range', {
        zip64EocdOffset: z64Offset,
        baseOffset,
        bufferLength: buf.length,
      });
    }
    if (buf.readUInt32LE(z64InBuf) !== SIG_EOCD64) {
      throw new ZipFormatError('ZIP64 EOCD locator points at a non-ZIP64-EOCD record', {
        zip64EocdOffset: z64Offset,
      });
    }
    entryCount = Number(buf.readBigUInt64LE(z64InBuf + 32));
    cdSize = Number(buf.readBigUInt64LE(z64InBuf + 40));
    cdOffset = Number(buf.readBigUInt64LE(z64InBuf + 48));
    zip64 = true;
  }

  if (cdOffset === 0xffffffff || cdSize === 0xffffffff || entryCount === 0xffff) {
    throw new ZipFormatError('ZIP64 sentinel in EOCD but no ZIP64 EOCD record present', {
      cdOffset,
      cdSize,
      entryCount,
    });
  }

  return {
    zip64,
    entryCount,
    cdSize,
    cdOffset,
    commentLength,
    eocdOffset: eocdOffset + baseOffset,
    comment: buf.subarray(eocdOffset + EOCD_MIN_SIZE, eocdOffset + EOCD_MIN_SIZE + commentLength),
  };
}

function readZip64Extra(extra, { uncompressedSize, compressedSize, localHeaderOffset }) {
  let pos = 0;
  while (pos + 4 <= extra.length) {
    const id = extra.readUInt16LE(pos);
    const size = extra.readUInt16LE(pos + 2);
    const body = extra.subarray(pos + 4, pos + 4 + size);
    if (id === ZIP64_EXTRA_ID) {
      let o = 0;
      const take64 = (current) => {
        if (current !== 0xffffffff) return current;
        if (o + 8 > body.length) {
          throw new ZipFormatError('truncated ZIP64 extended information field', {
            extraFieldSize: body.length,
          });
        }
        const v = Number(body.readBigUInt64LE(o));
        o += 8;
        return v;
      };
      return {
        uncompressedSize: take64(uncompressedSize),
        compressedSize: take64(compressedSize),
        localHeaderOffset: take64(localHeaderOffset),
      };
    }
    pos += 4 + size;
  }
  return {
    uncompressedSize,
    compressedSize,
    localHeaderOffset,
  };
}

/**
 * Parse central directory file headers.
 *
 * @param {Buffer} buf the central directory bytes (or a superset of them)
 * @param {object} [opts]
 * @param {number} [opts.offset=0] offset of the CD inside `buf`
 * @param {number|null} [opts.expectedCount] from the EOCD; when given, the
 *   parse stops there and a mismatch is an error
 * @param {number} [opts.baseOffset=0] absolute offset of `buf` byte 0
 * @returns {Array<object>} entry records in central directory order
 */
export function parseCentralDirectory(buf, opts = {}) {
  const { offset = 0, expectedCount = null, baseOffset = 0 } = opts;
  if (!Buffer.isBuffer(buf)) throw new ZipFormatError('parseCentralDirectory expects a Buffer');
  if (offset < 0 || offset >= buf.length) {
    throw new ZipFormatError('central directory offset lies outside the buffer', {
      offset,
      bufferLength: buf.length,
    });
  }

  const entries = [];
  let pos = offset;

  while (pos + CENTRAL_FIXED_SIZE <= buf.length) {
    if (expectedCount !== null && entries.length === expectedCount) break;

    if (buf.readUInt32LE(pos) !== SIG_CENTRAL) {
      if (expectedCount !== null && entries.length < expectedCount) {
        throw new ZipFormatError('central directory signature mismatch before entry count reached', {
          expectedCount,
          parsed: entries.length,
          offset: pos,
          bytes: buf.subarray(pos, pos + 4).toString('hex'),
        });
      }
      throw new ZipFormatError('central directory signature mismatch', {
        offset: pos,
        parsed: entries.length,
        expectedCount,
        bytes: buf.subarray(pos, pos + 4).toString('hex'),
      });
    }

    const flags = buf.readUInt16LE(pos + 8);
    const method = buf.readUInt16LE(pos + 10);
    const crc32 = buf.readUInt32LE(pos + 16);
    const rawCompressedSize = buf.readUInt32LE(pos + 20);
    const rawUncompressedSize = buf.readUInt32LE(pos + 24);
    const nameLength = buf.readUInt16LE(pos + 28);
    const extraLength = buf.readUInt16LE(pos + 30);
    const commentLength = buf.readUInt16LE(pos + 32);
    const diskStart = buf.readUInt16LE(pos + 34);
    const internalAttrs = buf.readUInt16LE(pos + 36);
    const externalAttrs = buf.readUInt32LE(pos + 38);
    const rawLocalOffset = buf.readUInt32LE(pos + 42);

    const headerEnd = pos + CENTRAL_FIXED_SIZE;
    if (headerEnd + nameLength + extraLength + commentLength > buf.length) {
      throw new ZipFormatError('central directory entry truncated', {
        offset: pos,
        nameLength,
        extraLength,
        commentLength,
        bufferLength: buf.length,
      });
    }

    const nameBytes = buf.subarray(pos + CENTRAL_FIXED_SIZE, pos + CENTRAL_FIXED_SIZE + nameLength);
    const extra = buf.subarray(
      pos + CENTRAL_FIXED_SIZE + nameLength,
      pos + CENTRAL_FIXED_SIZE + nameLength + extraLength,
    );

    const sizes = readZip64Extra(extra, {
      uncompressedSize: rawUncompressedSize,
      compressedSize: rawCompressedSize,
      localHeaderOffset: rawLocalOffset,
    });

    const name = decodeName(nameBytes, flags);
    entries.push({
      name,
      nameBytes,
      method,
      flags,
      crc32,
      compressedSize: sizes.compressedSize,
      uncompressedSize: sizes.uncompressedSize,
      localHeaderOffset: sizes.localHeaderOffset,
      extraLength,
      commentLength,
      diskStart,
      internalAttrs,
      externalAttrs,
      isDirectory: name.endsWith('/') || (externalAttrs & 0x10) !== 0,
      absoluteOffset: pos + baseOffset,
    });

    pos = headerEnd + nameLength + extraLength + commentLength;
  }

  if (expectedCount !== null && entries.length !== expectedCount) {
    throw new ZipFormatError('central directory ended before the EOCD entry count', {
      expectedCount,
      parsed: entries.length,
      bufferLength: buf.length,
    });
  }
  if (entries.length === 0) {
    throw new ZipFormatError('central directory contained no entries', { bufferLength: buf.length });
  }
  return entries;
}

/**
 * Convenience wrapper for the survey: given a tail buffer that is known to
 * contain the EOCD, parse the directory descriptor and return the entries
 * *if* the CD happened to be inside the same tail. Callers use
 * `describeTail` to decide whether a second range request is needed.
 */
export function parseTailIfComplete(tail) {
  const baseOffset = tail.start;
  const eocd = parseEocd(tail.buffer, baseOffset);
  const cdStartInBuf = eocd.cdOffset - baseOffset;
  const cdEndInBuf = cdStartInBuf + eocd.cdSize;
  const complete =
    cdStartInBuf >= 0 && cdEndInBuf <= tail.buffer.length;
  if (!complete) {
    return { eocd, entries: null, cdStartInBuf, cdEndInBuf, complete: false };
  }
  const entries = parseCentralDirectory(tail.buffer, {
    offset: cdStartInBuf,
    expectedCount: eocd.entryCount,
    baseOffset,
  });
  return { eocd, entries, cdStartInBuf, cdEndInBuf, complete: true };
}
