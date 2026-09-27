/**
 * Dependency-free HTTP range fetching with redirect handling, retry and
 * global byte accounting.
 *
 * Every byte that crosses the socket is counted in `fetcher.bytesFetched`,
 * including bytes discarded because the server ignored our Range header.
 * That total is a published result of the survey, so it is tracked here and
 * nowhere else, in one place, with no way to bypass it.
 */

const USER_AGENT =
  'andro-substrate-corpus-survey/0.1 (research; contact: srivtx@github)';

export class HttpError extends Error {
  constructor(message, { url, status, body } = {}) {
    super(message);
    this.name = 'HttpError';
    this.url = url;
    this.status = status;
    this.body = body;
  }
}

export class RangeNotSupportedError extends HttpError {
  constructor(url, message) {
    super(message, { url });
    this.name = 'RangeNotSupportedError';
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class RangeFetcher {
  /**
   * @param {object} [opts]
   * @param {number} [opts.maxRedirects=5]
   * @param {number} [opts.retries=4]
   * @param {number} [opts.retryBaseDelayMs=250]
   * @param {number} [opts.timeoutMs=30000]
   * @param {typeof fetch} [opts.fetchImpl]
   * @param {(event: object) => void} [opts.onEvent] audit sink
   */
  constructor(opts = {}) {
    this.maxRedirects = opts.maxRedirects ?? 5;
    this.retries = opts.retries ?? 4;
    this.retryBaseDelayMs = opts.retryBaseDelayMs ?? 250;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.fetchImpl = opts.fetchImpl ?? globalThis.fetch;
    this.onEvent = opts.onEvent ?? (() => {});

    this.bytesFetched = 0;
    this.requestCount = 0;
    this.redirectCount = 0;
    this.retryCount = 0;
    this.byHost = new Map();
  }

  account(url, n) {
    this.bytesFetched += n;
    let host;
    try {
      host = new URL(url).host;
    } catch {
      host = 'unknown';
    }
    this.byHost.set(host, (this.byHost.get(host) ?? 0) + n);
  }

  stats() {
    return {
      bytesFetched: this.bytesFetched,
      requestCount: this.requestCount,
      redirectCount: this.redirectCount,
      retryCount: this.retryCount,
      bytesByHost: Object.fromEntries([...this.byHost.entries()].sort()),
    };
  }

  async request(url, { method = 'GET', range, signal, meter } = {}) {
    const m = meter ?? { bytes: 0, requests: 0 };
    let currentUrl = url;
    for (let hop = 0; hop <= this.maxRedirects; hop++) {
      const headers = { 'user-agent': USER_AGENT, 'accept-encoding': 'identity' };
      if (range) headers.range = range;

      const res = await this.withRetry(
        () => {
          this.requestCount += 1;
          m.requests += 1;
          return this.fetchImpl(currentUrl, {
            method,
            headers,
            redirect: 'manual',
            signal,
          });
        },
        currentUrl,
        m,
      );

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        if (!location) {
          await this.readBody(currentUrl, res, m);
          throw new HttpError(`redirect ${res.status} without location`, {
            url: currentUrl,
            status: res.status,
          });
        }
        this.redirectCount += 1;
        const next = new URL(location, currentUrl).toString();
        this.onEvent({ type: 'redirect', from: currentUrl, to: next, status: res.status });
        currentUrl = next;
        continue;
      }

      return { res, finalUrl: currentUrl, meter: m };
    }
    throw new HttpError('too many redirects', { url });
  }

  async withRetry(fn, url, meter) {
    let lastError;
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      try {
        const res = await fn();
        if (res.status === 429 || res.status >= 500) {
          const body = await res.arrayBuffer();
          this.accountAndCharge(url, body.byteLength, meter);
          throw new HttpError(`retryable status ${res.status}`, {
            url,
            status: res.status,
          });
        }
        return res;
      } catch (err) {
        lastError = err;
        // Anything thrown by the fetch call itself is a connection-level
        // failure (reset, DNS, timeout) and is worth retrying. An
        // HttpError is only retried for 429 and 5xx; a 4xx is terminal.
        const retryable =
          !(err instanceof HttpError) ||
          err.status === 429 ||
          (err.status !== undefined && err.status >= 500);
        if (!retryable || attempt === this.retries) break;
        this.retryCount += 1;
        const delay = this.retryBaseDelayMs * 2 ** attempt;
        this.onEvent({ type: 'retry', url, attempt: attempt + 1, delay, reason: err.message });
        await sleep(delay);
      }
    }
    throw lastError;
  }

  accountAndCharge(url, n, meter) {
    this.account(url, n);
    if (meter) meter.bytes += n;
  }

  async readBody(url, res, meter) {
    const ab = await res.arrayBuffer();
    this.accountAndCharge(res.url || url, ab.byteLength, meter);
    return Buffer.from(ab);
  }

  /**
   * HEAD request used only to learn total size. Zero body bytes charged.
   * Falls back to a 1-byte range probe when HEAD is rejected.
   */
  async stat(url) {
    const meter = { bytes: 0, requests: 0 };
    try {
      const { res, finalUrl } = await this.request(url, { method: 'HEAD', meter });
      if (!res.ok) {
        await this.readBody(finalUrl, res, meter);
        throw new HttpError(`HEAD status ${res.status}`, { url, status: res.status });
      }
      const acceptRanges = (res.headers.get('accept-ranges') ?? '').toLowerCase();
      const len = res.headers.get('content-length');
      return {
        finalUrl,
        size: len === null ? null : Number(len),
        acceptsRanges: acceptRanges.includes('bytes'),
        contentType: res.headers.get('content-type'),
        bytesCharged: meter.bytes,
        requestsCharged: meter.requests,
      };
    } catch (err) {
      if (!(err instanceof HttpError) || err.status === undefined) throw err;
      const probe = await this.fetchRange(url, 0, 0);
      return {
        finalUrl: probe.finalUrl,
        size: probe.totalSize,
        acceptsRanges: true,
        contentType: probe.contentType,
        bytesCharged: meter.bytes + probe.bytesCharged,
        requestsCharged: meter.requests + probe.requestsCharged,
      };
    }
  }

  /**
   * Fetch the inclusive byte range [start, end]. When the server ignores
   * Range and replies 200 with the whole body, the requested slice is
   * returned but the FULL body is charged to the byte counter.
   *
   * @returns {Promise<{buffer: Buffer, start: number, end: number,
   *   totalSize: number|null, partial: boolean, status: number, finalUrl: string,
   *   contentType: string|null}>}
   */
  async fetchRange(url, start, end) {
    const range = `bytes=${start}-${end}`;
    const meter = { bytes: 0, requests: 0 };
    const { res, finalUrl } = await this.request(url, { range, meter });
    if (res.status !== 206 && res.status !== 200) {
      await this.readBody(finalUrl, res, meter);
      throw new HttpError(`range request status ${res.status}`, {
        url: finalUrl,
        status: res.status,
      });
    }

    const whole = await this.readBody(finalUrl, res, meter);
    const contentRange = res.headers.get('content-range');
    let totalSize = null;
    let actualStart = start;
    let partial = res.status === 206;

    if (contentRange) {
      const m = /bytes\s+(\d+)-(\d+)\/(\d+|\*)/i.exec(contentRange);
      if (m) {
        actualStart = Number(m[1]);
        if (m[3] !== '*') totalSize = Number(m[3]);
      }
    }

    if (partial) {
      if (whole.length !== end - start + 1) {
        if (actualStart + whole.length - 1 !== end) {
          throw new HttpError(
            `short range read: asked ${start}-${end}, got ${whole.length} bytes from ${actualStart}`,
            { url: finalUrl, status: res.status },
          );
        }
      }
      return {
        buffer: whole,
        start: actualStart,
        end: actualStart + whole.length - 1,
        totalSize,
        partial: true,
        status: res.status,
        finalUrl,
        contentType: res.headers.get('content-type'),
        bytesCharged: meter.bytes,
        requestsCharged: meter.requests,
      };
    }

    if (totalSize === null) {
      const len = res.headers.get('content-length');
      if (len !== null) totalSize = Number(len);
    }
    if (whole.length <= end) {
      throw new RangeNotSupportedError(
        finalUrl,
        `server ignored Range and returned ${whole.length} bytes, need offset ${start}`,
      );
    }
    return {
      buffer: whole.subarray(start, end + 1),
      start,
      end,
      totalSize,
      partial: false,
      status: res.status,
      finalUrl,
      contentType: res.headers.get('content-type'),
      bytesCharged: meter.bytes,
      requestsCharged: meter.requests,
    };
  }

  /**
   * Fetch the last `n` bytes of a resource. `Range: bytes=-n` lets the
   * server do the work. Returns a buffer whose `start` is the absolute file
   * offset of byte 0 in the buffer, which is not `size - n` when the resource
   * is shorter than `n`.
   */
  async fetchTail(url, n) {
    const range = `bytes=-${n}`;
    const meter = { bytes: 0, requests: 0 };
    const { res, finalUrl } = await this.request(url, { range, meter });
    if (res.status !== 206 && res.status !== 200) {
      await this.readBody(finalUrl, res, meter);
      throw new HttpError(`tail request status ${res.status}`, {
        url: finalUrl,
        status: res.status,
      });
    }
    const whole = await this.readBody(finalUrl, res, meter);
    const contentRange = res.headers.get('content-range');
    let totalSize = null;
    let start = null;
    if (contentRange) {
      const m = /bytes\s+(\d+)-(\d+)\/(\d+|\*)/i.exec(contentRange);
      if (m) {
        start = Number(m[1]);
        if (m[3] !== '*') totalSize = Number(m[3]);
      }
    }
    if (start === null) {
      if (res.status !== 206) {
        throw new RangeNotSupportedError(finalUrl, 'server ignored suffix Range header');
      }
      start = (totalSize ?? whole.length) - whole.length;
    }
    return {
      buffer: whole,
      start,
      end: start + whole.length - 1,
      totalSize,
      status: res.status,
      finalUrl,
      contentType: res.headers.get('content-type'),
      bytesCharged: meter.bytes,
      requestsCharged: meter.requests,
    };
  }
}

/**
 * Minimal ZIP writer used by the tests to build synthetic archives with
 * exact control over the central directory, ZIP64 markers and truncation.
 * Writes only what the reader under test consumes: local headers, data,
 * central directory, EOCD. No data descriptors.
 */
export function buildZip(entries, opts = {}) {
  const { zip64 = false, comment = Buffer.alloc(0), corruptCdOffset = null } = opts;
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.name, 'utf8');
    const data = entry.data ?? Buffer.alloc(0);
    const method = entry.method ?? 0;
    const flags = entry.flags ?? 0;
    const crc = entry.crc ?? 0x12345678;
    const compressedSize = entry.compressedSize ?? data.length;
    const uncompressedSize = entry.uncompressedSize ?? data.length;

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressedSize & 0xffffffff, 18);
    local.writeUInt32LE(uncompressedSize & 0xffffffff, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    name.copy(local, 30);

    let localExtra = Buffer.alloc(0);
    if (zip64) {
      localExtra = Buffer.alloc(20);
      localExtra.writeUInt16LE(0x0001, 0);
      localExtra.writeUInt16LE(16, 2);
      localExtra.writeBigUInt64LE(BigInt(uncompressedSize), 4);
      localExtra.writeBigUInt64LE(BigInt(compressedSize), 12);
      local.writeUInt16LE(localExtra.length, 28);
    }
    locals.push(local, localExtra, data);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressedSize & 0xffffffff, 20);
    central.writeUInt32LE(uncompressedSize & 0xffffffff, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(entry.externalAttrs ?? 0, 38);
    central.writeUInt32LE(offset & 0xffffffff, 42);
    name.copy(central, 46);

    let centralExtra = Buffer.alloc(0);
    if (zip64) {
      centralExtra = Buffer.alloc(4 + 8 + 8 + 8);
      centralExtra.writeUInt16LE(0x0001, 0);
      centralExtra.writeUInt16LE(centralExtra.length - 4, 2);
      centralExtra.writeBigUInt64LE(BigInt(uncompressedSize), 4);
      centralExtra.writeBigUInt64LE(BigInt(compressedSize), 12);
      centralExtra.writeBigUInt64LE(BigInt(offset), 20);
      central.writeUInt16LE(centralExtra.length, 30);
    }
    centrals.push(central, centralExtra);

    offset += 30 + name.length + localExtra.length + data.length;
  }

  const cd = Buffer.concat(centrals);
  const eocdOffset = offset;
  let eocd = Buffer.alloc(22 + comment.length);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(zip64 ? 45 : 0, 4);
  eocd.writeUInt16LE(zip64 ? 45 : 20, 6);
  eocd.writeUInt16LE(entries.length & 0xffff, 8);
  eocd.writeUInt16LE(entries.length & 0xffff, 10);
  eocd.writeUInt32LE(cd.length, 12);
  const declaredCdOffset = corruptCdOffset ?? offset;
  eocd.writeUInt32LE(declaredCdOffset >>> 0, 16);
  eocd.writeUInt16LE(comment.length, 20);
  comment.copy(eocd, 22);

  const parts = [...locals, cd, eocd];
  if (zip64) {
    const z64 = Buffer.alloc(56);
    z64.writeUInt32LE(0x06064b50, 0);
    z64.writeBigUInt64LE(44n, 4);
    z64.writeUInt16LE(45, 12);
    z64.writeUInt16LE(45, 14);
    z64.writeUInt32LE(0, 16);
    z64.writeUInt32LE(0, 20);
    z64.writeBigUInt64LE(BigInt(entries.length), 24);
    z64.writeBigUInt64LE(BigInt(entries.length), 32);
    z64.writeBigUInt64LE(BigInt(cd.length), 40);
    z64.writeBigUInt64LE(BigInt(declaredCdOffset), 48);
    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(0x07064b50, 0);
    locator.writeUInt32LE(0, 4);
    locator.writeBigUInt64LE(BigInt(offset + cd.length), 8);
    locator.writeUInt32LE(1, 16);
    return { buffer: Buffer.concat([...parts.slice(0, -1), z64, locator, eocd]), eocdOffset, cdOffset: offset, cdSize: cd.length };
  }
  return { buffer: Buffer.concat(parts), eocdOffset, cdOffset: offset, cdSize: cd.length };
}
