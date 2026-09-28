// Parser for Android ART method traces (`am profile start --sampling` output).
//
// File layout, recovered empirically and cross-checked in arttrace.test.mjs:
//
//   *version\n3\n<key>=<value>\n...        header key=value pairs
//   *threads\n<TID>\t<name>\n...           tid -> thread name
//   *methods\n<hexid>\t<class>\t<name>\t<sig>\t<file>\n...   method table
//   *end\n                                 end of sections
//   <binary>                               14-byte records
//
// The binary section is `TraceBuffer`'s serialised form, magic "SLOW"
// (0x574f4c53) in 14-byte records:
//
//   offset 0  u16  method id with two flag bits in the low positions
//   offset 2  u16  always 0
//   offset 4  u32  thread-local time, us
//   offset 8  u32  global time, us
//   offset 12 u16  tid
//
// Records are the *whole stack*, outermost first, and a single sample is a
// maximal run of records sharing (global time, tid). ART's header field
// `num-method-calls` counts records (stack entries), not samples.
//
// The first two records after `*end` are a fixed 14-byte preamble
// (serialisation version + start timestamp) and are not samples.

import { readFileSync } from 'node:fs';

const SECTION_END = '*end\n';
const REC = 14;

function sections(buf) {
  const threadsAt = buf.indexOf('*threads\n');
  const methodsAt = buf.indexOf('*methods\n');
  const endAt = buf.indexOf(SECTION_END);
  if (threadsAt < 0 || methodsAt < 0 || endAt < 0) {
    throw new Error('not an ART trace: missing *threads/*methods/*end');
  }
  return { threadsAt, methodsAt, endAt };
}

function parseHeader(buf) {
  const { threadsAt } = sections(buf);
  const head = buf.subarray(0, threadsAt).toString('latin1');
  const kv = {};
  for (const line of head.split('\n')) {
    const i = line.indexOf('=');
    if (i > 0) kv[line.slice(0, i)] = line.slice(i + 1);
  }
  return kv;
}

function parseThreads(buf) {
  const { threadsAt, methodsAt } = sections(buf);
  const out = new Map();
  for (const line of buf
    .subarray(threadsAt + 9, methodsAt)
    .toString('latin1')
    .split('\n')) {
    if (!line) continue;
    const t = line.indexOf('\t');
    if (t < 0) continue;
    out.set(Number(line.slice(0, t)), line.slice(t + 1));
  }
  return out;
}

function parseMethods(buf) {
  const { methodsAt, endAt } = sections(buf);
  const rows = [];
  for (const line of buf
    .subarray(methodsAt + 9, endAt)
    .toString('latin1')
    .split('\n')) {
    if (!line) continue;
    const f = line.split('\t');
    rows.push({
      id: parseInt(f[0], 16),
      cls: f[1],
      name: f[2],
      sig: f[3],
      file: f[4],
    });
  }
  // The table is not written in id order, but ART allocates ids as 4*k so a
  // dense id space is the invariant to check. Assert rather than trust.
  const seen = new Set();
  for (const r of rows) {
    if (r.id % 4 !== 0) throw new Error(`method id ${r.id} is not a multiple of 4`);
    if (seen.has(r.id)) throw new Error(`duplicate method id ${r.id}`);
    seen.add(r.id);
  }
  return rows;
}

function parseRecords(buf) {
  const { endAt } = sections(buf);
  const data = buf.subarray(endAt + SECTION_END.length);
  if (data.length < 6 + REC) {
    return { records: [], preamble: null, tailBytes: 0 };
  }
  if (data.readUInt32LE(0) !== 0x574f4c53) {
    throw new Error(`bad magic 0x${data.readUInt32LE(0).toString(16)}, want SLOW`);
  }
  const preamble = {
    formatVersion: data.readUInt16LE(4),
    startTimeNs: data.readUInt32LE(6),
  };
  const body = data.subarray(6 + REC);
  const n = Math.floor(body.length / REC);
  const tailBytes = body.length - n * REC;
  const records = new Array(n);
  for (let i = 0; i < n; i++) {
    const o = i * REC;
    const tagged = body.readUInt16LE(o);
    const f2 = body.readUInt16LE(o + 2);
    const threadTimeUs = body.readUInt32LE(o + 4);
    records[i] = {
      methodId: tagged & 0xfffc,
      flags: tagged & 0x3,
      f2,
      threadTimeUs,
      globalTimeUs: body.readUInt32LE(o + 8),
      tid: body.readUInt16LE(o + 12),
    };
  }
  return { records, preamble, tailBytes };
}

// A sample = maximal run of records with equal (globalTimeUs, tid). Records
// within a sample are the stack, outermost first.
function groupSamples(records) {
  const samples = [];
  let cur = null;
  for (const r of records) {
    if (!cur || cur.timeUs !== r.globalTimeUs || cur.tid !== r.tid) {
      cur = { timeUs: r.globalTimeUs, tid: r.tid, stack: [] };
      samples.push(cur);
    }
    cur.stack.push(r.methodId);
  }
  return samples;
}

export function parseTrace(path) {
  const buf = readFileSync(path);
  const header = parseHeader(buf);
  const threads = parseThreads(buf);
  const methods = parseMethods(buf);
  const { records, preamble, tailBytes } = parseRecords(buf);
  const samples = groupSamples(records);

  // Per-method record counts, and the set actually observed in a sample.
  const counts = new Map();
  for (const r of records) counts.set(r.methodId, (counts.get(r.methodId) || 0) + 1);

  // Per-thread record counts and thread-local time span.
  const perThread = new Map();
  for (const s of samples) {
    let t = perThread.get(s.tid);
    if (!t) {
      t = { tid: s.tid, name: threads.get(s.tid) || `tid:${s.tid}`, samples: 0, records: 0, methods: new Set(), firstUs: s.timeUs, lastUs: s.timeUs };
      perThread.set(s.tid, t);
    }
    t.samples += 1;
    t.records += s.stack.length;
    if (s.timeUs < t.firstUs) t.firstUs = s.timeUs;
    if (s.timeUs > t.lastUs) t.lastUs = s.timeUs;
    for (const m of s.stack) t.methods.add(m);
  }

  const byId = new Map(methods.map((m) => [m.id, m]));
  for (const r of records) {
    if (!byId.has(r.methodId)) throw new Error(`record references unknown method id ${r.methodId}`);
  }
  const observed = new Set(counts.keys());
  const name = (id) => {
    const m = byId.get(id);
    return `${m.cls}.${m.name}${m.sig}`;
  };

  return {
    path,
    header,
    methods,
    threads,
    records,
    samples,
    preamble,
    tailBytes,
    counts,
    perThread,
    byId,
    // The method table is what ART registers on method *entry*; `observed` is
    // what a sample actually landed on. They are not the same set.
    tableRows: methods.length,
    observedRows: observed.size,
    tableOnlyIds: methods.map((m) => m.id).filter((id) => !observed.has(id)),
    elapsedUs: Number(header['elapsed-time-usec'] ?? 0),
    numMethodCalls: Number(header['num-method-calls'] ?? 0),
    traceStartUs: samples.length ? samples[0].timeUs : 0,
    traceEndUs: samples.length ? samples[samples.length - 1].timeUs : 0,
    name,
  };
}
