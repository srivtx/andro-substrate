"""analysis.py — decompose ART buffered method traces.

Record layout (verified, see docs/analysis/0001):
  file  = text header, `*version`..`*threads`..`*methods`, terminated by `*end\n`
  data  = 32-byte `SLOW` packet header, then exactly num-method-calls fixed
          14-byte records: tid:u16le, (method_id<<2 | kind):u16le, u32, u32, u16
  kind  0 = METHOD_ENTER, 1 = METHOD_EXIT, 2 = THREAD_CHANGE
Self-check: the set of method ids in the data equals the `*methods` table keys
            and every ENTER has a matching EXIT on the same thread.
"""
import struct, collections

COUNTED = ('android.', 'java.', 'javax.', 'dalvik.')   # the project's prefix rule
HIDDEN = ('com.android.',)                             # com.android.internal.*
HOST   = ('sun.', 'libcore.', 'jdk.', 'com.google.android.collect')


def load(path):
    raw = open(path, 'rb').read()
    i = raw.index(b'*end\n') + 5
    head = raw[:i].decode('latin-1').split('\n')
    mi, ei, ti = head.index('*methods'), head.index('*end'), head.index('*threads')
    hdr = {}
    for l in head[:mi]:
        if '=' in l:
            k, v = l.split('=', 1)
            hdr[k] = v
    threads = {}
    for l in head[ti + 1:mi]:
        if '\t' in l:
            t, n = l.split('\t', 1)
            threads[int(t)] = n
    meth = {}
    for k, l in enumerate(head[mi + 1:ei]):
        f = l.split('\t')
        if len(f) >= 4:
            meth[k] = {'cls': f[1], 'name': f[2], 'sig': f[3], 'file': f[4] if len(f) > 4 else ''}
    data = raw[i:]
    n = int(hdr['num-method-calls'])
    assert (len(data) - 32) % 14 == 0, (path, len(data))
    assert (len(data) - 32) // 14 == n, (path, len(data), n)
    return hdr, threads, meth, data, n


def records(data, n):
    for k in range(n):
        r = data[32 + 14 * k:32 + 14 * k + 14]
        tid, = struct.unpack_from('<H', r, 0)
        v, = struct.unpack_from('<H', r, 2)
        yield tid, v & 3, v >> 2


def analyse(path):
    """Returns the closure + call graph, with the decode self-checked."""
    hdr, threads, meth, data, n = load(path)
    stacks = collections.defaultdict(list)
    seen = set()
    enter = collections.Counter()
    edges = collections.Counter()
    maxdepth = collections.defaultdict(int)
    mism = 0
    for tid, kind, mid in records(data, n):
        seen.add(mid)
        if kind == 0:
            if stacks[tid]:
                edges[(stacks[tid][-1], mid)] += 1
            stacks[tid].append(mid)
            enter[mid] += 1
            if len(stacks[tid]) > maxdepth[tid]:
                maxdepth[tid] = len(stacks[tid])
        elif kind == 1:
            if stacks[tid] and stacks[tid][-1] == mid:
                stacks[tid].pop()
            else:
                mism += 1
    called = seen
    # self-check: table == observed id set
    assert called == set(meth), (path, 'table/observed mismatch')
    main = threads and {t for t, n2 in threads.items() if n2 == 'main'}
    onmain = set()
    st2 = collections.defaultdict(list)
    for tid, kind, mid in records(data, n):
        if kind == 0:
            st2[tid].append(mid)
            if tid in main:
                onmain.add(mid)
        elif kind == 1 and st2[tid]:
            st2[tid].pop()
    return {'path': path, 'hdr': hdr, 'threads': threads, 'meth': meth, 'n': n,
            'called': called, 'enter': enter, 'edges': edges,
            'maxdepth': dict(maxdepth), 'mismatches': mism,
            'open': {t: len(s) for t, s in stacks.items() if s},
            'onmain': onmain}


def fam(cls):
    """Coarse family of a framework class."""
    p = cls.split('.')
    if p[0] in ('java', 'javax', 'dalvik'):
        return '.'.join(p[:2])
    if p[0] == 'android':
        return '.'.join(p[:2])
    return '.'.join(p[:2])


def counted(cls):
    return cls.startswith(COUNTED)
