#!/usr/bin/env python3
"""measure.py — joint static/dynamic table for the 24 traced APKs.

Static side comes from analysis/candidates/measured.jsonl (committed).
Dynamic side is measured here from ART buffered method traces.
Emits docs/analysis/measurement.json — the only file the document reads.
"""
import json, os, glob, collections, hashlib, sys, importlib.util as _il

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = _il.spec_from_file_location("arttrace", os.path.join(_HERE, "art-trace.py"))
A = _il.module_from_spec(_spec)
_spec.loader.exec_module(A)

# repo root: closure-frame/ -> analysis/ -> docs/ -> <root>
REPO = os.path.abspath(os.path.join(_HERE, '..', '..', '..'))
# Traces are not committed. Point A14_TRACE_DIR at a directory holding them.
TRACES = os.environ.get('A14_TRACE_DIR', _HERE)

# package -> local trace prefix for the four project candidates
NAMED = {
    'eu.quelltext.gita': 'gita',
    'com.jeffliu.balancetheball': 'balancetheball',
    'org.debian.eugen.headingcalculator': 'headingcalculator',
    'tk.al54.dev.badpixels': 'badpixels',
}

FW = A.COUNTED
WIDGET_ADAPTER = ('android.widget.Adapter', 'android.widget.AbsListView',
                  'android.widget.ListView', 'android.widget.AdapterView',
                  'android.widget.AbsAdapter', 'android.widget.BaseAdapter',
                  'android.widget.ArrayAdapter', 'android.widget.ListAdapter',
                  'android.widget.AbsSpinner', 'android.widget.ExpandableListView',
                  'android.widget.SimpleAdapter', 'android.widget.HeaderViewListAdapter')


def _selfcheck(path):
    """Per-thread enter/exit balance. Returns the decode's own error budget."""
    _hdr, _th, _m, data, n = A.load(path)
    st = collections.defaultdict(list)
    exact = spec = nocall = 0
    for tid, kind, mid in A.records(data, n):
        if kind == 0:
            st[tid].append(mid)
        elif kind == 1:
            s = st[tid]
            if s and s[-1] == mid:
                s.pop(); exact += 1
            elif mid in s:
                while s and s[-1] != mid:
                    s.pop(); spec += 1
                s.pop()
            else:
                nocall += 1
    return {'exactExits': exact, 'speculativePops': spec,
            'exitsWithNoFrame': nocall,
            'framesOpenAtCut': sum(len(x) for x in st.values())}


def is_adapter(cls):
    return any(cls == p or cls.startswith(p + '$') for p in WIDGET_ADAPTER)


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def main():
    static = {}
    for l in open(f'{REPO}/analysis/candidates/measured.jsonl'):
        r = json.loads(l)
        static[(r['packageName'], r['versionCode'])] = r

    sample = json.load(open(f'{_HERE}/sample20.json'))
    rows = []
    SETS = collections.defaultdict(list)
    sources = []   # (package, [trace files])
    for a in sample:
        sources.append((a['pkg'], sorted(glob.glob(f'{TRACES}/x{sample.index(a)}_r*.trace'))))
    for pkg, pref in NAMED.items():
        sources.append((pkg, sorted(glob.glob(f'{TRACES}/{pref}_r*.trace'))))

    for pkg, files in sources:
        files = [f for f in files if os.path.getsize(f) > 100_000]
        if not files:
            print(f'SKIP {pkg}: no trace', file=sys.stderr)
            continue
        st = next((v for k, v in static.items() if k[0] == pkg), None)
        if st is None:
            print(f'SKIP {pkg}: no static row', file=sys.stderr)
            continue
        reps = []
        for f in files:
            R = A.analyse(f)
            cls = {k: R['meth'][k]['cls'] for k in R['called']}
            fwset = {k for k in R['called'] if cls[k].startswith(FW)}
            SETS[pkg].append({f'{cls[k]}.{R["meth"][k]["name"]}{R["meth"][k]["sig"]}' for k in fwset})
            reps.append({
                'file': os.path.basename(f),
                'sha256': sha256(f),
                'methodCalls': R['n'],
                'bufferOverflowed': R['hdr'].get('data-file-overflow') == 'true',
                'selfcheck': _selfcheck(f),
                'distinctMethods': len(R['called']),
                'frameworkMethods': len(fwset),
                'frameworkClasses': len({cls[k] for k in fwset}),
                'hiddenApiMethods': sum(1 for k in R['called'] if cls[k].startswith(A.HIDDEN)),
                'adapterMethods': sum(1 for k in fwset if is_adapter(cls[k])),
                'byFamily': dict(collections.Counter(A.fam(cls[k]) for k in fwset).most_common()),
            })
        fwr = [r['frameworkMethods'] for r in reps]
        d = st['dex']
        rows.append({
            'package': pkg,
            'versionCode': st['versionCode'],
            'static': {
                'apkBytes': st['apkBytes'],
                'dexBytes': st['census']['dexBytes'],
                'methods': d['methods'],
                'classes': d['classes'],
                'distinctAndroidTypes': d['distinctAndroidTypes'],
                'distinctAndroidMethods': len(d['androidMethods']),
                'referencesListView': sorted(t for t in d['androidTypes'] if t.startswith(
                    ('Landroid/widget/ListView;', 'Landroid/widget/AbsListView;',
                     'Landroid/widget/AdapterView;', 'Landroid/widget/Adapter;',
                     'Landroid/widget/ArrayAdapter;', 'Landroid/widget/ListAdapter;',
                     'Landroid/widget/BaseAdapter;', 'Landroid/widget/AbsAdapter;'))),
            },
            'reps': reps,
            'bufferOverflowed': any(r['bufferOverflowed'] for r in reps),
            'cleanCaptures': sum(1 for r in reps if not r['bufferOverflowed']),
            'frameworkMethodsMin': min(fwr),
            'frameworkMethodsMax': max(fwr),
            'frameworkMethodsMed': sorted(fwr)[len(fwr) // 2],
        })

    # ---- the artefacts the brief's numbers came from, if they are reachable
    LEGACY_GLOB = ('gita.trace run1.trace run2.trace run3.trace run4.trace run5.trace '
                   'run6.trace t.trace c.trace clean.trace f1.trace gita_full.trace '
                   'm_create.trace m_recreate.trace m_recreate2.trace m_back.trace '
                   'm_idle.trace')
    legacy, undecodable = [], []
    for name in LEGACY_GLOB.split():
        f = os.path.join(TRACES, name)
        if not os.path.exists(f) or os.path.getsize(f) <= 4_096:
            continue
        try:
            R = A.analyse(f)
        except Exception as e:                                    # noqa: BLE001
            undecodable.append({'file': name, 'bytes': os.path.getsize(f),
                                'error': str(e)})
            continue
        app = sorted({R['meth'][k]['cls'] for k in R['called']
                      if not R['meth'][k]['cls'].startswith(
                          A.COUNTED + A.HIDDEN + A.HOST)})
        fwset = [k for k in R['called'] if R['meth'][k]['cls'].startswith(FW)]
        entry = {
            'file': name,
            'bytes': os.path.getsize(f),
            'sha256': sha256(f),
            'methodCalls': R['n'],
            'distinctMethods': len(R['called']),
            'frameworkMethods': len(fwset),
            'appClasses': app,
            'gitaPresent': any(c.startswith('eu.quelltext.gita') for c in app),
            'exactExits': None,
        }
        legacy.append(entry)

    out = {
        'schema': 'andro-substrate/framework-closure-measurement/1',
        'legacyCaptures': legacy,
        'legacyUndecodable': undecodable,
        'device': {
            'androidRelease': '13', 'sdkInt': 33, 'abi': 'arm64-v8a',
            'model': 'Android SDK built for arm64', 'qemu': True, 'rooted': True,
            'serial': 'emulator-5554',
            'bootedByThisAgent': False,
            'note': 'An emulator was already running and rooted (adbd running as '
                    'root) when this agent started. It was not booted here. It was '
                    'used read/write: `adb install` of 20 APKs and method traces '
                    'written to /data/local/tmp/mine.',
        },
        'method': {
            'capture': 'am start-activity -S -W -P <file> -n <component>',
            'semantics': '-S force-stops first so LaunchState is COLD; -W waits '
                         'for the first frame and prints TotalTime; -P starts ART '
                         'buffered method tracing (every method enter/exit, no '
                         'sampling) which stops when the app reports idle.',
            'counted': 'distinct method signatures in a class whose name starts '
                       'with android., java., javax. or dalvik.',
            'recordFormat': '14-byte records: tid:u16le, (methodId<<2|kind):u16le, '
                            'u32, u32, u16; kind 0=ENTER 1=EXIT 2=THREAD_CHANGE.',
            'window': 'process start -> first frame -> idle. The window is NOT '
                      '"first frame inclusive": ART stops the trace at idle, so '
                      'post-first-frame settle work is included. It is a COLD '
                      'start, so no previous activity of this app is torn down '
                      'inside the window.',
        },
        'rows': rows,
    }
    json.dump({p: sorted(v[0]) for p, v in SETS.items()}, open(f'{TRACES}/fwsets.json', 'w'), sort_keys=True)
    dst = f'{REPO}/docs/analysis/measurement.json'
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    json.dump(out, open(dst, 'w'), indent=1, sort_keys=True)
    print(f'wrote {dst}  rows={len(rows)}')
    print(f"{'package':46s} {'dMeth':>6s} {'fwMin':>7s} {'fwMed':>7s} {'fwMax':>7s} {'adapt':>6s}")
    for r in sorted(rows, key=lambda r: r['static']['distinctAndroidMethods']):
        print(f"{r['package']:46s} {r['static']['distinctAndroidMethods']:6d} "
              f"{r['frameworkMethodsMin']:7d} {r['frameworkMethodsMed']:7d} "
              f"{r['frameworkMethodsMax']:7d} "
              f"{max(x['adapterMethods'] for x in r['reps']):6d}")


if __name__ == '__main__':
    main()
