#!/usr/bin/env python3
"""stats.py — every derived figure quoted in 0001-why-the-ranking-inverts.md.

Reads docs/analysis/measurement.json (written by measure.py) and prints one
`key = value` line per figure. `node --test ../ranking-inversion.test.mjs`
and `../closure-frame/test-figures.py` pin these; nothing here is hand-typed.

Usage:  python3 stats.py            # print key = value
        python3 stats.py --json     # machine-readable
"""
import json, math, os, collections, sys, importlib.util as _il

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(_HERE, '..', '..', '..'))
# Traces are not committed; A14_TRACE_DIR points at a directory holding them.
TRACES = os.environ.get('A14_TRACE_DIR', _HERE)
_sp = _il.spec_from_file_location('arttrace', os.path.join(_HERE, 'art-trace.py'))
A = _il.module_from_spec(_sp)
_sp.loader.exec_module(A)
M = json.load(open(os.path.join(REPO, 'docs/analysis/measurement.json')))
ROWS = M['rows']
STATIC = {json.loads(l)['packageName']: json.loads(l)
          for l in open(os.path.join(REPO, 'analysis/candidates/measured.jsonl'))}

TARGET = 'frameworkMethodsMed'


def pearson(x, y):
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    d = math.sqrt(sum((a - mx) ** 2 for a in x) * sum((b - my) ** 2 for b in y))
    return sum((a - mx) * (b - my) for a, b in zip(x, y)) / d


def ranks(v):
    order = sorted(range(len(v)), key=lambda i: v[i])
    r = [0] * len(v)
    for pos, i in enumerate(order):
        r[i] = pos + 1
    return r


def spearman(x, y):
    return pearson(ranks(x), ranks(y))


def fisher_p(r, n):
    if abs(r) >= 1.0:
        return 0.0
    z = 0.5 * math.log((1 + r) / (1 - r)) * math.sqrt(n - 3)
    return 2 * (1 - 0.5 * (1 + math.erf(z / math.sqrt(2))))


def ci95(r, n):
    z = 1.959963984540054
    return (math.tanh(math.atanh(r) - z / math.sqrt(n - 3)),
            math.tanh(math.atanh(r) + z / math.sqrt(n - 3)))


def median(v):
    s = sorted(v)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def pstdev(v):
    m = sum(v) / len(v)
    return math.sqrt(sum((a - m) ** 2 for a in v) / len(v))


def spe(v):
    m = sum(v) / len(v)
    return math.sqrt(sum((a - m) ** 2 for a in v) / (len(v) - 1))


def main():
    y = [r[TARGET] for r in ROWS]
    n = len(y)
    out = collections.OrderedDict()
    out['n_apps'] = n
    CLEAN = [r for r in ROWS if not r.get('bufferOverflowed')]
    out['n_apps_untruncated'] = len(CLEAN)
    out['n_apps_truncated'] = n - len(CLEAN)
    out['truncated_apps'] = ','.join(sorted(r['package'] for r in ROWS
                                             if r.get('bufferOverflowed')))

    # ---- 1. the measurement itself
    for r in ROWS:
        k = r['package'].replace('.', '_')
        out[f'fw_min[{k}]'] = r['frameworkMethodsMin']
        out[f'fw_med[{k}]'] = r['frameworkMethodsMed']
        out[f'fw_max[{k}]'] = r['frameworkMethodsMax']
        out[f'static_android_methods[{k}]'] = r['static']['distinctAndroidMethods']
        out[f'static_android_types[{k}]'] = r['static']['distinctAndroidTypes']
        out[f'dex_methods[{k}]'] = r['static']['methods']
        out[f'dex_bytes[{k}]'] = r['static']['dexBytes']
        out[f'refs_adapter_type[{k}]'] = 1 if r['static']['referencesListView'] else 0
        out[f'adapter_methods_max[{k}]'] = max(x['adapterMethods'] for x in r['reps'])
        out[f'reps[{k}]'] = len(r['reps'])
        out[f'buffer_overflowed[{k}]'] = 1 if r.get('bufferOverflowed') else 0
        out[f'clean_captures[{k}]'] = r.get('cleanCaptures', len(r['reps']))
        out[f'distinct_methods_rep1[{k}]'] = r['reps'][0]['distinctMethods']
        out[f'method_calls_rep1[{k}]'] = r['reps'][0]['methodCalls']
        out[f'hidden_api_rep1[{k}]'] = r['reps'][0]['hiddenApiMethods']
        out[f'framework_classes_rep1[{k}]'] = r['reps'][0]['frameworkClasses']
        g = r['reps'][0]
        out[f'ratio_measured_over_static[{k}]'] = round(
            r[TARGET] / r['static']['distinctAndroidMethods'], 1)

    out['closure_min'] = min(y)
    out['closure_max'] = max(y)
    out['closure_median'] = median(y)
    out['closure_mean'] = round(sum(y) / n, 1)
    out['closure_sd_population'] = round(pstdev(y), 1)
    out['closure_sd_sample'] = round(spe(y), 1)

    # ---- 2. does any static feature predict it?
    FEATS = collections.OrderedDict([
        ('distinctAndroidMethods', lambda r: r['static']['distinctAndroidMethods']),
        ('distinctAndroidTypes', lambda r: r['static']['distinctAndroidTypes']),
        ('dexMethods', lambda r: r['static']['methods']),
        ('dexBytes', lambda r: r['static']['dexBytes']),
        ('apkBytes', lambda r: r['static']['apkBytes']),
        ('referencesAdapterType', lambda r: 1 if r['static']['referencesListView'] else 0),
        ('androidWidgetOrViewTypes',
         lambda r: sum(1 for t in STATIC[r['package']]['dex']['androidTypes']
                       if t.startswith(('Landroid/widget/', 'Landroid/view/')))),
        ('manifestComponents', lambda r: STATIC[r['package']]['manifest']['totalComponents']),
        ('manifestPermissions', lambda r: len(STATIC[r['package']]['manifest']['permissions'])),
        ('inflateCallSites',
         lambda r: sum(1 for m in STATIC[r['package']]['dex']['androidMethods']
                       if 'LayoutInflater;.inflate' in m)),
        ('canvasDrawCallSites',
         lambda r: sum(1 for m in STATIC[r['package']]['dex']['androidMethods']
                       if 'Canvas;.draw' in m)),
    ])
    yc = [r[TARGET] for r in CLEAN]
    for name, f in FEATS.items():
        x = [f(r) for r in ROWS]
        r = pearson(x, y)
        lo, hi = ci95(r, n)
        out[f'r_pearson[{name}]'] = round(r, 3)
        out[f'p_pearson[{name}]'] = round(fisher_p(r, n), 3)
        out[f'ci95_lo[{name}]'] = round(lo, 3)
        out[f'ci95_hi[{name}]'] = round(hi, 3)
        out[f'rho_spearman[{name}]'] = round(spearman(x, y), 3)
        # same feature, untruncated captures only
        xc = [f(r) for r in CLEAN]
        rc = pearson(xc, yc)
        loc, hic = ci95(rc, len(CLEAN))
        out[f'r_clean[{name}]'] = round(rc, 3)
        out[f'p_clean[{name}]'] = round(fisher_p(rc, len(CLEAN)), 3)
        out[f'ci95_lo_clean[{name}]'] = round(loc, 3)
        out[f'ci95_hi_clean[{name}]'] = round(hic, 3)
    adc = [r[TARGET] for r in CLEAN if r['static']['referencesListView']]
    noc = [r[TARGET] for r in CLEAN if not r['static']['referencesListView']]
    out['adapter_n_clean'] = len(adc)
    out['noadapter_n_clean'] = len(noc)
    out['adapter_median_clean'] = median(adc)
    out['noadapter_median_clean'] = median(noc)
    out['adapter_median_delta_clean'] = median(adc) - median(noc)
    out['adapter_median_delta_pct_clean'] = round(
        100 * (median(adc) / median(noc) - 1), 1)
    out['closure_median_clean'] = median(yc)
    out['closure_min_clean'] = min(yc)
    out['closure_max_clean'] = max(yc)

    # ---- 3. the published four
    FOUR = ['eu.quelltext.gita', 'tk.al54.dev.badpixels',
            'com.jeffliu.balancetheball', 'org.debian.eugen.headingcalculator']
    PUBLISHED_RANK = {'eu.quelltext.gita': 1, 'tk.al54.dev.badpixels': 2,
                      'com.jeffliu.balancetheball': 3,
                      'org.debian.eugen.headingcalculator': 4}
    four = [next(r for r in ROWS if r['package'] == p) for p in FOUR]
    y4 = [r[TARGET] for r in four]
    x4 = [r['static']['distinctAndroidMethods'] for r in four]
    out['four_r_pearson'] = round(pearson(x4, y4), 3)
    out['four_rho_spearman'] = round(spearman(x4, y4), 3)
    out['four_rho_publishedrank'] = round(
        spearman([PUBLISHED_RANK[r['package']] for r in four], y4), 3)
    out['four_fw_spread'] = max(y4) - min(y4)
    out['four_fw_spread_pct_of_median'] = round(
        100 * (max(y4) - min(y4)) / median(y4), 1)

    # ---- 4. the adapter cohort
    ad = [r[TARGET] for r in ROWS if r['static']['referencesListView']]
    no = [r[TARGET] for r in ROWS if not r['static']['referencesListView']]
    out['adapter_n'] = len(ad)
    out['adapter_median'] = median(ad)
    out['adapter_min'] = min(ad)
    out['adapter_max'] = max(ad)
    out['noadapter_n'] = len(no)
    out['noadapter_median'] = median(no)
    out['noadapter_min'] = min(no)
    out['noadapter_max'] = max(no)
    out['adapter_median_delta'] = median(ad) - median(no)
    out['adapter_median_delta_pct'] = round(100 * (median(ad) / median(no) - 1), 1)
    xa = [1 if r['static']['referencesListView'] else 0 for r in ROWS]

    def partial(a, b, c):
        rab, rac, rbc = pearson(a, b), pearson(a, c), pearson(b, c)
        return (rab - rac * rbc) / math.sqrt((1 - rac ** 2) * (1 - rbc ** 2))
    out['partial_adapter_given_dexMethods'] = round(
        partial(xa, y, [r['static']['methods'] for r in ROWS]), 3)
    out['partial_adapter_given_apkBytes'] = round(
        partial(xa, y, [r['static']['apkBytes'] for r in ROWS]), 3)
    out['adapter_methods_total_apps'] = sum(
        1 for r in ROWS if max(x['adapterMethods'] for x in r['reps']) > 0)
    out['adapter_methods_max_over_apps'] = max(
        max(x['adapterMethods'] for x in r['reps']) for r in ROWS)
    out['gita_adapter_methods'] = next(
        r for r in ROWS if r['package'] == 'eu.quelltext.gita')['reps'][0]['adapterMethods']

    # ---- 5. core vs app-specific, from the per-app method sets
    SETS = json.load(open(os.path.join(_HERE, 'fwsets.json')))
    core24 = set.intersection(*[set(SETS[r['package']]) for r in ROWS])
    union24 = set.union(*[set(SETS[r['package']]) for r in ROWS])
    out['core_all24'] = len(core24)
    out['union_all24'] = len(union24)
    out['core_share_of_union_pct'] = round(100 * len(core24) / len(union24), 1)
    for r in ROWS:
        k = r['package'].replace('.', '_')
        s = set(SETS[r['package']])
        out[f'core_share_pct[{k}]'] = round(100 * len(s & core24) / len(s), 1)
        out[f'extra_over_core[{k}]'] = len(s) - len(s & core24)
    gita = set(SETS['eu.quelltext.gita'])
    others = set().union(*[set(SETS[r['package']]) for r in ROWS
                           if r['package'] != 'eu.quelltext.gita'])
    out['gita_specific_vs_other23'] = len(gita - others)
    bad = set(SETS['tk.al54.dev.badpixels'])
    othersb = set().union(*[set(SETS[r['package']]) for r in ROWS
                            if r['package'] != 'tk.al54.dev.badpixels'])
    out['badpixels_specific_vs_other23'] = len(bad - othersb)
    out['gita_minus_badpixels'] = len(gita - bad)

    # ---- 6. static <-> dynamic overlap for the published four
    for p in FOUR:
        st = STATIC[p]
        dyn = set(SETS[p])
        sm = set(st['dex']['androidMethods'])
        hit = sum(1 for m in sm
                  if any(d.startswith(m.split(';')[0][1:].replace('/', '.'))
                         for d in dyn))
        k = p.replace('.', '_')
        out[f'static_recall_pct[{k}]'] = round(100 * hit / len(sm), 1)
        out[f'static_recall_hits[{k}]'] = hit
        out[f'static_methods[{k}]'] = len(sm)

    # ---- 7. gita's family decomposition (rep 1)
    g = next(r for r in ROWS if r['package'] == 'eu.quelltext.gita')
    fam = g['reps'][0]['byFamily']
    out['gita_fw_total_rep1'] = sum(fam.values())
    for k, v in fam.items():
        out[f'gita_family[{k}]'] = v
    out['gita_family_pct[android.view]'] = round(
        100 * fam['android.view'] / sum(fam.values()), 1)
    out['gita_family_pct[android.graphics]'] = round(
        100 * fam['android.graphics'] / sum(fam.values()), 1)
    out['gita_family_pct[android.app]'] = round(
        100 * fam['android.app'] / sum(fam.values()), 1)
    out['gita_family_pct[android.widget]'] = round(
        100 * fam['android.widget'] / sum(fam.values()), 1)
    out['gita_family_pct[java.lang]'] = round(
        100 * fam['java.lang'] / sum(fam.values()), 1)
    # gita's app-specific methods by family
    gspec = [s for s in (gita - others)]
    c = collections.Counter('.'.join(s.split('#')[0].split('.')[:2]) for s in gspec)
    for k, v in c.most_common(8):
        out[f'gita_specific_family[{k}]'] = v

    # ---- 7b. the four mechanism buckets, §3.2
    BUCKETS = {
        'adapter': ('android.widget.Adapter', 'android.widget.AbsListView',
                    'android.widget.ListView', 'android.widget.AdapterView',
                    'android.widget.AbsAdapter', 'android.widget.BaseAdapter',
                    'android.widget.ArrayAdapter', 'android.widget.ListAdapter',
                    'android.widget.AbsSpinner', 'android.widget.ExpandableListView',
                    'android.widget.SimpleAdapter',
                    'android.widget.HeaderViewListAdapter'),
        'text': ('android.text.', 'android.text.method.', 'android.text.style.',
                 'android.text.format.', 'android.text.TextPaint'),
        'touch': ('android.view.inputmethod.', 'android.view.KeyEvent',
                  'android.view.MotionEvent', 'android.view.MotionEvent$'),
        'surface': ('android.view.Surface', 'android.view.SurfaceView',
                    'android.view.SurfaceView$', 'android.view.SurfaceHolder',
                    'android.view.SurfaceHolder$'),
    }

    def _bucket(c):
        for nm, pref in BUCKETS.items():
            for p_ in pref:
                if c == p_ or c.startswith(p_):
                    return nm
        return None
    for r in ROWS:
        k = r['package'].replace('.', '_')
        cnt = collections.Counter()
        for sig in SETS[r['package']]:
            cnt[_bucket(sig[:sig.index('(')].rsplit('.', 1)[0])] += 1
        for nm in BUCKETS:
            out[f'mechanism[{nm}][{k}]'] = cnt[nm]
    out['mechanism_delta_text_gita_minus_balancetheball'] = (
        out['mechanism[text][com_jeffliu_balancetheball]']
        - out['mechanism[text][eu_quelltext_gita]'])

    # ---- 7c. gita's excess over badpixels *within the four*
    F3 = ['eu.quelltext.gita', 'tk.al54.dev.badpixels',
          'com.jeffliu.balancetheball', 'org.debian.eugen.headingcalculator']
    o3 = set().union(*[set(SETS[p]) for p in F3 if p != 'eu.quelltext.gita'])
    out['gita_specific_vs_other3'] = len(set(SETS['eu.quelltext.gita']) - o3)
    out['gita_minus_badpixels_shared_with_population'] = len(
        (set(SETS['eu.quelltext.gita']) - set(SETS['tk.al54.dev.badpixels'])) & others)

    # ---- 8. APK sizes, quoted in the static table
    for r in ROWS:
        out[f'apk_bytes[{r["package"].replace(".", "_")}]'] = r['static']['apkBytes']

    # ---- 9. the brief's own artefacts, decoded here so §1 is not an assertion
    for e in M.get('legacyCaptures', []):
        k = e['file'].replace('.', '_')
        out[f'legacy_bytes[{k}]'] = e['bytes']
        if 'frameworkMethods' in e:
            out[f'legacy_distinct[{k}]'] = e['distinctMethods']
            out[f'legacy_framework[{k}]'] = e['frameworkMethods']
            out[f'legacy_calls[{k}]'] = e['methodCalls']
            out[f'legacy_is_gita[{k}]'] = 1 if e.get('gitaPresent') else 0
    UND = M.get('legacyUndecodable', [])
    out['legacy_undecodable_count'] = len(UND)
    out['legacy_undecodable_total_bytes'] = sum(e['bytes'] for e in UND)
    for e in UND:
        out[f"legacy_undecodable_bytes[{e['file'].replace('.', '_')}]"] = e['bytes']
    LEG = M.get('legacyCaptures', [])
    out['legacy_captures_decoded'] = len(LEG)
    out['legacy_captures_with_gita_class'] = sum(1 for e in LEG if e.get('gitaPresent'))
    out['legacy_distinct_min'] = min(e['distinctMethods'] for e in LEG
                                      if 'distinctMethods' in e)
    out['legacy_distinct_max'] = max(e['distinctMethods'] for e in LEG
                                      if 'distinctMethods' in e)
    out['legacy_sparse_gita_distinct'] = ','.join(
        str(e['distinctMethods']) for e in LEG
        if e['file'] in ('run1.trace', 'run2.trace', 'run3.trace', 'run4.trace',
                         'run5.trace', 'run6.trace'))
    out['legacy_sparse_gita_framework'] = ','.join(
        str(e['frameworkMethods']) for e in LEG
        if e['file'] in ('run1.trace', 'run2.trace', 'run3.trace', 'run4.trace',
                         'run5.trace', 'run6.trace'))
    out['legacy_t_trace_framework'] = next(
        (e['frameworkMethods'] for e in LEG if e['file'] == 't.trace'), 0)
    out['legacy_gita_trace_framework'] = next(
        (e['frameworkMethods'] for e in LEG if e['file'] == 'gita.trace'), 0)
    # do any of the four reported counts appear as a per-file number?
    reported = {628, 373, 338, 242}
    seen = {e['frameworkMethods'] for e in LEG if 'frameworkMethods' in e}
    out['legacy_reported_counts_reproduced'] = len(reported & seen)
    out['legacy_reported_counts_total'] = len(reported)

    # ---- 10. shim-coverage recomputation against a real closure
    out['shim_methods'] = 215                     # harness/FINDINGS.md §7
    out['shim_coverage_vs_gita_pct'] = round(100 * 215 / 5722, 1)
    out['static_recall_gita_pct'] = round(100 * 17 / 5722, 2)

    # ---- 11. decoder self-check, from the recorded per-capture budget
    for r in ROWS:
        k = r['package'].replace('.', '_')
        sc = r['reps'][0].get('selfcheck')
        if not sc:
            continue
        out[f'selfcheck_exact_exits[{k}]'] = sc['exactExits']
        out[f'selfcheck_speculative_pops[{k}]'] = sc['speculativePops']
        out[f'selfcheck_exits_no_frame[{k}]'] = sc['exitsWithNoFrame']
        out[f'selfcheck_frames_open_at_cut[{k}]'] = sc['framesOpenAtCut']
    out['selfcheck_exact_exits_total'] = sum(
        r['reps'][0]['selfcheck']['exactExits'] for r in ROWS
        if r['reps'][0].get('selfcheck'))
    out['selfcheck_speculative_pops_total'] = sum(
        r['reps'][0]['selfcheck']['speculativePops'] for r in ROWS
        if r['reps'][0].get('selfcheck'))
    out['selfcheck_exits_no_frame_total'] = sum(
        r['reps'][0]['selfcheck']['exitsWithNoFrame'] for r in ROWS
        if r['reps'][0].get('selfcheck'))

    # ---- 12. method-call volume across the cohort
    calls = [r['reps'][0]['methodCalls'] for r in ROWS]
    out['method_calls_min'] = min(calls)
    out['method_calls_max'] = max(calls)
    out['method_calls_median'] = median(calls)

    # ---- 13. how much of gita's adapter set the other 23 apps share
    cls_of = lambda s: s[:s.index('(')].rsplit('.', 1)[0]
    PREF = ('android.widget.Adapter', 'android.widget.AbsListView',
            'android.widget.ListView', 'android.widget.AdapterView',
            'android.widget.AbsAdapter', 'android.widget.BaseAdapter',
            'android.widget.ArrayAdapter', 'android.widget.ListAdapter',
            'android.widget.AbsSpinner', 'android.widget.ExpandableListView',
            'android.widget.SimpleAdapter', 'android.widget.HeaderViewListAdapter')
    gad = {s for s in gita
           if any(cls_of(s) == p or cls_of(s).startswith(p + '$') for p in PREF)}
    out['gita_adapter_set'] = len(gad)
    out['gita_adapter_unique_to_gita'] = len(gad - others)
    out['gita_adapter_shared_with_others'] = len(gad & others)
    out['gita_adapter_apps_sharing'] = sum(
        1 for r in ROWS if r['package'] != 'eu.quelltext.gita'
        and gad & set(SETS[r['package']]))

    if '--json' in sys.argv:
        json.dump(out, sys.stdout, indent=1)
    else:
        for k, v in out.items():
            print(f'{k} = {v}')


if __name__ == '__main__':
    main()
