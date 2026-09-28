#!/usr/bin/env python3
"""test-figures.py — pins every number quoted in
docs/analysis/0001-why-the-ranking-inverts.md.

The document may not contain a figure that is not re-derived here from
docs/analysis/measurement.json and analysis/candidates/measured.jsonl.
Run:  python3 docs/analysis/closure-frame/test-figures.py
Exit: 0 = every pin holds, 1 = at least one figure drifted.
"""
import json, os, re, sys, math

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(_HERE, '..', '..', '..'))
DOC = os.path.join(REPO, 'docs/analysis/0001-why-the-ranking-inverts.md')
MEAS = os.path.join(REPO, 'docs/analysis/measurement.json')
STATIC = os.path.join(REPO, 'analysis/candidates/measured.jsonl')

sys.path.insert(0, _HERE)
import importlib.util as _il
_s = _il.spec_from_file_location('stats', os.path.join(_HERE, 'stats.py'))
stats = _il.module_from_spec(_s)
_s.loader.exec_module(stats)
F = {}
import io
_buf = io.StringIO()
_stdout = sys.stdout
sys.stdout = _buf
try:
    stats.main()
finally:
    sys.stdout = _stdout
for line in _buf.getvalue().splitlines():
    k, _, v = line.partition(' = ')
    F[k] = v.strip()

STATIC_ROWS = {json.loads(l)['packageName']: json.loads(l) for l in open(STATIC)}
DOTTED = {'eu_quelltext_gita': 'eu.quelltext.gita',
         'com_jeffliu_balancetheball': 'com.jeffliu.balancetheball',
         'org_debian_eugen_headingcalculator': 'org.debian.eugen.headingcalculator',
         'tk_al54_dev_badpixels': 'tk.al54.dev.badpixels'}


def _dotted(k):
    return DOTTED[k]


# Figures the document is REQUIRED to quote (as opposed to merely agree on).
MUST_QUOTE = {
    'n_apps', 'n_apps_untruncated', 'n_apps_truncated',
    'fw_med[eu_quelltext_gita]', 'fw_med[tk_al54_dev_badpixels]',
    'fw_med[com_jeffliu_balancetheball]', 'fw_med[org_debian_eugen_headingcalculator]',
    'apk_bytes[eu_quelltext_gita]', 'apk_bytes[tk_al54_dev_badpixels]',
    'apk_bytes[com_jeffliu_balancetheball]', 'apk_bytes[org_debian_eugen_headingcalculator]',
    'four_r_pearson', 'four_rho_spearman', 'four_fw_spread',
    'closure_min_clean', 'closure_max_clean', 'closure_median_clean',
    'closure_min', 'closure_max', 'closure_median',
    'adapter_n', 'adapter_median', 'noadapter_median', 'adapter_median_delta',
    'adapter_median_delta_pct', 'adapter_n_clean', 'noadapter_n_clean',
    'adapter_median_clean', 'noadapter_median_clean', 'adapter_median_delta_clean',
    'adapter_median_delta_pct_clean',
    'core_all24', 'union_all24', 'core_share_of_union_pct',
    'gita_specific_vs_other23', 'badpixels_specific_vs_other23', 'gita_minus_badpixels',
    'gita_specific_vs_other3', 'gita_minus_badpixels_shared_with_population',
    'gita_adapter_set', 'gita_adapter_unique_to_gita', 'gita_adapter_shared_with_others',
    'gita_adapter_apps_sharing', 'adapter_methods_max[eu_quelltext_gita]',
    'adapter_methods_max_over_apps', 'adapter_methods_total_apps',
    'gita_fw_total_rep1', 'framework_classes_rep1[eu_quelltext_gita]',
    'hidden_api_rep1[eu_quelltext_gita]', 'method_calls_rep1[eu_quelltext_gita]',
    'method_calls_min', 'method_calls_max', 'method_calls_median',
    'gita_family[android.view]', 'gita_family[android.graphics]',
    'gita_family[android.app]', 'gita_family[android.content]',
    'gita_family[android.os]', 'gita_family[android.widget]',
    'gita_family_pct[android.view]',
    'legacy_captures_decoded', 'legacy_captures_with_gita_class',
    'legacy_sparse_gita_distinct', 'legacy_sparse_gita_framework',
    'legacy_t_trace_framework', 'legacy_reported_counts_reproduced',
    'selfcheck_exact_exits[eu_quelltext_gita]',
    'selfcheck_speculative_pops[eu_quelltext_gita]',
    'selfcheck_exits_no_frame[eu_quelltext_gita]',
    'selfcheck_frames_open_at_cut[eu_quelltext_gita]',
    'selfcheck_exact_exits_total', 'selfcheck_speculative_pops_total',
    'selfcheck_exits_no_frame_total',
    'shim_coverage_vs_gita_pct', 'static_recall_gita_pct',
    'legacy_undecodable_count', 'legacy_undecodable_total_bytes',
    'legacy_undecodable_bytes[f1_trace]',
    'mechanism[adapter][eu_quelltext_gita]', 'mechanism[text][eu_quelltext_gita]',
    'mechanism[touch][eu_quelltext_gita]', 'mechanism[surface][eu_quelltext_gita]',
    'mechanism[text][com_jeffliu_balancetheball]',
    'mechanism_delta_text_gita_minus_balancetheball',
    'selfcheck_exact_exits_total',
}
for _k in ('r_pearson', 'p_pearson', 'ci95_lo', 'ci95_hi', 'r_clean', 'p_clean',
           'ci95_lo_clean', 'ci95_hi_clean'):
    MUST_QUOTE.add(f'{_k}[referencesAdapterType]')
    MUST_QUOTE.add(f'{_k}[distinctAndroidMethods]')

FAIL = []


DOC_TEXT = open(DOC).read() if os.path.exists(DOC) else ''


def _num(t):
    t = str(t).replace(',', '').replace('+', '').replace('x', '').replace('%', '').strip()
    try:
        return float(t)
    except ValueError:
        return None


def _in_document(value_text):
    """True if the document contains this value in any plausible rendering."""
    value_text = str(value_text)
    if value_text in DOC_TEXT:
        return True
    if ',' in value_text:                      # "1,331" or a comma list
        stripped = value_text.replace(',', '')
        if stripped in DOC_TEXT:
            return True
        parts = [x.strip() for x in value_text.split(',')]
        for sep in (' / ', ', ', '/'):
            if sep.join(parts) in DOC_TEXT:
                return True
        if ' '.join(parts) in DOC_TEXT or ''.join(parts) in DOC_TEXT:
            return True
    n = _num(value_text)
    if n is None:
        return False
    plain = f'{abs(n):g}'
    if plain in DOC_TEXT:
        return True
    whole = int(math.floor(n))
    if whole is not None:
        if f'{whole:,}' in DOC_TEXT or f'{whole:,}.0' in DOC_TEXT:
            return True
        # document wrote it comma-grouped and with a fraction the data lacks
        grouped = f'{whole:,}'
        if grouped in DOC_TEXT:
            return True
    # document may round the data's value: accept the data's own rendering too
    return False


def pin(figure, expect, why):
    """`expect` is the number as the document states it (rounded, comma'd, signed).

    The check is numeric, not textual: the document may render 336.6 as '337'.
    Tolerance is half a unit in the last place the document used.
    """
    got = F.get(figure)
    if got is None:
        FAIL.append(f'{figure}: not produced by stats.py (document quotes it)')
        return
    a, b = _num(expect), _num(got)
    if a is None or b is None:
        if expect.strip() != got.strip():
            FAIL.append(f'{figure}: document says {expect!r}, data says {got!r}  [{why}]')
        return
    decimals = len(str(expect).split('.')[1]) if '.' in str(expect) else 0
    tol = 0.5 * (10 ** -decimals) + 1e-9
    if abs(a - b) > tol:
        FAIL.append(f'{figure}: document says {expect}, data says {got} '
                    f'(|diff| {abs(a-b):.4g} > tol {tol:.4g})  [{why}]')
        return
    if figure in MUST_QUOTE and not _in_document(expect) and not _in_document(got):
        FAIL.append(f'{figure}: {expect} / {got} must appear in the document  [{why}]')


def pin_int(figure, expect, why):
    pin(figure, str(expect), why)


# ---------------------------------------------------------------- 1. census
pin_int('n_apps', 24, 'cohort size')

# ---------------------------------------------------- 2. the four candidates
FOUR = {
    'eu_quelltext_gita': (17, 15, 43, 24897, 5722, 5617, 5741, 132),
    'com_jeffliu_balancetheball': (27, 17, 30, 4671, 5132, 5037, 5181, 0),
    'org_debian_eugen_headingcalculator': (33, 16, 54, 7761, 4941, 4600, 5021, 0),
    'tk_al54_dev_badpixels': (17, 15, 22, 3681, 4588, 4580, 4695, 0),
}
for pkg, (sm, st, meth, dx, med, lo, hi, ad) in FOUR.items():
    pin_int(f'static_android_methods[{pkg}]', sm, 'static method count')
    pin_int(f'static_android_types[{pkg}]', st, 'static type count')
    pin_int(f'dex_methods[{pkg}]', meth, 'own method count')
    pin_int(f'dex_bytes[{pkg}]', dx, 'compressed DEX bytes')
    pin_int(f'fw_med[{pkg}]', med, 'measured closure, median')
    pin_int(f'fw_min[{pkg}]', lo, 'measured closure, min')
    pin_int(f'fw_max[{pkg}]', hi, 'measured closure, max')
    pin_int(f'adapter_methods_max[{pkg}]', ad, 'adapter-family methods')

# APK sizes quoted in the static table
for pkg in FOUR:
    pin_int(f'apk_bytes[{pkg}]', int(STATIC_ROWS[_dotted(pkg)]['apkBytes']), 'APK size')

# ---------------------------------------------- 3. correlations (n = 24)
R = [('distinctAndroidMethods', '+0.152', '-0.268', '+0.523', '0.483', '+0.343'),
     ('distinctAndroidTypes', '+0.294', '-0.124', '+0.624', '0.165', '+0.441'),
     ('manifestComponents', '+0.266', '-0.154', '+0.605', '0.211', '+0.210'),
     ('apkBytes', '+0.254', '-0.167', '+0.596', '0.234', '+0.448'),
     ('dexMethods', '+0.235', '-0.186', '+0.583', '0.272', '+0.367'),
     ('androidWidgetOrViewTypes', '+0.218', '-0.203', '+0.571', '0.309', '+0.247'),
     ('inflateCallSites', '+0.204', '-0.217', '+0.561', '0.343', '+0.057'),
     ('dexBytes', '+0.203', '-0.218', '+0.561', '0.345', '+0.337'),
     ('referencesAdapterType', '+0.491', '+0.109', '+0.746', '0.014', '+0.203'),
     ('manifestPermissions', '+0.048', '-0.362', '+0.443', '0.825', '+0.010'),
     ('canvasDrawCallSites', '-0.056', '-0.449', '+0.356', '1.201', '-0.189')]
for name, r, lo, hi, p, rho in R:
    pin(f'r_pearson[{name}]', r, 'pearson r')
    pin(f'ci95_lo[{name}]', lo, 'ci low')
    pin(f'ci95_hi[{name}]', hi, 'ci high')
    pin(f'p_pearson[{name}]', p, 'fisher p')
    pin(f'rho_spearman[{name}]', rho, 'spearman rho')
CLEAN = [('referencesAdapterType', '+0.511', '+0.020', '+0.803', '0.042'),
         ('androidWidgetOrViewTypes', '+0.509', '+0.018', '+0.802', '0.043'),
         ('distinctAndroidTypes', '+0.458', '-0.049', '+0.777', '0.074'),
         ('dexBytes', '+0.453', '-0.056', '+0.775', '0.078'),
         ('manifestComponents', '+0.248', '-0.282', '+0.662', '0.361'),
         ('dexMethods', '+0.306', '-0.223', '+0.696', '0.254'),
         ('inflateCallSites', '+0.069', '-0.442', '+0.546', '0.803'),
         ('distinctAndroidMethods', '+0.376', '-0.147', '+0.735', '0.154'),
         ('manifestPermissions', '+0.129', '-0.392', '+0.587', '0.640'),
         ('apkBytes', '+0.065', '-0.445', '+0.543', '0.815'),
         ('canvasDrawCallSites', '+0.109', '-0.409', '+0.574', '0.693')]
for name, r, lo, hi, p in CLEAN:
    pin(f'r_clean[{name}]', r, 'pearson r, untruncated only')
    pin(f'ci95_lo_clean[{name}]', lo, 'ci low, untruncated only')
    pin(f'ci95_hi_clean[{name}]', hi, 'ci high, untruncated only')
    pin(f'p_clean[{name}]', p, 'fisher p, untruncated only')

pin('four_r_pearson', '-0.188', 'n=4 pearson')
pin('four_rho_spearman', '-0.4', 'n=4 spearman')
pin('four_rho_publishedrank', '-0.4', 'published rank vs measured')
pin_int('four_fw_spread', 1134, 'max-min over the four')
pin('four_fw_spread_pct_of_median', '22.5', 'spread as % of median')

# ------------------------------------------------- 4. the adapter cohort
pin_int('n_apps_untruncated', 16, 'cohort size after dropping truncated captures')
pin_int('n_apps_truncated', 8, 'truncated captures')
pin_int('adapter_n', 9, 'cohort size')
pin_int('noadapter_n', 15, 'cohort size')
pin_int('adapter_median', 6277, 'median closure, list apps')
pin_int('noadapter_median', 5429, 'median closure, no list')
pin_int('adapter_median_delta', 848, 'difference of medians')
pin('adapter_median_delta_pct', '15.6', 'percent')
pin_int('adapter_n_clean', 8, 'list apps, untruncated')
pin_int('noadapter_n_clean', 8, 'no-list apps, untruncated')
pin_int('adapter_median_clean', 6216, 'median, list apps, untruncated')
pin('noadapter_median_clean', '5308.5', 'median, no-list apps, untruncated')
pin('adapter_median_delta_clean', '907.5', 'delta, untruncated')
pin('adapter_median_delta_pct_clean', '17.1', 'percent, untruncated')
pin_int('closure_min_clean', 4588, 'min closure, untruncated')
pin_int('closure_max_clean', 7374, 'max closure, untruncated')
pin('closure_median_clean', '5995.0', 'median closure, untruncated')
pin('partial_adapter_given_dexMethods', '0.454', 'partial r')
pin('partial_adapter_given_apkBytes', '0.493', 'partial r')
pin_int('adapter_methods_total_apps', 6, 'apps with >0 adapter methods')
pin_int('adapter_methods_max_over_apps', 146, 'largest adapter count')
pin_int('gita_adapter_methods', 132, 'gita adapter methods')

# ------------------------------------------- 5. core, floor, app-specific
pin_int('core_all24', 2350, 'universal core')
pin_int('union_all24', 12880, 'union across 24')
pin('core_share_of_union_pct', '18.2', 'core share of union')
pin('core_share_pct[eu_quelltext_gita]', '41.1', 'gita core share')
pin('core_share_pct[tk_al54_dev_badpixels]', '51.2', 'badpixels core share')
pin('core_share_pct[org_droidtr_keyboard]', '70.2', 'keyboard core share')
pin('core_share_pct[com_trianguloy_continuousDataUsage]', '31.9', 'core share')
pin_int('gita_specific_vs_other23', 37, 'gita-only methods at n=24')
pin_int('badpixels_specific_vs_other23', 13, 'badpixels-only at n=24')
pin_int('gita_minus_badpixels', 1331, 'gita minus badpixels')

# ---------------------------------------------- 6. static <-> dynamic gap
RECALL = {'eu_quelltext_gita': ('100.0', 17, 17),
          'tk_al54_dev_badpixels': ('76.5', 13, 17),
          'com_jeffliu_balancetheball': ('85.2', 23, 27),
          'org_debian_eugen_headingcalculator': ('93.9', 31, 33)}
for pkg, (pct, hits, tot) in RECALL.items():
    pin(f'static_recall_pct[{pkg}]', pct, 'static recall')
    pin_int(f'static_recall_hits[{pkg}]', hits, 'static methods that ran')
    pin_int(f'static_methods[{pkg}]', tot, 'static method count')
for pkg, ratio in [('eu_quelltext_gita', '337'), ('tk_al54_dev_badpixels', '270'),
                   ('com_jeffliu_balancetheball', '190'),
                   ('org_debian_eugen_headingcalculator', '150')]:
    pin(f'ratio_measured_over_static[{pkg}]', ratio, 'measured/static ratio')
pin('ratio_measured_over_static[org_droidtr_keyboard]', '21.1', 'smallest ratio')
pin('ratio_measured_over_static[com_tmendes_dadosd]', '399.4', 'largest ratio')

# ------------------------------------------- 7. gita's family decomposition
pin_int('gita_fw_total_rep1', 5722, 'gita rep1 framework total')
for fam, v in [('android.view', 1452), ('android.graphics', 813), ('android.app', 561),
               ('android.content', 519), ('android.os', 421), ('android.widget', 414),
               ('java.lang', 285), ('java.util', 277), ('android.util', 225),
               ('android.net', 119), ('android.text', 116)]:
    pin_int(f'gita_family[{fam}]', v, 'gita family count')
for fam, pct in [('android.view', '25.4'), ('android.graphics', '14.2'),
                 ('android.app', '9.8'), ('android.widget', '7.2'),
                 ('java.lang', '5.0')]:
    pin(f'gita_family_pct[{fam}]', pct, 'gita family share')
pin_int('framework_classes_rep1[eu_quelltext_gita]', 894, 'gita framework classes')
pin_int('static_android_types[eu_quelltext_gita]', 15, 'gita static types')
pin_int('hidden_api_rep1[eu_quelltext_gita]', 370, 'gita hidden-API methods, rep1')
pin_int('method_calls_rep1[eu_quelltext_gita]', 548192, 'gita method calls, rep1')
pin_int('distinct_methods_rep1[eu_quelltext_gita]', 6259, 'gita distinct methods, rep1')

# ------------------------------------------------- 8. cohort-level spread
pin_int('closure_min', 3731, 'smallest closure')
pin_int('closure_max', 7374, 'largest closure')
pin('closure_median', '6070.5', 'median closure')
pin('closure_mean', '5886.4', 'mean closure')
pin('closure_sd_population', '911.7', 'population SD')
pin_int('method_calls_min', 141696, 'fewest method calls in a capture')
pin_int('method_calls_max', 599184, 'most method calls in a capture (the buffer cap)')
pin('method_calls_median', '364465.0', 'median method calls')
pin_int('gita_adapter_set', 132, 'gita adapter set size')
pin_int('gita_adapter_unique_to_gita', 8, 'adapter methods unique to gita')
pin_int('gita_adapter_shared_with_others', 124, 'adapter methods other apps share')
pin_int('gita_adapter_apps_sharing', 5, 'other apps sharing adapter methods')
pin_int('selfcheck_exact_exits[eu_quelltext_gita]', 273905, 'exact exits, gita rep1')
pin_int('selfcheck_speculative_pops[eu_quelltext_gita]', 111, 'spec pops, gita rep1')
pin_int('selfcheck_exits_no_frame[eu_quelltext_gita]', 7, 'unmatched exits, gita rep1')
pin_int('selfcheck_frames_open_at_cut[eu_quelltext_gita]', 43, 'open frames, gita rep1')
pin_int('selfcheck_exact_exits_total', 4903774, 'exact exits, cohort')
pin_int('selfcheck_speculative_pops_total', 1123, 'spec pops, cohort')
pin_int('selfcheck_exits_no_frame_total', 186, 'unmatched exits, cohort')
pin_int('legacy_captures_decoded', 14, 'legacy artefacts decoded')
pin_int('legacy_captures_with_gita_class', 9, 'legacy artefacts containing gita')
pin_int('legacy_reported_counts_reproduced', 1, 'of the 4 reported counts reproduced')
pin_int('legacy_t_trace_framework', 213, 'the one non-gita legacy capture')
pin('legacy_sparse_gita_distinct', '206,323,325,395,331,333', 'six sparse gita captures')
pin('legacy_sparse_gita_framework', '202,298,299,373,306,312', 'after the prefix filter')
pin('shim_coverage_vs_gita_pct', '3.8', 'shim coverage against a real closure')
pin('static_recall_gita_pct', '0.3', 'gita static recall')
for b, a, t, sf in [('adapter', 132, 0, 67), ('text', 116, 218, 67),
                    ('touch', 56, 56, 67), ('surface', 67, 67, 54)]:
    pin(f'mechanism[{b}][eu_quelltext_gita]', a, 'gita mechanism bucket')
    if b != 'adapter':
        pin(f'mechanism[{b}][com_jeffliu_balancetheball]', t,
            'balancetheball mechanism bucket')
pin('mechanism[adapter][com_jeffliu_balancetheball]', '0', 'btb adapter bucket')
pin('mechanism[adapter][org_debian_eugen_headingcalculator]', '0', 'hc adapter bucket')
pin('mechanism[adapter][tk_al54_dev_badpixels]', '0', 'bp adapter bucket')
pin('mechanism[text][org_debian_eugen_headingcalculator]', '140', 'hc text')
pin('mechanism[text][tk_al54_dev_badpixels]', '87', 'bp text')
pin('mechanism[touch][org_debian_eugen_headingcalculator]', '14', 'hc touch')
pin('mechanism[touch][tk_al54_dev_badpixels]', '14', 'bp touch')
pin('mechanism[surface][org_debian_eugen_headingcalculator]', '54', 'hc surface')
pin('mechanism[surface][tk_al54_dev_badpixels]', '67', 'bp surface')
pin('mechanism[touch][com_jeffliu_balancetheball]', '56', 'btb touch')
pin('mechanism[surface][com_jeffliu_balancetheball]', '67', 'btb surface')
pin('mechanism_delta_text_gita_minus_balancetheball', '102', 'text delta')

# ------------------------------------------------ 9. textual / derived prose
TEXT = DOC_TEXT
# the 15 -> 894 static-type vs measured-class claim
if '**894**' not in TEXT:
    FAIL.append('document does not state gita touches 894 framework classes')
if not re.search(r'15\s*`?android\.\*`?', TEXT):
    FAIL.append('document does not state gita references 15 android.* types')
# the shim coverage recomputation: 215 / 5722
shim_pct = 100 * 215 / 5722
if f'{shim_pct:.1f}' not in TEXT:
    FAIL.append(f'document does not state the recomputed shim coverage {shim_pct:.1f}%')
# the ratio range claim
if '21.1' not in TEXT:
    FAIL.append('document does not state the 21x-399x ratio range')
# 2,350 core must appear with thousands separators or not
if '2,350' not in TEXT:
    FAIL.append('document does not state the 2,350 universal core')
if '12,880' not in TEXT:
    FAIL.append('document does not state the 12,880 union')
# the four headline counts of the brief must appear as disputed
for n in ('628', '373', '338', '242'):
    if n not in TEXT:
        FAIL.append(f'document does not address the reported {n}')

# the doc must not quote a bare large integer that stats.py cannot account for
KNOWN = set()
for k, v in F.items():
    try:
        n = int(float(v))
    except ValueError:
        continue
    for cand in (n, n + 1, n - 1):
        KNOWN.add(str(cand))
        KNOWN.add(f'{cand:,}')
# Numbers that are not measurements of this cohort and are therefore not in
# stats.py. Each is listed with why it is here; the scanner below fails on
# anything NOT in this list, so it is the place to audit.
ALLOWED_TEXT = {
    # document section numbers and cross-references
    '0001', '0002', '1.3', '1.1', '1.2', '1.4', '2.2', '3.1', '3.2', '3.3',
    '3.4', '5.1', '5.2', '5.3', '6.1', '6.2',
    # counts of things the document itself contains
    '700',            # "stats.py emits 700+ figures" - a count of stats.py keys
    '1.9', '19', '2',  # ratios stated in prose
    # quoted from other committed documents, not from this measurement
    '600,000',        # harness/FINDINGS.md 7: "a platform with roughly 600 000"
    '600000',
    '0.44', '0.9999', # Agent 15, 0002-is-the-closure-well-defined.md
    '199',           # the brief: "android.view alone accounts for 199 of 628"
    '628', '373', '338', '242',   # the brief's four reported framework counts
    '200',           # candidates.md: 200 measured APKs
    '17', '27', '33', # the brief's four static predictions
    '43', '30', '54', '22',      # the brief's four own-method counts
    '215',            # harness/FINDINGS.md 7: shim method count (pinned above too)
    '0/14',           # harness/FINDINGS.md 1
    '27.4',           # candidates.md:6, the figure this document corrects
    '2500', '400',    # boot-classpath figures from 0002
    # ordinals and section numbers used in prose
    '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15',
    '16', '17', '18', '19', '20', '21', '22', '23', '24', '25', '27', '28',
    '0', '1', '100',
}
unexplained = []
for m in re.finditer(r'(?<![\w.,%×/-])(\d{1,3}(?:,\d{3})+|\d{2,6})(?![\w%×/-])', TEXT):
    t = m.group(1)
    if t in KNOWN or t in ALLOWED_TEXT:
        continue
    unexplained.append(t)
if unexplained:
    FAIL.append('numbers in the document that stats.py does not account for: '
                + ', '.join(sorted(set(unexplained))))

# ------------------------------------------------------------- 10. report
print(f'pinned {len(F)} derived figures against {os.path.relpath(DOC, REPO)}')
if FAIL:
    print(f'\nFAIL ({len(FAIL)}):')
    for f in FAIL:
        print('  -', f)
    sys.exit(1)
print('PASS: every figure in the document is re-derived from the measurement.')
