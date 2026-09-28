# ART method-trace report

Generated from `trace/runs`.
Every count is labelled with the coverage it was measured at.

## Failed captures (excluded from every set)

| trace | bytes | reason |
|---|---|---|
| `com.jeffliu.balancetheball.create.run1.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/com.jeffliu.balancetheball.create.run1.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `com.jeffliu.balancetheball.create.run2.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/com.jeffliu.balancetheball.create.run2.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `com.jeffliu.balancetheball.startprof.run1.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/com.jeffliu.balancetheball.startprof.run1.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `com.jeffliu.balancetheball.startprof.run2.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/com.jeffliu.balancetheball.startprof.run2.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `com.jeffliu.balancetheball.teardown.run1.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/com.jeffliu.balancetheball.teardown.run1.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `com.jeffliu.balancetheball.teardown.run2.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/com.jeffliu.balancetheball.teardown.run2.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `de.cweiske.headphoneindicator.startprof.run1.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/de.cweiske.headphoneindicator.startprof.run1.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `de.cweiske.headphoneindicator.startprof.run2.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/de.cweiske.headphoneindicator.startprof.run2.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `org.billthefarmer.shorty.startprof.run1.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/org.billthefarmer.shorty.startprof.run1.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `org.billthefarmer.shorty.startprof.run2.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/org.billthefarmer.shorty.startprof.run2.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `tk.al54.dev.badpixels.startprof.run1.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/tk.al54.dev.badpixels.startprof.run1.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |
| `tk.al54.dev.badpixels.startprof.run2.trace` | 0 | /Users/zen/Desktop/uni/andro-substrate/trace/runs/tk.al54.dev.badpixels.startprof.run2.trace: empty file (0 bytes) — this is a failed capture, not a run with no calls |

## Per app

| package | mode | sampling | coverage | runs | per-run framework methods | union | pairwise Jaccard |
|---|---|---|---|---|---|---|---|
| `com.jeffliu.balancetheball` | idle | full | **exhaustive** | 1/1 | 379 | **379** | n/a (1 run) |
| `com.jeffliu.balancetheball` | recreate | s100us | **sampled@100us (lower bound)** | 1/1 | 229 | **229** | n/a (1 run) |
| `com.jeffliu.balancetheball` | recreate | full | **exhaustive** | 3/3 | 4605, 4619, 4631 | **4738** | r1~r2=0.9522 r1~r3=0.9498 r2~r3=0.9970 |
| `com.oF2pks.applicationsinfo` | create | full | **exhaustive** | 3/3 | 2251, 2260, 2259 | **2269** | r1~r2=0.9951 r1~r3=0.9965 r2~r3=0.9916 |
| `com.oF2pks.applicationsinfo` | idle | full | **exhaustive** | 1/1 | 151 | **151** | n/a (1 run) |
| `com.oF2pks.applicationsinfo` | recreate | s100us | **sampled@100us (lower bound)** | 1/1 | 1099 | **1099** | n/a (1 run) |
| `com.oF2pks.applicationsinfo` | recreate | full | **TRUNCATED (data-file-overflow in 3/3 run(s)) — lower bound** | 3/3 | 6523, 6527, 6202 | **6569** | r1~r2=0.9872 r1~r3=0.9386 r2~r3=0.9493 |
| `com.oF2pks.applicationsinfo` | startprof | full | **exhaustive (overflow NOT verifiable: continuous layout carries no flag) — unverifiable** | 2/2 | 8844, 8904 | **8904** | r1~r2=0.9933 |
| `com.oF2pks.applicationsinfo` | teardown | full | **TRUNCATED (data-file-overflow in 1/3 run(s)) — lower bound** | 3/3 | 2359, 2734, 2364 | **3496** | r1~r2=0.4589 r1~r3=0.9911 r2~r3=0.4599 |
| `de.cweiske.headphoneindicator` | create | full | **exhaustive** | 3/3 | 1770, 1769, 1769 | **1770** | r1~r2=0.9994 r1~r3=0.9994 r2~r3=1.0000 |
| `de.cweiske.headphoneindicator` | idle | full | **exhaustive** | 1/1 | 91 | **91** | n/a (1 run) |
| `de.cweiske.headphoneindicator` | recreate | s100us | **sampled@100us (lower bound)** | 1/1 | 329 | **329** | n/a (1 run) |
| `de.cweiske.headphoneindicator` | recreate | full | **exhaustive** | 3/3 | 4430, 4412, 4405 | **4432** | r1~r2=0.9950 r1~r3=0.9944 r2~r3=0.9980 |
| `de.cweiske.headphoneindicator` | teardown | full | **exhaustive** | 3/3 | 1873, 1871, 1862 | **1882** | r1~r2=0.9894 r1~r3=0.9846 r2~r3=0.9931 |
| `eu.quelltext.gita` | create | full | **exhaustive** | 3/3 | 2374, 2380, 1854 | **2437** | r1~r2=0.9950 r1~r3=0.7399 r2~r3=0.7395 |
| `eu.quelltext.gita` | idle | full | **exhaustive** | 1/1 | 91 | **91** | n/a (1 run) |
| `eu.quelltext.gita` | recreate | s100us | **sampled@100us (lower bound)** | 1/1 | 230 | **230** | n/a (1 run) |
| `eu.quelltext.gita` | recreate | full | **exhaustive** | 3/3 | 4638, 4638, 4637 | **4638** | r1~r2=1.0000 r1~r3=0.9998 r2~r3=0.9998 |
| `eu.quelltext.gita` | startprof | full | **exhaustive (overflow NOT verifiable: continuous layout carries no flag) — unverifiable** | 2/2 | 6009, 6025 | **6025** | r1~r2=0.9973 |
| `eu.quelltext.gita` | teardown | full | **exhaustive** | 3/3 | 1491, 773, 1864 | **1883** | r1~r2=0.4365 r1~r3=0.7846 r2~r3=0.4124 |
| `org.billthefarmer.shorty` | create | full | **exhaustive** | 3/3 | 2311, 2317, 2326 | **2327** | r1~r2=0.9957 r1~r3=0.9927 r2~r3=0.9953 |
| `org.billthefarmer.shorty` | idle | full | **exhaustive** | 1/1 | 138 | **138** | n/a (1 run) |
| `org.billthefarmer.shorty` | recreate | s100us | **sampled@100us (lower bound)** | 1/1 | 254 | **254** | n/a (1 run) |
| `org.billthefarmer.shorty` | recreate | full | **exhaustive** | 3/3 | 6255, 6100, 6100 | **6263** | r1~r2=0.9727 r1~r3=0.9727 r2~r3=1.0000 |
| `org.billthefarmer.shorty` | teardown | full | **exhaustive** | 3/3 | 2483, 2481, 2489 | **2492** | r1~r2=0.9944 r1~r3=0.9976 r2~r3=0.9944 |
| `tk.al54.dev.badpixels` | create | full | **exhaustive** | 3/3 | 2816, 2553, 2601 | **2900** | r1~r2=0.8571 r1~r3=0.8692 r2~r3=0.9800 |
| `tk.al54.dev.badpixels` | idle | full | **exhaustive** | 1/1 | 91 | **91** | n/a (1 run) |
| `tk.al54.dev.badpixels` | recreate | s100us | **sampled@100us (lower bound)** | 1/1 | 195 | **195** | n/a (1 run) |
| `tk.al54.dev.badpixels` | recreate | full | **exhaustive** | 3/3 | 3866, 3871, 3862 | **3875** | r1~r2=0.9966 r1~r3=0.9990 r2~r3=0.9977 |
| `tk.al54.dev.badpixels` | teardown | full | **exhaustive** | 3/3 | 1898, 1889, 1890 | **1898** | r1~r2=0.9953 r1~r3=0.9958 r2~r3=0.9974 |

## Convergence, |union of k runs|

Enumerated over every ordering of the runs, so the value does not depend on
capture order. `orderings` is how many permutations were averaged.

- `com.jeffliu.balancetheball` idle full (exhaustive, 1 ordering): 379.0
- `com.jeffliu.balancetheball` recreate s100us (sampled@100us (lower bound), 1 ordering): 229.0
- `com.jeffliu.balancetheball` recreate full (exhaustive, 6 orderings): 4618.3 → 4698.0 → 4738.0
- `com.oF2pks.applicationsinfo` create full (exhaustive, 6 orderings): 2256.7 → 2263.0 → 2269.0
- `com.oF2pks.applicationsinfo` idle full (exhaustive, 1 ordering): 151.0
- `com.oF2pks.applicationsinfo` recreate s100us (sampled@100us (lower bound), 1 ordering): 1099.0
- `com.oF2pks.applicationsinfo` recreate full (TRUNCATED (data-file-overflow in 3/3 run(s)) — lower bound, 6 orderings): 6417.3 → 6553.7 → 6569.0
- `com.oF2pks.applicationsinfo` startprof full (exhaustive (overflow NOT verifiable: continuous layout carries no flag) — unverifiable, 2 orderings): 8874.0 → 8904.0
- `com.oF2pks.applicationsinfo` teardown full (TRUNCATED (data-file-overflow in 1/3 run(s)) — lower bound, 6 orderings): 2485.7 → 3118.3 → 3496.0
- `de.cweiske.headphoneindicator` create full (exhaustive, 6 orderings): 1769.3 → 1769.7 → 1770.0
- `de.cweiske.headphoneindicator` idle full (exhaustive, 1 ordering): 91.0
- `de.cweiske.headphoneindicator` recreate s100us (sampled@100us (lower bound), 1 ordering): 329.0
- `de.cweiske.headphoneindicator` recreate full (exhaustive, 6 orderings): 4415.7 → 4425.0 → 4432.0
- `de.cweiske.headphoneindicator` teardown full (exhaustive, 6 orderings): 1868.7 → 1879.0 → 1882.0
- `eu.quelltext.gita` create full (exhaustive, 6 orderings): 2202.7 → 2415.7 → 2437.0
- `eu.quelltext.gita` idle full (exhaustive, 1 ordering): 91.0
- `eu.quelltext.gita` recreate s100us (sampled@100us (lower bound), 1 ordering): 230.0
- `eu.quelltext.gita` recreate full (exhaustive, 6 orderings): 4637.7 → 4638.0 → 4638.0
- `eu.quelltext.gita` startprof full (exhaustive (overflow NOT verifiable: continuous layout carries no flag) — unverifiable, 2 orderings): 6017.0 → 6025.0
- `eu.quelltext.gita` teardown full (exhaustive, 6 orderings): 1376.0 → 1774.3 → 1883.0
- `org.billthefarmer.shorty` create full (exhaustive, 6 orderings): 2318.0 → 2324.3 → 2327.0
- `org.billthefarmer.shorty` idle full (exhaustive, 1 ordering): 138.0
- `org.billthefarmer.shorty` recreate s100us (sampled@100us (lower bound), 1 ordering): 254.0
- `org.billthefarmer.shorty` recreate full (exhaustive, 6 orderings): 6151.7 → 6208.7 → 6263.0
- `org.billthefarmer.shorty` teardown full (exhaustive, 6 orderings): 2484.3 → 2490.0 → 2492.0
- `tk.al54.dev.badpixels` create full (exhaustive, 6 orderings): 2656.7 → 2797.3 → 2900.0
- `tk.al54.dev.badpixels` idle full (exhaustive, 1 ordering): 91.0
- `tk.al54.dev.badpixels` recreate s100us (sampled@100us (lower bound), 1 ordering): 195.0
- `tk.al54.dev.badpixels` recreate full (exhaustive, 6 orderings): 3866.3 → 3870.7 → 3875.0
- `tk.al54.dev.badpixels` teardown full (exhaustive, 6 orderings): 1892.3 → 1896.0 → 1898.0

## Common to every app

Computed within a single capture mode. `recreate` includes activity teardown
and `idle` includes almost nothing, so pooling modes would produce a number
that describes no app.

### `create full` — exhaustive

- Apps compared: `com.oF2pks.applicationsinfo`, `de.cweiske.headphoneindicator`, `eu.quelltext.gita`, `org.billthefarmer.shorty`, `tk.al54.dev.badpixels` (5).
- **Intersection: 1697 methods.** Union of all app unions: 3550.
- Per-app union sizes: `com.oF2pks.applicationsinfo` 2269, `de.cweiske.headphoneindicator` 1770, `eu.quelltext.gita` 2437, `org.billthefarmer.shorty` 2327, `tk.al54.dev.badpixels` 2900.
- Pairwise Jaccard between app unions: com.oF2pks.applicationsinfo vs de.cweiske.headphoneindicator 0.7477; com.oF2pks.applicationsinfo vs eu.quelltext.gita 0.6512; com.oF2pks.applicationsinfo vs org.billthefarmer.shorty 0.8488; com.oF2pks.applicationsinfo vs tk.al54.dev.badpixels 0.5754; de.cweiske.headphoneindicator vs eu.quelltext.gita 0.6991; de.cweiske.headphoneindicator vs org.billthefarmer.shorty 0.7265; de.cweiske.headphoneindicator vs tk.al54.dev.badpixels 0.5788; eu.quelltext.gita vs org.billthefarmer.shorty 0.6237; eu.quelltext.gita vs tk.al54.dev.badpixels 0.7413; org.billthefarmer.shorty vs tk.al54.dev.badpixels 0.5782.

### `idle full` — exhaustive

- Apps compared: `com.jeffliu.balancetheball`, `com.oF2pks.applicationsinfo`, `de.cweiske.headphoneindicator`, `eu.quelltext.gita`, `org.billthefarmer.shorty`, `tk.al54.dev.badpixels` (6).
- **Intersection: 91 methods.** Union of all app unions: 436.
- Per-app union sizes: `com.jeffliu.balancetheball` 379, `com.oF2pks.applicationsinfo` 151, `de.cweiske.headphoneindicator` 91, `eu.quelltext.gita` 91, `org.billthefarmer.shorty` 138, `tk.al54.dev.badpixels` 91.
- Pairwise Jaccard between app unions: com.jeffliu.balancetheball vs com.oF2pks.applicationsinfo 0.2156; com.jeffliu.balancetheball vs de.cweiske.headphoneindicator 0.2401; com.jeffliu.balancetheball vs eu.quelltext.gita 0.2401; com.jeffliu.balancetheball vs org.billthefarmer.shorty 0.2193; com.jeffliu.balancetheball vs tk.al54.dev.badpixels 0.2401; com.oF2pks.applicationsinfo vs de.cweiske.headphoneindicator 0.6026; com.oF2pks.applicationsinfo vs eu.quelltext.gita 0.6026; com.oF2pks.applicationsinfo vs org.billthefarmer.shorty 0.9139; com.oF2pks.applicationsinfo vs tk.al54.dev.badpixels 0.6026; de.cweiske.headphoneindicator vs eu.quelltext.gita 1.0000; de.cweiske.headphoneindicator vs org.billthefarmer.shorty 0.6594; de.cweiske.headphoneindicator vs tk.al54.dev.badpixels 1.0000; eu.quelltext.gita vs org.billthefarmer.shorty 0.6594; eu.quelltext.gita vs tk.al54.dev.badpixels 1.0000; org.billthefarmer.shorty vs tk.al54.dev.badpixels 0.6594.

### `recreate full` — TRUNCATED (data-file-overflow in 3/3 run(s)) — lower bound

- Apps compared: `com.jeffliu.balancetheball`, `com.oF2pks.applicationsinfo`, `de.cweiske.headphoneindicator`, `eu.quelltext.gita`, `org.billthefarmer.shorty`, `tk.al54.dev.badpixels` (6).
- **Intersection: 3203 methods.** Union of all app unions: 8789.
- Per-app union sizes: `com.jeffliu.balancetheball` 4738, `com.oF2pks.applicationsinfo` 6569, `de.cweiske.headphoneindicator` 4432, `eu.quelltext.gita` 4638, `org.billthefarmer.shorty` 6263, `tk.al54.dev.badpixels` 3875.
- Pairwise Jaccard between app unions: com.jeffliu.balancetheball vs com.oF2pks.applicationsinfo 0.4726; com.jeffliu.balancetheball vs de.cweiske.headphoneindicator 0.6395; com.jeffliu.balancetheball vs eu.quelltext.gita 0.6337; com.jeffliu.balancetheball vs org.billthefarmer.shorty 0.5811; com.jeffliu.balancetheball vs tk.al54.dev.badpixels 0.7711; com.oF2pks.applicationsinfo vs de.cweiske.headphoneindicator 0.5360; com.oF2pks.applicationsinfo vs eu.quelltext.gita 0.5650; com.oF2pks.applicationsinfo vs org.billthefarmer.shorty 0.6182; com.oF2pks.applicationsinfo vs tk.al54.dev.badpixels 0.4875; de.cweiske.headphoneindicator vs eu.quelltext.gita 0.8759; de.cweiske.headphoneindicator vs org.billthefarmer.shorty 0.6605; de.cweiske.headphoneindicator vs tk.al54.dev.badpixels 0.7577; eu.quelltext.gita vs org.billthefarmer.shorty 0.6797; eu.quelltext.gita vs tk.al54.dev.badpixels 0.7574; org.billthefarmer.shorty vs tk.al54.dev.badpixels 0.5893.

### `recreate s100us` — sampled@100us (lower bound)

- Apps compared: `com.jeffliu.balancetheball`, `com.oF2pks.applicationsinfo`, `de.cweiske.headphoneindicator`, `eu.quelltext.gita`, `org.billthefarmer.shorty`, `tk.al54.dev.badpixels` (6).
- **Intersection: 75 methods.** Union of all app unions: 1354.
- Per-app union sizes: `com.jeffliu.balancetheball` 229, `com.oF2pks.applicationsinfo` 1099, `de.cweiske.headphoneindicator` 329, `eu.quelltext.gita` 230, `org.billthefarmer.shorty` 254, `tk.al54.dev.badpixels` 195.
- Pairwise Jaccard between app unions: com.jeffliu.balancetheball vs com.oF2pks.applicationsinfo 0.1264; com.jeffliu.balancetheball vs de.cweiske.headphoneindicator 0.2653; com.jeffliu.balancetheball vs eu.quelltext.gita 0.3266; com.jeffliu.balancetheball vs org.billthefarmer.shorty 0.3343; com.jeffliu.balancetheball vs tk.al54.dev.badpixels 0.3333; com.oF2pks.applicationsinfo vs de.cweiske.headphoneindicator 0.1851; com.oF2pks.applicationsinfo vs eu.quelltext.gita 0.1577; com.oF2pks.applicationsinfo vs org.billthefarmer.shorty 0.1973; com.oF2pks.applicationsinfo vs tk.al54.dev.badpixels 0.1451; de.cweiske.headphoneindicator vs eu.quelltext.gita 0.2619; de.cweiske.headphoneindicator vs org.billthefarmer.shorty 0.3013; de.cweiske.headphoneindicator vs tk.al54.dev.badpixels 0.3717; eu.quelltext.gita vs org.billthefarmer.shorty 0.4152; eu.quelltext.gita vs tk.al54.dev.badpixels 0.3666; org.billthefarmer.shorty vs tk.al54.dev.badpixels 0.4075.

### `startprof full` — exhaustive (overflow NOT verifiable: continuous layout carries no flag) — unverifiable

- Apps compared: `com.oF2pks.applicationsinfo`, `eu.quelltext.gita` (2).
- **Intersection: 5767 methods.** Union of all app unions: 9162.
- Per-app union sizes: `com.oF2pks.applicationsinfo` 8904, `eu.quelltext.gita` 6025.
- Pairwise Jaccard between app unions: com.oF2pks.applicationsinfo vs eu.quelltext.gita 0.6294.

### `teardown full` — TRUNCATED (data-file-overflow in 1/3 run(s)) — lower bound

- Apps compared: `com.oF2pks.applicationsinfo`, `de.cweiske.headphoneindicator`, `eu.quelltext.gita`, `org.billthefarmer.shorty`, `tk.al54.dev.badpixels` (5).
- **Intersection: 1556 methods.** Union of all app unions: 4011.
- Per-app union sizes: `com.oF2pks.applicationsinfo` 3496, `de.cweiske.headphoneindicator` 1882, `eu.quelltext.gita` 1883, `org.billthefarmer.shorty` 2492, `tk.al54.dev.badpixels` 1898.
- Pairwise Jaccard between app unions: com.oF2pks.applicationsinfo vs de.cweiske.headphoneindicator 0.4469; com.oF2pks.applicationsinfo vs eu.quelltext.gita 0.4777; com.oF2pks.applicationsinfo vs org.billthefarmer.shorty 0.5934; com.oF2pks.applicationsinfo vs tk.al54.dev.badpixels 0.4384; de.cweiske.headphoneindicator vs eu.quelltext.gita 0.8844; de.cweiske.headphoneindicator vs org.billthefarmer.shorty 0.6063; de.cweiske.headphoneindicator vs tk.al54.dev.badpixels 0.9052; eu.quelltext.gita vs org.billthefarmer.shorty 0.6435; eu.quelltext.gita vs tk.al54.dev.badpixels 0.8580; org.billthefarmer.shorty vs tk.al54.dev.badpixels 0.6028.

## Teardown confound, per app

`R minus C` is the set difference: methods the `recreate` window counted
that a creation-only window did not. It is an **upper bound** on the teardown
contribution — the `create` window is a *warm* re-creation, so cold-start-only
methods present in `R` are attributed to teardown too.

| package | recreate R | create C | idle | teardown (BACK) | R minus C | share of R |
|---|---|---|---|---|---|---|
| `com.oF2pks.applicationsinfo` | 6569 | 2269 | 151 | 3496 | **4574** | 69.6% |
| `de.cweiske.headphoneindicator` | 4432 | 1770 | 91 | 1882 | **2692** | 60.7% |
| `eu.quelltext.gita` | 4638 | 2437 | 91 | 1883 | **2531** | 54.6% |
| `org.billthefarmer.shorty` | 6263 | 2327 | 138 | 2492 | **3964** | 63.3% |
| `tk.al54.dev.badpixels` | 3875 | 2900 | 91 | 1898 | **1645** | 42.5% |

Not comparable — no usable `create` run for: `com.jeffliu.balancetheball`. See the failed-capture table.

## Provenance

| package | apk sha256 | component |
|---|---|---|
| `com.jeffliu.balancetheball` | `6180534b151e4d50365b21483f3719e32f207a42675dee20227de449c875c1e2` | `com.jeffliu.balancetheball/.GameActivity` |
| `com.oF2pks.applicationsinfo` | `c0188f5f1f566e12324bd6bf4bf4f1b9408d852c6cc6b113706503031f13eebd` | `com.oF2pks.applicationsinfo/.MainActivity` |
| `de.cweiske.headphoneindicator` | `816e49cacfe137c91929a3983a0418fccd8c15c9e94fdb8a58b245f3bc262fb5` | `de.cweiske.headphoneindicator/.MainActivity` |
| `eu.quelltext.gita` | `1dc68f1ff0bff92408dc8b472c2afafec2f45cabb269a0a10cb4222d34b8d8cb` | `eu.quelltext.gita/.activities.ChooseChaptersActivity` |
| `org.billthefarmer.shorty` | `0fb027c3b436f0b335d6c7397539fcbf25fd683688c893a9d494ff43e0c1f4b3` | `org.billthefarmer.shorty/.MainActivity` |
| `tk.al54.dev.badpixels` | `43842c079c9f8cde375dc4a25ad62f7cd39237b4dcbf5ddbbb45738a620dd82f` | `tk.al54.dev.badpixels/.MainActivity` |

