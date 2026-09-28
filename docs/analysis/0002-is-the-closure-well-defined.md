# 0002 — Is the closure well-defined?

**Agent 15 · threat-to-validity resolution for the host-synthesis plan**

Every number below carries a tag.

* **[measured]** — read directly off a capture, or counted in a file.
* **[derived]** — a computation over measured values, reproducible by
  `node run-analysis.mjs` and pinned by `closure.test.mjs`.
* **[conjecture]** — not measured here; an interpretation, labelled as one.

Reproduce with:

```sh
cd docs/analysis
node run-analysis.mjs          # writes data/figures.json
node --test closure.test.mjs   # pins every figure quoted below
```

The captures themselves are not committed. `data/manifest.json` records the
SHA-256 of every byte this analysis consumed, and `run-analysis.mjs` refuses to
proceed if a file's hash does not match.

---

## 0. The short answer

**"The closure of app A" is a set, not a distribution — conditional on a pinned
window and entry state — and the evidence that it looked like a distribution was
an artefact of the instrument.**

Three independent cold starts of gita captured at a matched configuration and an
adequate sample budget report **4,649 / 4,649 / 4,648** distinct framework
methods. Mean pairwise Jaccard between them: **0.99986**, minimum pair 0.99979.
Spread across the three runs: **one method**. **[derived]**

The same app captured the way the original captures were taken reports
206–395 methods with a mean pairwise Jaccard of 0.441. That number is real — it
is exactly reproduced by a *measurement null* in which the app is held perfectly
constant — but it measures the sampler, not the app. **[derived]**

The two are reconciled by one fact: **the low-budget captures see 4.4%–8.5% of
the closure; a memoryless sampler at the same budget would see 10.6%.**
**[derived]**

Independently confirmed (§2.5): a concurrent agent measuring 24 apps by
*exhaustive* tracing — a different route with no sampling in it at all — puts
those same four apps at 9.1×, 13.8×, 14.6× and 19.0× the brief's figures.
**The brief's ground truth was low by an order of magnitude, and two agents
found that independently.**

The threat this document was commissioned to resolve is real but is not the
threat that was feared. It is not "we cannot separate the substrate from the
app". It is **"our ground-truth instrument was sampling 4–9% of the thing it
was supposed to measure"** — and that failure is invisible in the data it
produced, because a badly sampled set is indistinguishable from an unstable one.

There is a second, real dependency, and it is not nondeterminism either: the
closure is a function of **the app's persistent state**. gita with an empty
database has a closure of 1,853 methods; the same binary with a populated
database has 4,649. Jaccard between the two states: 0.3869, and both are
individually reproducible (J = 0.9845 within the empty state, 0.99986 within
the populated one). **[derived]**

---

## 1. What was actually measured, and what it says

### 1.1 The captures

Every cell below is **[measured]** except the sampling interval, which is
**[derived]** from the window and the sample count.

| app | runs | records/run | window (ms) | sampling interval (ms) | threads |
|---|---|---|---|---|---|
| gita (low) | 6 | 915–1,591 | 1,985–7,129 | 22.6–83.9 | 6–9 |
| balancetheball | 2 | 5,450–5,486 | 6,241–6,326 | 17.1 / 17.1 | 8 / 11 |
| headingcalculator | 3 | 648–782 | 993–6,322 | 15.8–118.5 | 6–8 |
| badpixels | 3 | 392–563 | 6,153–6,169 | 111.9–143.1 | 7 |
| **gita (high, matched)** | **3** | **496,189–512,758** | **6,191–6,245** | — | 6–7 |
| gita (empty database) | 2 | 96,644–96,713 | 6,197–6,210 | — | — |

Three captures were lost before this analysis began. They are recorded as lost,
not imputed: `cand_com.jeffliu.balancetheball_2.trace`, `/tmp/clean.trace` and
`/tmp/gita_full.trace` are all **0 bytes**. **[measured]** balancetheball
therefore has n = 2, not 3, and every balancetheball figure below rests on a
single pair.

A parser cross-check that validates the whole decode: ART writes one 14-byte
record per method event and counts them in the header as `num-method-calls`.
The decoded record count equals the header count in **21 of 21** captures
without exception. **[derived]** A record layout that were wrong could not
reproduce that.

### 1.2 The low-budget arm, as originally reported **[derived]**

| app | per-run sizes | union | intersection | mean pairwise J | 95% CI | sd(J) |
|---|---|---|---|---|---|---|
| gita | 206, 323, 325, 395, 331, 333 | **683** | 112 | **0.4411** | [0.4111, 0.4697] | 0.0600 |
| balancetheball | 274, 335 | 403 | 206 | 0.5112 | — (n=1 pair) | — |
| headingcalculator | 199, 242, 219 | 355 | 104 | **0.4498** | [0.3887, 0.5155] | 0.0635 |
| badpixels | 192, 145, 158 | 265 | 110 | **0.5264** | [0.4706, 0.5699] | 0.0508 |

gita's marginal-addition curve, runs added smallest-first:
**206, 397, 490, 566, 617, 683**. **[derived]**

**Reconciliation with the figures this work was commissioned against.** The
brief reported per-app closures of gita 628, balancetheball 373,
headingcalculator 338, badpixels 242, a gita mean pairwise Jaccard of 0.451,
and a gita curve of 199, 366, 450, 545, 583, 628. I could not reproduce those
numbers from the files those claims were attributed to. My per-app unions are
683 / 403 / 355 / 265 and my gita mean Jaccard is 0.4411, not 0.451. The
*phenomenon* reproduces closely and the *shape* of the curve reproduces
(199→628 vs 206→683; increments 167, 84, 95, 38, 45 vs 191, 93, 76, 51, 66), but
the individual values do not match under any filter I tried — all methods,
excluding D8 synthetic classes, excluding the app's own package, and deduplicating
by class+name rather than class+name+signature. All three variants land within
1% of each other and none lands on 628.

I report my numbers and flag the discrepancy rather than adopting either set.
One plausible mechanism, offered as **[conjecture]**: a size-ordered union curve
is order-dependent, so a different run ordering or a different set of surviving
captures produces a different curve of the same shape; the brief's first value,
199, is exactly headingcalculator's first run, not gita's, which suggests the two
figures came from different capture sets.

### 1.3 The high-budget arm: three matched runs **[derived]**

| | run 1 | run 2 | run 3 |
|---|---|---|---|
| records | 512,758 | 504,552 | 496,189 |
| window (ms) | 6,216 | 6,191 | 6,245 |
| distinct methods | **4,649** | **4,649** | **4,648** |

* union over the three: **4,649**
* intersection over the three: **4,648**
* pairwise Jaccard: 1.000000, 0.999785, 0.999785 → mean **0.999857**
* variance of the per-run count: **0.333 methods²** (sd 0.577 methods)
* spread: **1 method in 4,649, i.e. 0.021%**

This is the number that answers the commission. Run-to-run instability at an
adequate sample budget is **one method**, not 550.

### 1.4 The measurement null: the app held constant **[derived]**

Take *one* high-budget run. Resample it. Nothing about the app changes, the
window is unchanged, the sampler rate is unchanged. Vary only which stacks the
sampler lands on.

| budget (records) | null J (resample) | null \|S\| | null J (phase-only) | null \|S\| | **observed low-budget J** | observed \|S\| |
|---|---|---|---|---|---|---|
| 915 | 0.3067 ± 0.0161 | 454 ± 13 | 0.3119 ± 0.0228 | 465 ± 10 | **0.4411** | 206–395 |
| 1,300 | 0.3552 ± 0.0147 | 570 ± 15 | 0.3783 ± 0.0272 | 562 ± 12 | — | — |
| 1,591 | 0.3820 ± 0.0136 | 642 ± 16 | 0.3863 ± 0.0230 | 647 ± 13 | — | — |

With the app frozen, two captures at the real runs' budget share **31–39%** of
their method sets, against the observed 44%. **The instability is reproduced
without the app doing anything differently at all.** **[derived]**

### 1.5 The mechanism: the sampler aliases against the app's own cadence **[derived]**

Same 2 seconds of the same run, same 915 events selected, two selection rules.

| selection rule | \|S\| | sd | mean pairwise J | sd(J) | union over 12 draws |
|---|---|---|---|---|---|
| periodic, 1 ms | 184.4 | 47.6 | 0.5652 | 0.1400 | 311 |
| periodic, 10 ms | 158.8 | 34.6 | 0.4123 | 0.3082 | 432 |
| **periodic, 35 ms** (the real cadence) | **187.1** | **60.2** | 0.4873 | 0.2861 | **427** |
| periodic, 350 ms | 175.4 | 40.8 | 0.3357 | 0.3902 | 799 |
| **memoryless (random)** | **473.3** | **8.2** | 0.3192 | 0.0143 | **1,564** |

A periodic sampler at the real cadence sees **2.5× fewer methods** than a
memoryless one at the identical budget, and twelve different sampling phases
cover **427** methods where twelve memoryless draws cover **1,564**. The pool
available in that window is 4,365.

**How much of the observed sizes this accounts for — and how much it does
not.** The low-budget captures reported 206, 323, 325, 331, 333, 395
(median 331). The periodic model at their budget predicts 187 ± 60 and the
memoryless model 473 ± 8. The observed median is **1.77× the periodic
prediction and 0.70× the memoryless prediction** — it falls between the two.
The smallest observed run (206) is 1.10× the periodic mean, but the largest
(395) is **3.45 sd above** it, outside even the 2 sd band.

So: aliasing is **measured**, its direction and magnitude are known (a 2.5×
downward bias, a 3.7× reduction in what N runs can reach), and it is the
mechanism with the right sign. But at n = 6 it does **not** account for the
upper half of the observed size range, and I am not going to claim it does. Two
things it cannot explain, and which remain open: the largest three runs
(331, 333, 395) and the fact that §1.4's *resample* null — which has no
aliasing at all — still under-predicts the observed 0.441 (it gives 0.31–0.38).
The honest summary is that aliasing plus budget account for the bulk of the
instability and leave a residual of roughly a factor of 1.7 in |S| and about
0.06–0.13 in Jaccard unexplained.

The app's side of the aliasing **[conjecture]**: after detrending the
main-thread call density with a 25 ms moving average, all three high-budget runs
show a residual periodicity at **43–58 ms** (peak autocorrelation 0.115, 0.184,
0.208 in the three runs) and a *negative* autocorrelation at 16–17 ms (−0.257,
−0.183, −0.180), which is the signature of a signal with a period near twice
that lag. The low-budget captures' sampling intervals are 22.6–143.1 ms, i.e.
the same range. I am **not** claiming the app has a 50 ms clock: the period
varies by 15 ms between runs and the peak is weak, and raw autocorrelation
without detrending decays monotonically and is not evidence of anything. The
aliasing *effect* is measured by the selection experiment above; its attribution
to a specific app-side clock is not.

### 1.6 Why the low-budget sizes track the budget so exactly **[derived]**

Regressing log(size) on log(records) across the runs of one app:

| app | R² |
|---|---|
| gita (n=6) | **0.9635** |
| headingcalculator (n=3) | 0.9059 |
| badpixels (n=3) | 0.7167 |
| balancetheball (n=2) | not defined — 2 points always fit exactly |

**96.4% of the run-to-run variance in the size of gita's reported closure is
explained by how many stack records the sampler happened to collect.** The record
count is fixed by the instrument's interval and the window, and is determined
before the app's method set is observed, so this is a causal decomposition rather
than a correlation.

Absolute: gita's per-run size variance is **3,787 methods²** (sd 61.5) at low
budget and **0.333 methods²** (sd 0.577) at high budget — a factor of **11,400**
reduction from changing only the sampling rate.

### 1.7 Which framework calls are volatile, and why **[derived]**

Per-category mean pairwise Jaccard across the low-budget runs, gita:

| category | per-run counts | mean J | 90% range | variance | R² (budget) | unexplained |
|---|---|---|---|---|---|---|
| animation (Choreographer, ThreadedRenderer, ViewRootImpl, hwui) | 48, 46, 49, 45, 49, 47 | **0.742** | 0.67–0.85 | 2.7 | 0.172 | 2.2 |
| gc (java.lang.ref.*, System.gc) | 2, 2, 3, 2, 2, 2 | 0.889 | 0.67–1.00 | 0.2 | 0.009 | 0.2 |
| classload | 2, 4, 7, 8, 5, 4 | 0.579 | 0.27–0.91 | 4.8 | 0.535 | 2.2 |
| looper_msg (ActivityThread, Looper, servertransaction) | 42, 35, 39, 45, 30, 37 | 0.607 | 0.54–0.72 | 28.0 | **0.039** | 26.9 |
| binder_ipc (Binder, IBinder, Parcel) | 7, 8, 5, 4, 6, 2 | 0.426 | 0.21–0.68 | 4.7 | 0.170 | 3.9 |
| **resource_inflate** (content.res, Resources, Context.get*) | **4, 18, 14, 30, 25, 21** | **0.183** | 0.00–0.35 | 82.3 | **0.953** | 3.9 |
| other | 101, 208, 208, 261, 214, 219 | 0.380 | 0.26–0.48 | 2,837 | **0.955** | 129 |

The picture is clean and it is the opposite of "the platform is nondeterministic":

* **The render pipeline is the most reproducible thing in the system.** 48, 46,
  49, 45, 49, 47 methods across six cold starts — a coefficient of variation of
  0.03 and a Jaccard of 0.742. Choreographer, ThreadedRenderer and hwui do the
  same work every time. Whatever nondeterminism Android has, it is not here.
* **GC is reproducible too**: 2–3 methods, J = 0.889.
* **The volatility is concentrated in resource inflation and Binder/Parcel** —
  exactly the subsystems whose method count scales with how many resources and
  IPC transactions were actually processed.
* **But that volatility is 95% explained by the sample budget** (R² = 0.953 and
  0.955). That the app inflated the *same* resources each time is
  **[conjecture]** — I never observed a run's inflation independently of the
  sampler, so I cannot rule out that the app really did inflate fewer of them.
  What is measured is that the count of observed inflation methods scales with
  the record budget at R² = 0.953, which is what a fixed work load under a
  varying sampler would also produce. badpixels makes the
  failure mode explicit: **0 resource-inflation methods observed in one run**,
  7 in another, mean J = 0.000. A whole subsystem went missing from a capture.
* The only category with substantial *unexplained* variance is `looper_msg`
  (variance 28.0, R² = 0.039, unexplained 26.9) — small in absolute terms, and
  it is the handler-dispatch path, which is where a genuinely different message
  ordering would show up. I would not build anything on n = 6.

### 1.8 The app's own code is nearly invisible at the low budget **[derived]**

**[derived]** gita's own methods observed per run: **0, 2, 1, 4, 4, 4** at low budget;
**10, 10, 10** at high budget. Other apps: balancetheball 6, 6;
headingcalculator 2, 4, 2; badpixels 1, 0, 0. One of the six gita low-budget
captures (run 1) contains **no gita method at all**, and one badpixels capture
contains none either. An analysis that concluded "this app
does not use X" from those captures would be reasoning about the sampler.

---

## 2. The convergence verdict, with a number

### 2.1 Does a finite asymptote exist? **[derived]**

**Yes, and it is small, and it is reached.** For (gita, populated database,
6.2 s window, this device state) the closure is **4,649 methods**, and the
uncertainty on that number from run-to-run variation is **±1 method**.

One clarification of terms before the table. The **pool** — 4,649 / 4,649 /
4,648, the method table ART itself wrote for each run — is **[measured]**: it is
what that run demonstrably executed at that sampling rate. The **closure** is
the **[derived]** claim that the pool is the whole of what the program executed
in the window. The first is a fact; the second is a conclusion, and the whole
question is whether the conclusion is warranted.

The approach to the pool, measured three independent ways, agreeing throughout:

| budget (distinct records sampled memorylessly) | run 1 | run 2 | run 3 | spread | fraction of pool |
|---|---|---|---|---|---|
| 125 | 105 | 104 | 104 | 1 | 2.2% |
| 500 | 322 | 328 | 325 | 6 | 6.9% |
| **915** (the real low-budget budget) | **496** | **491** | **495** | **5** | **10.6%** |
| 2,000 | 778 | 780 | 778 | 2 | 16.8% |
| 8,000 | 1,457 | 1,453 | 1,448 | 9 | 31.3% |
| 32,000 | 2,297 | 2,299 | 2,292 | 7 | 49.4% |
| 128,000 | 3,494 | 3,497 | 3,496 | 3 | 75.2% |
| 256,000 | 4,191 | 4,211 | 4,219 | 28 | 90.2% |
| 400,000 | 4,561 | 4,575 | 4,581 | 20 | 98.3% |
| 480,000 | 4,642 | 4,644 | 4,645 | 3 | 99.9% |

The three independently captured runs produce saturation curves that agree to
within 2.1% at every budget (worst case, N = 250), and their *full* pools agree
to within one method. The curve flattens into the pool rather than diverging: at
480,000 records — 94% of the run's records — the observed set is within 3 to 7
methods of the pool.

**Answer to the question as posed: the closure is not a distribution over runs,
and it is not non-converging. It is a set of 4,649 ± 1.** The budget needed to
see 90% of it is 256,000 records; to see 99% it is between 400,000 and 480,000.
The captures the project was working from had 915–1,591.

### 2.2 What the asymptote's uncertainty actually is **[derived]**

Two different uncertainties must not be conflated:

1. **Run-to-run: ±1 method** (sd 0.577 over three runs, 0.333 methods²). This is
   the quantity the commission asked about, and it is negligible.
2. **Window-and-state: ±2,796 methods.** The closure is *not* a single number
   for "gita". It is a number *per (window, database state)*:
   * 6.2 s window, populated database: **4,649**
   * 6.2 s window, empty database: **1,853 / 1,862** (two runs, J = 0.9845)
   * Jaccard between the two states: **0.3869**; intersection 1,814; union 4,688

   Both states are internally reproducible. **The 2.5× difference being a real,
   deterministic property of the app given its data is [derived]**: I can show
   each state is reproducible and that they differ, but with two runs per state
   I cannot separate "the app did more work" from "the empty-database run was
   also sampled more thinly" — the empty-state runs collected 96,644–96,713
   records against the populated state's 496,189–512,758, and that difference
   is confounded with the state itself. The direction of the bias is known
   (thinner sampling can only understate), so the populated closure of 4,649 is
   the safer number of the two. It is also a **2.5× larger synthesis target** for
   the same binary.

Uncertainty (2) dominates uncertainty (1) by three orders of magnitude. A
synthesizing compiler that targets "the closure of app A" without pinning the
window and the entry state is targeting a number that is wrong by up to 60%
before any nondeterminism enters — and the window axis has not been swept at
all: the only window length measured at high budget is 6.2 s.

### 2.3 Finiteness has an arithmetic bound too **[measured]**

The universe is finite and countable without running anything: the 37 jars in
`/system/framework/*.jar` on this Android 13 arm64 image contain **411,072
`method_id` entries** across **43,137 `class_def`s** (framework.jar 250,010;
services.jar 111,264), read from each DEX header. gita's 4,649-method closure is
**1.13%** of that. So "the closure diverges" is not a live hypothesis: it is
arithmetically impossible. It is 1.13% of a countable universe.

```sh
for j in $(adb shell ls /system/framework/*.jar); do adb pull $j; done
# then, for each classes.dex in each jar, read the u32 at DEX offset 0x58
# (method_ids_size) and at 0x60 (class_defs_size), and sum
```

### 2.4 The experiment that would have settled it, and the one that would settle the rest

The decisive experiment was: **capture the same app, same window, same state,
three times, at a sample budget where the saturation curve has flattened.** That
is the `recreate` set, and it is what produced §1.3. It is worth recording that
the cheap version of this experiment — a handful of cold starts at the default
sampling rate — cannot distinguish "unstable closure" from "undersampled
closure", because both produce J ≈ 0.44. **The null in §1.4 is the minimum
control any future closure measurement needs**, and it costs nothing: resample
one existing capture and compute the Jaccard. If that number is not well below
the number you are about to report, you have measured your sampler.

What would still be open, and what would settle it: the closure of the other
three apps at an adequate budget. gita is measured; balancetheball (n=2),
headingcalculator (n=3) and badpixels (n=3) are **not**. §1.6 leaves one loose
end there: balancetheball's two runs have *identical* cadence (17.1 ms), *identical*
window and *identical* budget, and still differ by 61 methods (J = 0.511). One
pair is no evidence, but it is the only residual variation in this analysis that
budget-matching did not explain, and it deserves three more runs.

---

## 2.5 An independent measurement of the same thing, by a different route

While this analysis was running, a concurrent agent measured the framework
closure of **24 apps** by a different route: `am start-activity -S -W -P`, which
is ART's **buffered exhaustive tracing** (every method enter/exit, no sampling),
with `-S` forcing a cold start and `-W` stopping at the first frame. Its output
is in `measurement.json` in this directory. It is not my data, I did not
control it, and I did not check it before it corroborated me.

Its counts, filtered to `android.`, `java.`, `javax.`, `dalvik.` classes, over a
window it documents as *process start → first frame → idle* (so post-first-frame
settle work is included — a longer and less sharply bounded window than my fixed
6.2 s):

| app | brief's figure | exhaustive median | ratio | exhaustive spread over reps |
|---|---|---|---|---|
| gita | 628 | **5,722** | **9.1×** | 5,617–5,741 (124) |
| balancetheball | 373 | **5,132** | **13.8×** | 5,037–5,181 (144) |
| headingcalculator | 338 | **4,941** | **14.6×** | 4,600–5,021 (421) |
| badpixels | 242 | **4,588** | **19.0×** | 4,580–4,695 (115) |
| *all 24 apps* | — | min 3,731 / **median 6,070.5** / max 7,374 | — | — |

**Two independent agents, two different capture modes, and the brief's
ground-truth numbers are low by 9× to 19× on the four apps where both
exist.** That is the central claim of this document, arrived at twice. My
4,649 for gita and their 5,722 are the same measurement to within 19%, which is
what two different window definitions of the same quantity should look like.

**This also tempers §2.1, and the tempering matters.** Their gita runs span
5,617–5,741: **124 methods, 2.2%**, at *exhaustive* coverage. My three runs span
one method, 0.02%. Both can be right, and the difference is the window: theirs
is "start → first frame → idle", a boundary that moves with how long the app
takes to report idle; mine is a fixed 6.2 s. So:

* **Given a pinned window and entry state, the closure is a set and it is
  reproducible to ~0.02%.** **[derived]**
* **Given a window defined by a behavioural event ("first frame", "idle"), even
  exhaustive traces of the same binary differ by ~2%.** **[derived from
  `measurement.json`]**

The second is the honest version of the threat. It is not app nondeterminism in
the sense this commission meant — the app is not choosing differently, the
*stopping rule* is landing in different places. But for the project's purposes
it is just as damaging, because "run until the app is idle" is exactly the kind
of window definition a synthesising compiler would want to use, and it carries a
2% error. §5 develops this.

**One correction that belongs on the record.** That agent's `measurement.json`
documents the record format as *"14-byte records: tid:u16le,
(methodId<<2|kind):u16le, u32, u32, u16"*. Read literally, the method id is at
byte offset 2. It is not. On **its own** capture (`badpixels_r1.trace`, pulled
from the device to check) the u16 at offset 2 is **zero in 141,696 of 141,696
records**, so a literal reading of that schema yields method id 0 for every
record and a single-element method set. The layout that holds at 100.00% of
records on both its file and mine is:

```
offset 0   u16   method id, two flag bits in the low positions
offset 2   u16   always zero
offset 4   u32   thread-local time, us
offset 8   u32   global time, us
offset 12  u16   tid
```

**[measured]** The tid is at the *end*, not the start. Its reported numbers are
presumably fine — its code evidently reads the bytes correctly and only the
schema string is wrong — but the string is in the repository now, and anyone
implementing from it will get a degenerate result. Worth fixing at the source.

---

---

## 3. Separating the substrate from the app's own nondeterminism

The commission asked me to tell these apart. The answer is that for the
categories that dominate the reported variance, the split is:

| source | share of the observed run-to-run variance in reported \|S\| | evidence |
|---|---|---|
| **the instrument** (sampling budget) | **96.4%** | R²(log size ~ log records) = 0.9635, §1.6; and the null reproduces J = 0.31–0.39 with the app frozen, §1.4 |
| **the instrument** (sampler aliasing) | on top of the above, a 2.5× downward bias in \|S\| and a 3.7× reduction in what N runs can cover | the selection experiment, §1.5 |
| **the app's persistent state** | a 2.5× shift in \|S\| between two reproducible states | §2.2, J = 0.3869 across states, 0.9845–0.99986 within |
| **the app's own nondeterminism** | **≤ 0.021% of the closure (1 method in 4,649)** | three matched runs, §1.3 |
| **the platform's nondeterminism** | not separable from the above at this n. The render path — the part of the framework most under the platform's control — has variance 2.7 methods² against gita's total 3,787, i.e. **0.07% of the observed variance**, and a Jaccard of 0.742 | §1.7 |

The honest statement of the app/platform split: **with n = 3 matched runs I can
bound the combined app+platform nondeterminism at one method in 4,649, and I
cannot decompose it further into "app" and "platform" parts.** But the
decomposition that matters for the project is not app-versus-platform. It is
**app-state versus execution-nondeterminism**, and that one is settled: state
dominates by 3 orders of magnitude.

One caveat that cuts the other way and I will not bury: the low-budget captures
were *not* a matched set. Their windows ranged from 993 ms to 7,129 ms and their
sampling intervals from 15.8 ms to 143.1 ms. Part of the low-budget variance is
therefore a *design* variance (the captures were not comparable) rather than a
sampling variance, and the R² = 0.9635 attributes it to the record count, which
is a proxy for the interval. The 96.4% figure is an upper bound on the
instrument's share in the sense that the instrument set two things at once
(interval and budget) and I can only regress on one.

---

## 4. Consequence for host synthesis

The plan was: compute the transitive closure of framework surface an app needs,
generate exactly that, report the bound. Given §2, that plan is **sound in
principle and was being fed a number 12–23× too small** — the low-budget
captures reported 4.4% to 8.5% of gita's closure.

**What a synthesizing compiler must target, in order of preference:**

1. **A pinned (app, entry state, window) triple, measured at saturation.** The
   target is a set of 4,649 methods for gita-with-data, reproducibly. This is
   the good case, and it is the case the plan assumed.
2. **Not the cold-start window.** The 6.2 s window used here is 3× longer than
   "to first frame" and already yields 4,649. A first-frame window yields
   materially less. The activity is not uniform in time: the four quarters of the
   6.2 s window contain 3,624 / 2,937 / 368 / 62 methods, and their six pairwise
   Jaccards are 0.413, 0.125, 0.054, 0.019, 0.078, 0.015 — the third quarter of
   the window shares 5% of its methods with the first. **"To first frame" is a
   definition the project has to make explicit and then honour, because the
   closure is a function of it, and the marginal cost of a longer window is not
   small.** **[derived]**
3. **The worst case over entry states, if the app can be launched in more than
   one.** For gita that is 4,649 rather than 1,853 — a 2.5× cost. This is the
   only place in this analysis where a "worst case" target is actually required,
   and it is required by *data*, not by nondeterminism.
4. **Never a sample.** A single unsaturated capture understates the target by
   **12–23×** (§0). §1.5's twelve periodic draws covering 427 of 4,365 methods
   in the window is the concrete picture: N runs of a naive sampler do not
   converge to the closure, they converge to the sampler's alias set, and
   increasing N barely helps — the 12-draw union of a memoryless sampler reaches
   1,564 of 4,365 while the periodic one reaches 427.

**Cost.** Generating a host for 4,649 methods rather than 300 is a **15× larger
synthesis problem** for the same app. That is the real consequence of this
document: the project's own headline ground-truth numbers were low by more than
an order of magnitude, and every bound computed from them — every
"this app needs N framework methods" claim in the corpus analysis — is
correspondingly low. I have not audited those; that is a follow-up and it should
be done before any synthesis target is fixed.

**The approach is not dead.** The thing that would have killed it — "the closure
is a distribution, so no finite host can be synthesised" — is refuted. The closure
is a set. What is dead is the *measurement* that was being used to estimate it.

---

## 5. The single strongest reason to distrust this measurement

**Everything above rests on one undocumented decision: what "the same app, the
same run" means when the capture starts and stops.**

The high-budget number — 4,649 ± 1 — is a statement about *a 6.2-second window
that begins 3 seconds after the app was told to settle, on a database that
already had content.* It is reproducible because the harness is deterministic
about that window.

It is reproducible *because* the window is pinned, and the window is the only
part of this that is arbitrary. §2.5 shows how much the unpinned version costs:
the concurrent agent's exhaustive traces, whose window is defined behaviourally
("stop when the app reports idle") rather than by a clock, span **124 methods
(2.2%) across three runs of the same binary at exhaustive coverage** — against
my one method. The behaviourally-defined window is the one a synthesising
compiler would actually want, and it carries a 2% error that a clock-pinned
window hides completely. §2.2 shows a third axis, the app's database state, that
moves the answer by 2.5×.

So the claim I am confident in is narrow: **for a pinned (app, entry state,
window) triple, the closure is a set, reproducible to ~0.02%.** The claim a
reader will *want* — "the closure of gita is N methods" — is not supported, and
three different reasonable definitions of the window give 1,853, 4,649 and
5,722.

The runner-up, which I would also take seriously **[conjecture, about my own
inference rather than about the platform]**: the 14-byte record format was
recovered by inference, not from a specification, and I found it by fitting
structure to bytes. The evidence that it is right is that decoded record counts
match ART's own `num-method-calls` in 21 of 21 files and every method id resolves
into the file's own method table — but if ART emitted a *second*, differently
encoded class of record in some other capture, I would not detect it, and the
method sets here would be a subset of the truth. The same inference produced the
~4,649 figure and the 1-method reproducibility, so an error there would not be
visible as instability; it would be invisible.

---

## Appendix — files

| path | what |
|---|---|
| `run-analysis.mjs` | produces every figure; verifies each capture's SHA-256 first |
| `lib/arttrace.mjs` | ART trace decoder (14-byte record layout, asserted) |
| `lib/closure.mjs` | the experiments: per-app distribution, nulls, saturation, categories |
| `lib/stats.mjs` | Jaccard, bootstrap, saturation fits, seeded PRNG |
| `data/manifest.json` | every capture, with SHA-256, plus the three lost captures |
| `data/figures.json` | every number in this document, machine-readable |
| `closure.test.mjs` | pins every figure quoted above |
