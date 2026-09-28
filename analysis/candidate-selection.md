# Which predictive signals mattered for choosing a first subject

Companion to [`candidates.md`](candidates.md), which holds the shortlist and the
recommendation. This file records **which signals earned their place and which
were noise**, over a 200-APK measurement.

The brief asked for this explicitly, and added: *"Being wrong here is a useful
result."* So the failures are the point, and they are given the same weight as
the successes.

---

## 1. Signals that decided the outcome

### 1.1 `straySharedObjects` — the whole ballgame

**The single most valuable field in `corpus/survey.jsonl`, and it is one boolean
away from being missed.** `corpus/survey.jsonl` has two native-code signals:
`hasNativeCode` (the `lib/<abi>/` test) and `straySharedObjects` (`.so`-named
entries anywhere else). Six corpus rows ship a `.so` outside `lib/`; five are
Chaquopy runtimes and bundled `llama.cpp`, already caught by `hasNativeCode`.
The sixth is `org.bitbucket.watashi564.combapp`, which `hasNativeCode` calls
clean and which ships a 7.3 MB and a 17.8 MB ELF at `res/5x.so` and `res/yG.so`.

Filter on `hasNativeCode` and you ship a Python/ELF app to a bytecode-only
substrate. Filter on both and the census is sufficient — no archive inspection
needed for this particular trap.

**Generalisable:** a "does it have native code" signal is a claim about *where
you looked*, not about *what is there*. Two fields that answer the same question
at different scopes are not redundant; the narrower one is the dangerous one,
because its name matches the question.

### 1.2 `dexBytes` — the pool, and nothing else

DEX size did exactly one job: it *defines the pool*. The 200 smallest of 213
surviving rows are the measurement set, and the ordering within that set decides
nothing — the **top candidate has the largest DEX of the top 12** (24,897 bytes
against a 3,025-byte minimum), and would not have been in the pool at all under a
"smallest 50" cut.

That is a clean separation worth stating: `dexBytes` is an excellent
**exclusion** criterion and an actively misleading **ranking** criterion. The
third-smallest app in the pool (`S.N.A.K.E`, 3,025 B, 17th smallest of 200) has
40 framework method references to gita's 17, from 9 declared methods.

### 1.3 The manifest — 3 of 4 launch-path gates came from here

The DEX knows nothing about components. Of 181 rejections, **87 declare a
`Service`, 79 a `receiver`, 26 a `provider`** — 116 rejections from background
lifecycle alone, and they cost one `AndroidManifest.xml` parse.

**116** of the 200 measured apps declare at least one of the three (87 service,
79 receiver, 26 provider; a row may trip more than one).

The manifest also produced the three gates that removed the *individually
best-scoring* candidates, which is the part that mattered:

| gate | removed | because |
|---|---|---|
| `layout_onclick_reflective_dispatch` | 45 | `android:onClick` is framework-side reflection, invisible in the app's DEX |
| `text_field_on_launch_path` | 73 | the first visible break is a soft keyboard the substrate cannot produce |
| `special_permission:…` | 20 | protocol §3.5's "requires a role we do not grant", same shape |

**Generalisable:** for a first subject, *what the app is declared to be* predicts
difficulty better than *what its bytecode touches*. A `Service` is a background
lifecycle; a text field is a keyboard; `SYSTEM_ALERT_WINDOW` is a grant. None of
that is visible as a framework method reference.

### 1.4 `android.* types referenced` — the primary signal, confirmed

The brief nominated this and it held up. The eligible 19 span 14 to 132 distinct
`android.*` types; the top 12's median is 22. The correlation is not an artefact
of the rubric, which weights this component 0.28: it also predicted the
hand-verified framework increment. gita needs 6 classes and 10 methods;
`anupam.acrylic` needs 110 classes and 173 methods.

### 1.5 Taxonomy class, not taxonomy count

The count alone is nearly useless: the top 12 all trip 3–12 IDs, and the
*count* correlates with app size rather than with risk. The **class** is the
signal, and only two classes matter for a first subject:

* `REFUSE` means the app will not start, so the ladder stops at rung 0 and there
  is nothing to observe.
* `MISBEHAVE` is the class the project ultimately cares about, but a first
  subject cannot demonstrate it — there is no ground truth to be silently wrong
  about yet.

Weighting `REFUSE` 1.0 / `MISBEHAVE` 0.6 / `DEGRADE` 0.3 is what separated
`com.jeffliu.balancetheball` (3 `REFUSE`-class IDs, ranks 3rd) from
`eu.quelltext.gita` (0, ranks 1st). Without the taxonomy component at all,
balancetheball ranks **1st** — see `candidates.md` §2.1.

### 1.6 Shim method coverage, as a separate signal from surface size

`shim/CONFORMANCE.md`'s 27.4% method coverage is the real constraint, and
"how many framework methods does the app touch" is not the same question as "how
many of them exist". `S.N.A.K.E` is the case that proves it: fewest
`android.*` types in the pool (14), fewest declared methods (9), 3rd-smallest
DEX (3,025 B) — and **34 of its 40 framework methods have no same-named shim
method**, the worst gap in the top 12. It ranks 5th.

---

## 2. Signals that were noise

### 2.1 `reflection_call_sites` — the DEX signal is structurally blind

This was the surprise, and it is the most useful negative result here.

`analysis/prediction.md` reports reflective call sites at 95.8% prevalence and
weights them in its rubric. For *selection* the signal is close to worthless, and
here is why: **reflection the framework performs on an app's behalf does not
appear in the app's DEX at all.**

`android:onClick` is the clean case. `LayoutInflater` wraps the view in a
`DeclaredOnClickListener` that calls `getMethod(name)` on the context's class.
`com.tmendes.dadosd` reports `reflection_call_sites = 0` and binds three of them
— two `Button`s and one `ImageView` in `res/layout/activity_main.xml`.

So a substrate must implement a reflective member lookup over the app's classes
for an app that a DEX-only reflection count certifies as reflection-free. Among
the 200 measured, **45 apps bind `android:onClick`**; of those, **15 report no
reflective call site at all** and 20 report at most one.

**Generalisable:** a static reflection count measures the app's *use* of
reflection, not the framework's use of the app. Any selection rule keyed on it
is measuring the wrong side.

### 2.2 `minSdk` — no signal at all

The brief expected lowish `minSdk` to correlate with less modern API use. It does
not, in this pool. The winner declares `minSdk 1`; ranks 1–6 span
`minSdk 1, 8, 14, 16, 24, 14`, and the *worst* candidate in the top 12 by
`android.*` surface (`anupam.acrylic`, 132 types) declares `minSdk 14` — the
same as `com.jeffliu.balancetheball` at rank 3, which needs 27 framework methods
to gita's 17.

What `minSdk` *does* predict is nothing about framework surface and something
real about the **oracle**: `targetSdk` 28 for gita, against a modern reference
image. That is a different question from the one asked, and it is now a risk to
state rather than a ranking input.

### 2.3 `entryCount` and `dexCount` — redundant with `dexBytes`

`dexCount` is **1 for all 200** — the pool contains no multidex app at all, so
the field has no variation and cannot rank anything. `entryCount` correlates with
resource count, not with framework surface. Neither moved the ranking.

### 2.4 `dexUncompressedBytes` — same ordering as `dexBytes`

The ratio ranges 1.0–4.7× (1.0 being a stored, uncompressed DEX) and reorders
nothing. Not used.

### 2.5 The predictor's band and score — unusable as-is

`analysis/prediction.md` §4.2 reports `REFUSE 119/120 = 99.2%`. On the corrected
opcode constants, this pool measures:

```
REFUSE 0/200   DEGRADE 0/200   LIKELY_RUNS 0/200   MINIMAL 200/200
```

The predictor's band has **no resolution in this stratum** — `MINIMAL 200/200`,
zero in every other band. It is a valid measurement (nothing here has native code,
GMS, or `invokedynamic`) and a useless ranking signal. Its continuous
`score_0_100` does still vary, over 0.0–15.5 — gita 0.0, balancetheball 1.0 — but
on a rubric whose four largest weights are gates that cannot fire, so the
variation comes entirely from the three smallest.

**Generalisable:** a band that is constant across the population being chosen
from carries no information *for that choice*, however correct it is in
absolute terms. Report it; do not rank on it.

### 2.6 `taxonomy_hits` count, as distinct from class

Covered in §1.5. The count tracks app size.

---

## 3. Two bugs the predictor's history predicted, found in my own code

The brief warned that the predictor had produced "a 68.3% headline that was
actually 1.7%" from a mislabelled opcode, and said to verify anything relied on.
Verifying paid for itself: **the same class of bug appeared three times in the
selection code, each time producing a confident wrong number rather than a
crash.** All three are worth recording because the failure mode is the point —
none of them threw, and each would have quietly changed the answer.

### 3.1 The `method_id` owner is the compile-time receiver, not the declaring class

`eu.quelltext.gita` calls `setContentView` **twice** — in
`ChapterActivity.onCreate` and `ChooseChaptersActivity.onCreate` — and the DEX
records both as:

```
invoke-virtual v3, v4, Leu/quelltext/gita/activities/ChapterActivity;->setContentView(I)V
```

The owner is the *app's own class*, because the method is inherited from
`Activity` and the compiler emitted the subclass. A render signal anchored on
`^Landroid/` scored this app **0** `setContentView` sites. It was in the
shortlist anyway, on the strength of two `inflate` sites — i.e. for the wrong
reason, and the published `setContentView = 0` was false.

The same trap in the other direction: `org.debian.eugen.headingcalculator` wires
its 16-button keypad with
`Landroid/widget/Button;->setOnClickListener(...)`, so a signal anchored on
`Landroid/view/View;` reported **zero** clickable views for an app that is
nothing but buttons.

Fix: match on the **member name**, and anchor on the owner class only where the
owner cannot be the app's own — that is, where the platform declares the class
(`LayoutInflater`, `Canvas`).

This is also a **standing measurement limitation**, not just a bug I fixed. It
means `distinctAndroidMethods` understates the surface of every app, by the
number of inherited framework methods called through app subclasses. For gita
that is six: `setContentView`, `findViewById`, `getIntent`, `getSystemService`,
`getStringResourceByName`, `getTitle`. Five of the six are shim-implemented, so
its coverage figure survives; in general it would not.

### 3.2 A reference-format mismatch that returned zero matches

`analysis/src/dexscan.rs` emits `L<class>;.member(args)ret` — semicolon, then
**dot**. `dexcore`'s human-readable dumps use `L<class>;->member(args)ret`. A
matcher written for one form returns **no matches at all** for the other, every
count is 0, and the consequence is a confident "this app has no render call
site". Both forms are now accepted, and the shape is asserted.

### 3.3 A key-spelling drift that produced `NaN`

`RENDER_SIGNATURES` declared keys `set_content_view`/`layout_inflate`/
`canvas_draw`; the accumulator was initialised with `setContentView`/
`layoutInflate`/`canvasDraw`. `undefined + n` is `NaN`, `JSON.stringify` renders
`NaN` as `null`, and the render gate then rejected **all 200** candidates with a
well-formatted "no render call site". Fixed by deriving the accumulator from the
signature table so the two cannot disagree, plus an explicit finiteness check.

### 3.4 The one that was caught by an independent re-implementation

`analysis/tests/figures.rs` re-derives the gate histogram in Rust rather than
reading a stored number. Its first version of the `text_field_on_launch_path`
gate checked only `EditText` and produced **70** where the script produced
**73** — a partial list is a wrong number, and it is wrong silently. The Rust
gate now checks the full type list and the taxonomy ID, and the two agree
exactly, which is the cross-check's whole purpose.

---

## 4. Signals that were *not* available, and would have helped

Stated as gaps, not as complaints.

| missing | would have decided |
|---|---|
| the DEX class hierarchy (`class_def.superclass_id`) | exact shim coverage for inherited methods — §3.1's standing limitation — and the difference between an app's own `inflate` and `LayoutInflater.inflate` without heuristics |
| `resources.arsc` | whether `setContentView(R.layout.x)` resolves to a layout with a button in it. `prediction.md` T-VAL-8 already calls this "probably the biggest miss"; here it is concrete: the only way to know gita's `ListView` has clickable rows is to read the layout, and I read the layout by hand instead |
| the call graph from `onCreate` | the *launch path* as distinct from the whole app. Four gates in `candidates.md` §1.5 are launch-path gates approximated by whole-app signals; a real call graph would make them exact and would catch cases where an app's dangerous dependency is off the launch path entirely |
| a `getIdentifier`/`getResourceName` probe | `SUB.RES.PACKAGE_RESOLVER` is `MISBEHAVE` and gita trips it (`getStringResourceByName` ×2). Whether that degrades or refuses is unmeasured |

---

## 5. Summary

| signal | verdict |
|---|---|
| `straySharedObjects` | **decisive** — the census's other native field would have shipped an ELF app |
| manifest components | **decisive** — 116 of 181 rejections, and all three launch-path gates |
| `android.* types referenced` | **decisive** as a ranking signal |
| taxonomy **class** | **decisive** — reorders the top 3 |
| shim method coverage | **decisive** — `S.N.A.K.E` is 5th, not 1st, because of it |
| `dexBytes` | decisive as an *exclusion*; **noise** as a *ranking* input |
| `android:onClick` in layouts | decisive, and invisible to every DEX-level signal |
| `reflection_call_sites` | **noise for selection** — 43 of 45 affected apps report ~0 |
| `minSdk` | **no signal** in this pool; a real risk only for the oracle |
| `entryCount`, `dexCount`, `dexUncompressedBytes` | **noise** — redundant with `dexBytes` |
| predictor band | **no resolution** — `MINIMAL 200/200` |
| `taxonomy_hits` count | **noise** — tracks app size, not risk |

The one-line version: **for choosing a first subject, the manifest and the
archive beat the bytecode, and the bytecode signals that *should* have carried
the most weight — reflection, invokedynamic, the predictor's band — either had no
resolution in this stratum or were measuring the wrong side of the boundary.**
