#!/usr/bin/env python3
"""
Parse an ART method trace into structured records.

    python3 trace/parse.py <trace>...            # human summary
    python3 trace/parse.py <trace> --json        # machine-readable

# What this reads

An ART method trace is a *text* preamble followed by a *binary* data section.
The preamble is where every distinct method the trace observed is named, and it
is the only part this parser reads. Three sections matter:

    *version            header keys, incl. num-method-calls and
                        data-file-overflow
    *threads            tid -> thread name
    *methods            the string table: one row per DISTINCT method, as
      0x2c <TAB> java.lang.ref.ReferenceQueue <TAB> remove
         <TAB> ()Ljava/lang/ref/Reference; <TAB> ReferenceQueue.java
    *end                end of the preamble; the binary data section follows

Two on-disk layouts exist and both are supported. Which one a file is comes
from its first bytes:

    "*version"  "batched"  — the preamble above, with the data section starting
                             after `*end\n` as `SLOW` + a version byte. Produced
                             by `am profile start` … `am profile stop`, and by
                             `--start-profiler` *without* `--streaming`.
    "SLOW"      "continuous" — no preamble at all; the data section is the
                             whole file. Method names are stored inline in the
                             record stream, each as `class<TAB>name<TAB>
                             (sig)ret<TAB>source\n`. Produced by `--streaming`.

# Why the *methods table is the right thing to count

ART allocates one entry per method *when it is first entered during the trace*,
so the table is deduplicated by construction and its row count is the number of
distinct methods observed. `num-method-calls` counts entries, not distinct
methods: a full trace of gita records 511,961 calls across 4,643 distinct
methods. Counting rows, not calls, is what makes the number a *surface* rather
than a workload.

# Sampling, and why it makes this a lower bound

Under `--sampling INTERVAL` ART records whichever method a thread happens to be
inside at each tick. A method shorter than the interval can be missed entirely,
so a method it never names. The method table of a sampled trace is therefore a
strict subset of the exhaustive one, and every count derived from it is a
LOWER BOUND, not a measurement of coverage. Measured ratio on gita: 319 methods
sampled at 100us against 4,643 exhaustive — sampling undercounts by 14.6x.

The layout byte cannot tell you whether a batched trace was sampled, and the
preamble does not record the interval. `--mode` therefore has to be supplied by
whoever captured the file; when it is absent this module refuses to guess and
labels the result `undetermined`, which downgrades every count to a lower bound.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable, Iterator, Sequence

# --------------------------------------------------------------------------
# What counts as "framework"
# --------------------------------------------------------------------------
#
# These are the namespaces the platform loads into every app process. They are
# not a guess: `measure.mjs` prints every namespace the traces actually
# observed, split into kept and dropped, so a wrong entry here is visible in
# the report rather than silently skewing it.
#
# `com.android.*` is included wholesale and then the system-app namespaces are
# subtracted, because the traces contain three distinct `com.android.*`
# namespaces (internal, icu, org) and naming each sub-prefix separately would
# make the filter quietly incomplete when a new one appears.

FRAMEWORK_PREFIXES: tuple[str, ...] = (
    "android.",
    "java.",
    "javax.",
    "jdk.",
    "sun.",
    "libcore.",
    "dalvik.",
    "org.apache.harmony.",
    "org.apache.http.",
    "org.conscrypt.",
    "org.json.",
    "org.w3c.",
    "org.xml.",
    "org.xmlpull.",
    "com.android.",
)

# Namespaces under `com.android.` that are preinstalled *applications*, not
# framework, and so are never executed inside an app's own process.
FRAMEWORK_PREFIX_EXCEPTIONS: tuple[str, ...] = (
    "com.android.providers.",
    "com.android.vending.",
    "com.android.chrome.",
    "com.android.packageinstaller.",
    "com.android.settings.",
    "com.android.shell.",
    "com.android.bluetooth.",
    "com.android.nfc.",
    "com.android.printspooler.",
    "com.android.external.",
    "com.android.wallpaper.",
    "com.android.cellbroadcastreceiver.",
    "com.android.keychain.",
    "com.android.location.fused.",
    "com.android.mms.",
    "com.android.server.",
    "com.android.systemui.",
)

# --------------------------------------------------------------------------
# Record grammar
# --------------------------------------------------------------------------
#
# Every field is validated, and each failure gets its own rejection reason, so a
# report can say *what* it dropped rather than only how much. This is the whole
# defence against parsing artefacts, and it has two independent parts:
#
#   1. Scope. The batched parser reads only between `*methods` and `*end`, and
#      the continuous parser only accepts byte sequences that match the full
#      four-field record shape. The header therefore cannot be read as a record
#      at all. A regex applied to the whole file is not safe here: the binary
#      data section decodes, lossily, into 566,787 "rows" for a trace whose
#      method table holds 4,643.
#
#   2. Shape. Even inside the table, a class name must be a dotted Java
#      identifier. The reported failure mode — a header value such as
#      `elapsed-time-usec=628...` read as a class named `628` — is a class name
#      that starts with a digit, and a dotted-identifier test rejects it. The
#      signature check rejects it too, independently, because `628` cannot
#      supply a `(sig)ret` field.

_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
CLASS_RE = re.compile(rf"^{_IDENT}(?:\.{_IDENT})+$")
# A leading `-` is legal here and common: d8 emits accessors such as
# `-$$Nest$fgetthreadLocalHashCode` for nestmate field access. A `-` also
# appears *inside* desugared lambda names, which encode the enclosing class
# with dots replaced by dashes:
# `lambda$onFrameDraw$0$android-view-ViewRootImpl$1`. All of these are real
# framework methods a shim could be asked for, and dropping them silently cost
# 108 of gita's 4,650 table rows in an earlier version of this check.
_NAME_BODY = r"[A-Za-z0-9_$-]*"
NAME_RE = re.compile(rf"^-?(?:[A-Za-z_$]{_NAME_BODY}|<init>|<clinit>)$")
# A JVM field descriptor: a primitive, an object type `Lpkg/Name;`, or an array
# of either. Arrays nest, so `[` may be followed by another array marker and
# only then a base type — `()[Ljava/lang/Object;` and `()[I` both occur in real
# traces, and an earlier form of this check accepted only the first character
# of a type, which rejected every method returning an object or an array and
# would have understated framework coverage by hundreds of methods per app.
_TYPE = r"(?:[VZBCSIJFD]|\[+(?:[VZBCSIJFD]|[L][^();]+;)?|[L][^();]+;)"
SIG_RE = re.compile(rf"^\((?:{_TYPE})*\){_TYPE}$")
# ART writes a bare file name, one of a small set of sentinels, or nothing at
# all — the empty string occurs in real traces and means "no source file".
SOURCE_RE = re.compile(
    r"^(?:[A-Za-z0-9_$][A-Za-z0-9_$.\-]*"
    r"|Unknown Source|No source available|D8\$\$SyntheticClass)?$"
)

# The continuous layout stores the same four fields inline. Anchored on the
# trailing newline so a record torn by a flush boundary is dropped rather than
# half-read.
_CONTINUOUS_RE = re.compile(
    rb"([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)\t"
    rb"(-?(?:[A-Za-z_$][A-Za-z0-9_$-]*|<init>|<clinit>))\t"
    rb"(\((?:[VZBCSIJFD]|\[+(?:[VZBCSIJFD]|[L][^();]+;)?|[L][^();]+;)*\)"
    rb"(?:[VZBCSIJFD]|\[+(?:[VZBCSIJFD]|[L][^();]+;)?|[L][^();]+;))\t"
    rb"([A-Za-z0-9_$.\-]*)\n"
)

LAYOUT_BATCHED = "batched"
LAYOUT_CONTINUOUS = "continuous"

MODE_EXHAUSTIVE = "exhaustive"
MODE_SAMPLED = "sampled"
MODE_UNDETERMINED = "undetermined"


@dataclass(frozen=True, order=True)
class Method:
    """One distinct method. Identity is the first three fields; `source` is
    display only and is excluded from equality, because ART can name the same
    method with different source sentinels."""

    cls: str
    name: str
    sig: str
    source: str = field(compare=False)

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.cls, self.name, self.sig)

    @property
    def slash(self) -> str:
        """`Landroid/view/View;.draw()V` — the form a DEX method reference and
        the shim's own registry use, so reports join without translation."""
        return f"L{self.cls.replace('.', '/')};.{self.name}{self.sig}"

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.cls}.{self.name}{self.sig} [{self.source}]"


@dataclass
class Trace:
    path: str
    sha256: str
    size: int
    layout: str
    mode: str
    sampling_us: int | None
    header: dict[str, str]
    methods: list[Method]
    rejected: collections.Counter
    duplicates: int
    table_rows: int
    overflow: bool | None
    elapsed_us: int | None
    num_method_calls: int | None

    @property
    def exhaustive(self) -> bool:
        """True only if every entry was recorded *and* ART did not overflow.

        `data-file-overflow=true` means ART's ring buffer filled and entries were
        dropped. The method table is then a subset of what ran, so the trace is
        exhaustive in *instrumentation* and truncated in *fact* — a lower bound
        wearing the wrong label unless this is checked. 8 of the 64 usable
        captures in this study overflowed.
        """
        return self.mode == MODE_EXHAUSTIVE and self.overflow is False

    @property
    def coverage_label(self) -> str:
        """The word every number in a report must carry."""
        if self.overflow is True:
            prefix = "exhaustive-but-TRUNCATED" if self.mode == MODE_EXHAUSTIVE else "TRUNCATED"
            return f"{prefix} (data-file-overflow; lower bound)"
        if self.mode == MODE_EXHAUSTIVE:
            return "exhaustive"
        if self.mode == MODE_SAMPLED:
            return f"sampled@{self.sampling_us}us (lower bound)"
        return "undetermined (lower bound)"

    @property
    def distinct(self) -> int:
        return len(self.methods)

    def framework(self) -> list[Method]:
        return [m for m in self.methods if is_framework(m.cls)]

    def app(self) -> list[Method]:
        return [m for m in self.methods if not is_framework(m.cls)]

    def namespaces(self) -> collections.Counter:
        return collections.Counter(m.cls.split(".")[0] for m in self.methods)


def is_framework(cls: str) -> bool:
    if not cls.startswith(FRAMEWORK_PREFIXES):
        return False
    return not cls.startswith(FRAMEWORK_PREFIX_EXCEPTIONS)


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def _check(fields: Sequence[str]) -> str | None:
    """Return a rejection reason, or None if the row is a well-formed record."""
    cls, name, sig, source = fields
    if not cls:
        return "empty-class"
    # The defect this whole module exists to prevent.
    if not CLASS_RE.match(cls):
        return "class-not-dotted-identifier"
    if not NAME_RE.match(name):
        return "name-not-identifier"
    if not SIG_RE.match(sig):
        return "signature-not-descriptor"
    if not SOURCE_RE.match(source):
        return "source-not-file-name"
    return None


def _parse_header(lines: Iterable[str]) -> dict[str, str]:
    header: dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("*"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            header[k] = v
        elif line.isdigit():
            # `*version` is followed by the bare version number.
            header.setdefault("version", line)
        else:
            header[line] = ""
    return header


def _finish(
    path: str,
    data: bytes,
    layout: str,
    mode: str,
    sampling_us: int | None,
    header: dict[str, str],
    table_rows: int,
    keys: Iterable[tuple[str, str, str, str]],
    rejected: collections.Counter,
) -> Trace:
    seen: dict[tuple[str, str, str], Method] = {}
    duplicates = 0
    for cls, name, sig, source in keys:
        why = _check((cls, name, sig, source))
        if why is not None:
            rejected[why] += 1
            continue
        key = (cls, name, sig)
        if key in seen:
            # ART can name the same method from two different `ArtMethod`
            # addresses (a redefinition or a class reload). Counted, not
            # dropped silently, so that
            #     table_rows == distinct + duplicates + rejected
            # holds and the row accounting is auditable.
            duplicates += 1
            continue
        seen[key] = Method(cls, name, sig, source)

    overflow_raw = header.get("data-file-overflow")
    elapsed_raw = header.get("elapsed-time-usec")
    calls_raw = header.get("num-method-calls")
    return Trace(
        path=path,
        sha256=sha256_of(data),
        size=len(data),
        layout=layout,
        mode=mode,
        sampling_us=sampling_us,
        header=header,
        methods=sorted(seen.values()),
        rejected=rejected,
        duplicates=duplicates,
        table_rows=table_rows,
        overflow=(overflow_raw == "true") if overflow_raw is not None else None,
        elapsed_us=int(elapsed_raw) if elapsed_raw and elapsed_raw.isdigit() else None,
        num_method_calls=int(calls_raw) if calls_raw and calls_raw.isdigit() else None,
    )


def parse_bytes(
    data: bytes,
    path: str = "<bytes>",
    mode: str = MODE_UNDETERMINED,
    sampling_us: int | None = None,
) -> Trace:
    if not data:
        raise ValueError(f"{path}: empty file (0 bytes) — this is a failed capture, not a run with no calls")

    if data.startswith(b"*version"):
        return _parse_batched(data, path, mode, sampling_us)
    if data.startswith(b"SLOW"):
        return _parse_continuous(data, path, mode, sampling_us)
    raise ValueError(f"{path}: not an ART method trace (starts with {data[:16]!r})")


def _parse_batched(data: bytes, path: str, mode: str, sampling_us: int | None) -> Trace:
    start = data.find(b"*methods")
    end = data.find(b"*end")
    if start < 0 or end < 0 or end < start:
        raise ValueError(f"{path}: batched trace missing *methods/*end markers")
    preamble = _decode(data[:start])
    header = _parse_header(preamble.splitlines())

    # The data section begins immediately after `*end\n`: a 4-byte clock magic
    # then a version byte whose high nibble flags a streaming write.
    data_start = end + len(b"*end\n")
    version_byte = data[data_start + 4] if len(data) > data_start + 4 else 0x00
    streaming = bool(version_byte & 0xF0)

    body = data[start + len(b"*methods") : end]
    text = _decode(body)
    rejected: collections.Counter = collections.Counter()
    keys: list[tuple[str, str, str, str]] = []
    rows = 0
    for line in text.split("\n"):
        if not line.strip():
            continue
        rows += 1
        fields = line.split("\t")
        if len(fields) != 5:
            # The address field is column 0 and is never part of the identity.
            rejected[f"field-count-{len(fields)}"] += 1
            continue
        keys.append((fields[1], fields[2], fields[3], fields[4]))
    t = _finish(path, data, LAYOUT_BATCHED, mode, sampling_us, header, rows, keys, rejected)
    if streaming:
        # A batched preamble in front of a streaming body: report the layout the
        # bytes say, not the one the name suggests.
        t.header["streamed"] = "true"
    return t


def _parse_continuous(data: bytes, path: str, mode: str, sampling_us: int | None) -> Trace:
    # The continuous layout has no preamble, so the header is genuinely absent
    # and `num-method-calls` cannot be cross-checked. Say so rather than 0.
    matches = _CONTINUOUS_RE.findall(data)
    keys = [(m[0].decode(), m[1].decode(), m[2].decode(), m[3].decode()) for m in matches]
    rejected: collections.Counter = collections.Counter()
    return _finish(path, data, LAYOUT_CONTINUOUS, mode, sampling_us, {}, len(keys), keys, rejected)


def parse_file(path: str, mode: str = MODE_UNDETERMINED, sampling_us: int | None = None) -> Trace:
    with open(path, "rb") as fh:
        return parse_bytes(fh.read(), path, mode, sampling_us)


def load_sidecar(trace_path: str) -> tuple[str, int | None]:
    """Read the capture record written next to a trace.

    `capture.sh` writes `<trace>.json` holding the mode it actually used. The
    file is advisory: if it disagrees with the trace, the trace's own layout
    byte still wins for `layout`. A missing sidecar yields `undetermined`,
    which is the correct default and not an error.
    """
    try:
        with open(trace_path + ".json", "r", encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, ValueError):
        return MODE_UNDETERMINED, None
    mode = meta.get("mode", MODE_UNDETERMINED)
    if mode not in (MODE_EXHAUSTIVE, MODE_SAMPLED, MODE_UNDETERMINED):
        return MODE_UNDETERMINED, None
    interval = meta.get("sampling_us")
    return mode, interval if isinstance(interval, int) else None


def method_keys(methods: Iterable[Method]) -> set[tuple[str, str, str]]:
    return {m.key for m in methods}


def jaccard(a: set, b: set) -> float:
    union = a | b
    return 1.0 if not union else len(a & b) / len(union)


def convergence(sets: Sequence[set]) -> list[int]:
    """|union of the first k runs| for k = 1..n, in the order given.

    The order is the caller's, so a caller that wants a mean curve should
    average over permutations rather than present one lucky ordering as *the*
    curve. `measure.mjs` reports every ordering's curve for small n.
    """
    out: list[int] = []
    acc: set = set()
    for s in sets:
        acc |= s
        out.append(len(acc))
    return out


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("traces", nargs="+")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument("--mode", choices=(MODE_EXHAUSTIVE, MODE_SAMPLED, MODE_UNDETERMINED), default=None)
    ap.add_argument("--sampling-us", type=int, default=None)
    ap.add_argument("--all", action="store_true", help="count app classes too (default: framework only)")
    ap.add_argument("--with-keys", action="store_true",
                    help="include the distinct framework method keys, for set arithmetic downstream")
    args = ap.parse_args(argv)

    traces: list[Trace] = []
    failures: list[dict[str, str]] = []
    for p in args.traces:
        mode, interval = load_sidecar(p)
        if args.mode is not None:
            mode = args.mode
        if args.sampling_us is not None:
            interval = args.sampling_us
        try:
            traces.append(parse_file(p, mode, interval))
        except (OSError, ValueError) as exc:
            # A failed capture is a *result*. Reporting it and continuing is
            # the whole point: the alternative is a run that silently reads as
            # "this app called nothing".
            failures.append({"path": p, "error": str(exc)})

    if args.json:
        json.dump(
            {
                "traces": [
                    {
                        "path": t.path,
                        "sha256": t.sha256,
                        "size": t.size,
                        "layout": t.layout,
                        "mode": t.mode,
                        "sampling_us": t.sampling_us,
                        "coverage": t.coverage_label,
                        "tableRows": t.table_rows,
                        "distinctMethods": t.distinct,
                        "frameworkMethods": len(t.framework()),
                        "appMethods": len(t.app()),
                        "numMethodCalls": t.num_method_calls,
                        "dataFileOverflow": t.overflow,
                        "rejected": dict(t.rejected),
                        "duplicateRows": t.duplicates,
                        **(
                            {
                                "frameworkKeys": ["\t".join(m.key) for m in t.framework()],
                                "appKeys": ["\t".join(m.key) for m in t.app()],
                            }
                            if args.with_keys
                            else {}
                        ),
                    }
                    for t in traces
                ],
                "failures": failures,
            },
            sys.stdout,
            indent=2,
        )
        print()
        return 1 if failures else 0

    for t in traces:
        fw = t.framework()
        print(f"{t.path}")
        print(f"  layout              {t.layout}")
        print(f"  coverage            {t.coverage_label}")
        print(f"  sha256              {t.sha256}")
        print(f"  bytes               {t.size}")
        print(f"  table rows          {t.table_rows}")
        print(f"  distinct methods    {t.distinct}")
        print(f"  framework methods   {len(fw)}")
        if args.all:
            print(f"  app methods         {len(t.app())}")
        if t.num_method_calls is not None:
            print(f"  num-method-calls    {t.num_method_calls} (entries, not distinct)")
        if t.elapsed_us is not None:
            print(f"  elapsed             {t.elapsed_us} us")
        if t.overflow is not None:
            print(f"  data-file-overflow  {t.overflow}")
        if t.duplicates:
            print(f"  duplicate rows      {t.duplicates} (same method, two ArtMethod addresses)")
        if t.rejected:
            print(f"  rejected rows       {sum(t.rejected.values())} {dict(t.rejected)}")
        print()
    for f in failures:
        print(f"FAILED CAPTURE  {f['path']}\n  {f['error']}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
