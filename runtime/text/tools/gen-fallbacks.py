#!/usr/bin/env python3
"""Regenerate the declared fallback metric table in src/font.rs from a device
recording.

    tools/gen-fallbacks.py fixtures/device-android13.jsonl

Every number the table contains is a *mean advance in em* measured on a real
device, over the code points the corpus exercised in that block. It is not a
font metric and it is not a claim about a font; it is a declared stand-in with
a measured residual, and `metrics.rs` reports that residual per script.

The generator prints the Rust table to stdout. It is checked in as a tool so
that the number in the source can be traced back to the bytes that produced it
rather than taken on trust.
"""
import json
import sys
import collections

# (name, lo, hi, comment) — deliberately a short, explicit list. A large
# fabricated metric table would be a font we do not ship under a licence we have
# not read, which is the thing this crate is supposed to avoid.
RANGES = [
    ("hebrew", 0x0590, 0x05FF, "block mean"),
    ("arabic", 0x0600, 0x06FF, "block mean"),
    ("devanagari", 0x0900, 0x0963, "base letters only; marks are zero-width"),
    ("devanagari-digits", 0x0966, 0x096F, "digits are wider than the letters"),
    ("thai", 0x0E00, 0x0E7F, "block mean"),
    ("hangul", 0xAC00, 0xD7A3, "Noto Sans CJK KR hangul cell"),
    ("han", 0x3400, 0x4DBF, "full-width cell, exact"),
    ("han-ext", 0x4E00, 0x9FFF, "full-width cell, exact"),
    ("hiragana", 0x3040, 0x309F, "full-width cell, exact"),
    ("katakana", 0x30A0, 0x30FF, "full-width cell, exact"),
    ("fullwidth", 0xFF00, 0xFF60, "full-width cell by definition"),
]


def main(path):
    cases = {}
    import os
    cases_path = os.path.join(os.path.dirname(os.path.abspath(path)), "cases.jsonl")
    with open(cases_path) as f:
        for line in f:
            o = json.loads(line)
            cases[o["id"]] = o

    best = {}
    clusters = []
    with open(path) as f:
        for line in f:
            o = json.loads(line)
            if o.get("kind") != "measure":
                continue
            c = cases.get(o["id"])
            if c is None or c["letter_spacing_px"] or c["text_scale_x"] != 1.0:
                continue
            # Paint.getTextWidths returns one entry per UTF-16 code unit, not
            # per code point, so a surrogate pair comes back as two widths and
            # a plain `zip(text, widths)` silently misaligns every emoji row.
            # This is also a finding in its own right: anything that maps
            # per-character widths back onto a `char`-indexed string is wrong
            # for every character outside the BMP.
            units, sz, ws = c["text"].encode("utf-16-le"), c["size_px"], o["widths"]
            if len(units) // 2 != len(ws):
                continue
            for i, w in enumerate(ws):
                cu = units[2 * i:2 * i + 2]
                cp = (0x10000 + ((cu[0] & 0x3FF) << 10) + (cu[1] & 0x3FF)
                      if 0xD8 <= cu[1] <= 0xDF else cu[1] << 8 | cu[0])
                if cp not in best or sz > best[cp][0]:
                    best[cp] = (sz, w)
            # Emoji: the advance belongs to a whole cluster, so measure clusters.
            if any(0x1F000 <= ord(x) <= 0x1FAFF for x in c["text"]):
                # Only the largest sizes: a cluster advance quantised to whole
                # pixels is worth 1/34 em, so 8px data would drag a 1.245 em
                # figure toward 1.1 for no reason.
                if sz >= 24.0:
                    clusters.extend(cluster_widths(c["text"], ws, sz))

    out = []
    for name, lo, hi, comment in RANGES:
        vals = [w / sz for cp, (sz, w) in best.items()
                if lo <= cp <= hi and w > 0 and sz >= 24.0]
        if not vals:
            continue
        mean = sum(vals) / len(vals)
        exact1 = sum(1 for v in vals if abs(v - 1.0) < 0.02)
        trust = "Measured" if exact1 == len(vals) else "Fabricated"
        out.append((name, lo, hi, round(mean, 3), len(vals), trust, comment))

    if clusters:
        mean = sum(clusters) / len(clusters)
        out.append(("emoji-cluster", 0x1F000, 0x1FAFF, round(mean, 3), len(clusters), "Measured",
                    "one ZWJ/flag cluster"))

    for name, lo, hi, pm, n, trust, comment in out:
        lo_s = f"0x{lo:04X}" if lo <= 0xFFFF else hex(lo)
        hi_s = f"0x{hi:04X}" if hi <= 0xFFFF else hex(hi)
        print(f"        SyntheticMetrics {{")
        print(f"            name: {name!r},".replace("'", '"'))
        print(f"            ranges: &[({lo_s}, {hi_s})],")
        print(f"            per_mille: {int(pm * 1000)},")
        print(f"            trust: MetricTrust::{trust},")
        print(f"            basis: \"{comment}; {n} code points measured, mean {pm:.4f} em\",")
        print(f"        }},")
    print("];")


def cluster_widths(text, widths, size):
    """Advance of each emoji cluster, in em.

    Walks code points and consumes the whole UTF-16 span of each, so a
    ZWJ sequence or a flag pair is counted once.
    """
    out = []
    i = 0          # index into `text` (code points)
    u = 0          # index into `widths` (UTF-16 code units)
    n = len(text)
    while i < n:
        cp = ord(text[i])
        span = 2 if cp > 0xFFFF else 1
        w = widths[u] if u < len(widths) else 0
        j = i + 1
        u += span
        while j < n:
            nx = ord(text[j])
            nspan = 2 if nx > 0xFFFF else 1
            if nx == 0x200D or 0x1F3FB <= nx <= 0x1F3FF or 0xFE0E <= nx <= 0xFE0F:
                j += 1
                u += nspan
            else:
                break
        if w > 0 and (0x1F000 <= cp <= 0x1FAFF):
            out.append(w / size)
        i = j
    return out


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "fixtures/device-android13.jsonl")
