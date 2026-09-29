#!/usr/bin/env python3
"""Turn Unicode's BidiTest.txt into a fixture for tests/bidi.rs.

    curl -O https://www.unicode.org/Public/15.1.0/ucd/BidiTest.txt
    tools/gen-biditest.py BidiTest.txt fixtures/biditest.jsonl [stride]

Output: one JSON object per (case, paragraph mode) pair:

    {"types": ["L","RLE",...], "mode": "auto", "para": 0,
     "levels": [0,1,...], "removed": [false,true,...],
     "reorder": [0,1,-3,-2]}

`levels` carries `null` where the UBA assigns no level (X9-removed characters),
matching the `x` in the UCD file. `reorder` is Unicode's reorder map, verbatim:
entry i is the logical index that lands at visual position i, negated and
bit-inverted when that character was reversed.

The stride is deterministic and the file's cases are ordered by construction
rather than by difficulty, so a plain stride samples the space without a shuffle
that would only look random. The full-file pass rate is reported separately in
README.md and is the number that carries the denominator.
"""
import json
import sys

STRIDE = int(sys.argv[3]) if len(sys.argv) > 3 else 37


def main(src, dst):
    types, bits, para, order = [], None, None, []
    modes = {}
    all_cases = []
    for line in open(src, encoding="utf-8"):
        line = line.split("#")[0].strip()
        if not line:
            continue
        if line.startswith("@Levels"):
            levels = line.split(":", 1)[1].split()
            modes = {}
            continue
        if line.startswith("@Reorder"):
            order = line.split(":", 1)[1].split()
            continue
        if ";" not in line:
            continue
        fields = line.split(";")
        if len(fields) < 2:
            continue
        types = fields[0].split()
        bits = int(fields[1].strip(), 16)
        # The UCD's own runner picks exactly one paragraph level per data
        # line: auto if bit 1 is set, else LTR if bit 2, else RTL. The
        # @Levels/@Reorder block that precedes it describes that one choice,
        # not all three. Reading a bitset of 7 as "three cases with the same
        # expectation" is wrong and silently costs about 30% of the file.
        if bits & 1:
            mode, para = "auto", None
        elif bits & 2:
            mode, para = "ltr", 0
        else:
            mode, para = "rtl", 1
        all_cases.append({
            "types": list(types),
            "mode": mode,
            "para": para,
            "levels": [None if x == "x" else int(x) for x in levels],
            "reorder": [int(x) for x in order],
        })
    del modes

    picked = all_cases[::STRIDE]
    with open(dst, "w", encoding="utf-8") as f:
        for c in picked:
            f.write(json.dumps(c, separators=(",", ":")) + "\n")
    print(f"{len(all_cases)} cases in {src}")
    print(f"{len(picked)} written to {dst} (stride {STRIDE})")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
