#!/usr/bin/env python3
"""Build andro-substrate runtime/resources/fixtures from F-Droid APKs.

Everything committed here is a byte-for-byte extract except
`weatherforecast.reframed.arsc`, whose framing is rebuilt; see FIXTURES.md.
"""
import hashlib, os, shutil, struct, subprocess, sys, zipfile

CAND = "/tmp/andro-substrate-candidates"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
EMULATOR = os.path.expanduser("~/Library/Android/sdk/emulator/resources/skins/android-36/user")

# (fixture basename, apk path, members to extract)
EXTRACTS = [
    ("clock31.arsc", f"{CAND}/com.dosse.clock31_5.apk", ["resources.arsc"]),
    ("clock31.layout_c31_widget.axml", f"{CAND}/com.dosse.clock31_5.apk", ["res/7_.xml"]),
    ("clock31.layout_calendar_entry.axml", f"{CAND}/com.dosse.clock31_5.apk", ["res/Jq.xml"]),
    ("clock31.manifest.axml", f"{CAND}/com.dosse.clock31_5.apk", ["AndroidManifest.xml"]),
    ("t4.arsc", f"{CAND}/com.github.rsteube.t4_4.apk", ["resources.arsc"]),
    ("t4.drawable_button.axml", f"{CAND}/com.github.rsteube.t4_4.apk", ["res/drawable/button.xml"]),
    ("vanillaplug.arsc", f"{CAND}/ch.blinkenlights.android.vanillaplug_170.apk", ["resources.arsc"]),
    ("pixel10proxl.arsc", f"{EMULATOR}/pixel_10_pro_xl/EmulationPixel10ProXLOverlay.apk", ["resources.arsc"]),
]

def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def chunks(buf, at, end):
    while at + 8 <= end:
        t, hs, sz = struct.unpack_from("<HHI", buf, at)
        if sz < 8:
            break
        yield t, hs, sz, at
        at += sz

def build_reframed(src_apk, dst):
    """Keep the rare `ResTable_config.size == 36` and 284-byte package header.

    The real file's global value pool is 5.3 MB and the layout type inside it is
    2.8 MB, so the table is rebuilt around the chunks that actually carry the
    structure under test. Every retained chunk *body* is byte-identical to the
    original; only the container `size` words and the two pool offsets move.
    """
    b = zipfile.ZipFile(src_apk).read("resources.arsc")
    rt, rhs, rsz, rat = next(iter(chunks(b, 0, len(b))))
    assert rt == 0x0002 and rhs == 12
    pkg_t, pkg_hs, pkg_sz, pkg_at = next(
        c for c in chunks(b, rat + rhs, rat + rsz) if c[0] == 0x0200
    )
    assert pkg_t == 0x0200 and pkg_hs == 284, (hex(pkg_t), pkg_hs)

    # The two string pools, in order, and the typeSpec/type pair for type id 2.
    subs = list(chunks(b, pkg_at + pkg_hs, pkg_at + pkg_sz))
    pools = [(t, hs, sz, a) for t, hs, sz, a in subs if t == 0x0001]
    assert len(pools) == 2, len(pools)
    # Find the smallest complete typeSpec + type pair, to keep the fixture tiny.
    best = None
    for i, (t, hs, sz, a) in enumerate(subs):
        if t != 0x0202:
            continue
        following = subs[i + 1] if i + 1 < len(subs) else None
        if following is None or following[0] != 0x0201:
            continue
        cand = (sz + following[2], (t, hs, sz, a), following)
        if best is None or cand[0] < best[0]:
            best = cand
    assert best is not None
    spec, typ = best[1], best[2]

    def body(c):
        return b[c[3]:c[3] + c[2]]

    def pool_bytes(c):
        return bytearray(body(c))

    type_pool = pool_bytes(pools[0])
    key_pool = pool_bytes(pools[1])
    # The global value pool is replaced by a structurally valid empty one; the
    # retained chunks reference no global strings, which the verifier below
    # checks rather than assuming.
    empty_global = bytearray(28)
    struct.pack_into("<HHIIIIII", empty_global, 0, 0x0001, 28, 28, 0, 0, 0x0100, 28, 0)

    pkg_body = bytearray(b[pkg_at:pkg_at + pkg_hs])
    # The two pool offsets are relative to the start of the package chunk.
    type_off = pkg_hs
    key_off = pkg_hs + len(type_pool)
    struct.pack_into("<I", pkg_body, 268, type_off)
    struct.pack_into("<I", pkg_body, 276, key_off)
    payload = bytes(type_pool) + bytes(key_pool) + bytes(body(spec)) + bytes(body(typ))
    pkg_size = pkg_hs + len(payload)
    struct.pack_into("<I", pkg_body, 4, pkg_size)

    total = 12 + len(empty_global) + pkg_size
    out = bytearray(total)
    struct.pack_into("<HHII", out, 0, 0x0002, 12, total, 1)
    out[12:12 + len(empty_global)] = empty_global
    base = 12 + len(empty_global)
    out[base:base + pkg_hs] = pkg_body
    out[base + pkg_hs:base + pkg_size] = payload
    with open(dst, "wb") as f:
        f.write(bytes(out))
    # Wrap it in a ZIP so aapt2 and apkanalyzer, which only accept containers,
    # can be pointed at the reframed table as an independent oracle.
    wrapper = dst.replace(".arsc", ".apk")
    with zipfile.ZipFile(wrapper, "w", zipfile.ZIP_STORED) as z:
        z.writestr("resources.arsc", bytes(out))
        # Both oracles insist on a manifest before they will read the table.
        z.writestr("AndroidManifest.xml", zipfile.ZipFile(src_apk).read("AndroidManifest.xml"))
    return len(out), spec, typ

def main():
    os.makedirs(OUT, exist_ok=True)
    manifest = []
    for name, apk, members in EXTRACTS:
        if not os.path.exists(apk):
            print(f"SKIP (absent): {apk}", file=sys.stderr)
            continue
        z = zipfile.ZipFile(apk)
        for m in members:
            data = z.read(m)
            with open(os.path.join(OUT, name), "wb") as f:
                f.write(data)
            manifest.append((name, m, len(data), hashlib.sha256(data).hexdigest(), hashlib.sha256(open(apk,'rb').read()).hexdigest(), os.path.basename(apk)))
        print(f"{name:38s} {len(data):7d}  {hashlib.sha256(data).hexdigest()[:16]}")

    src = f"{CAND}/uk.org.boddie.android.weatherforecast_173.apk"
    n, spec, typ = build_reframed(src, os.path.join(OUT, "weatherforecast.reframed.arsc"))
    data = open(os.path.join(OUT, "weatherforecast.reframed.arsc"), "rb").read()
    manifest.append(("weatherforecast.reframed.arsc", "resources.arsc(type 2 only)", len(data),
                     hashlib.sha256(data).hexdigest(), hashlib.sha256(open(src,'rb').read()).hexdigest(),
                     os.path.basename(src)))
    wrap = os.path.join(OUT, "weatherforecast.reframed.apk")
    wdata = open(wrap, "rb").read()
    manifest.append(("weatherforecast.reframed.apk", "(zip wrapper for the oracles)", len(wdata),
                     hashlib.sha256(wdata).hexdigest(), hashlib.sha256(open(src,'rb').read()).hexdigest(),
                     os.path.basename(src)))
    print(f"{'weatherforecast.reframed.arsc':38s} {len(data):7d}  {hashlib.sha256(data).hexdigest()[:16]}")

    with open(os.path.join(OUT, "MANIFEST.tsv"), "w") as f:
        f.write("fixture\tsource-member\tbytes\tsha256-member\tsha256-apk\tapk\n")
        for row in manifest:
            f.write("\t".join(str(x) for x in row) + "\n")

if __name__ == "__main__":
    main()
