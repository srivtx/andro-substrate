#!/usr/bin/env python3
"""
Tests for `trace/parse.py`.

    python3 -m unittest discover -s trace/tests -v
    python3 trace/tests/test_parse.py

These tests are the reason the parser can be believed. Four of them are about
artefacts rather than happy paths, because the artefacts are what silently
inflate an intersection:

  1. `test_header_is_never_read_as_a_record` — a trace whose header contains
     `elapsed-time-usec=6282909` must yield zero records mentioning `628`. A
     whole-file regex does yield one; the test asserts the naive count so the
     regression cannot be reintroduced silently.
  2. `test_binary_tail_is_not_parsed` — a realistic binary data section must
     contribute zero rows.
  3. `test_malformed_rows_are_rejected_with_reasons` — every rejection path is
     named, not merely counted.
  4. `test_zero_byte_trace_is_a_failed_capture` — the `balancetheball` case, in
     which a 0-byte file would otherwise read as "an app that called nothing".

Fixtures are built in-process, byte for byte, so the suite needs no device, no
captured trace, and no network. `test_real_trace_*` is skipped unless
`trace/runs/` happens to hold a capture.
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import parse as P  # noqa: E402


def batched(
    methods=(),
    *,
    version=3,
    num_method_calls=100,
    elapsed_usec=6282909,
    overflow=False,
    threads=(("1", "main"),),
    tail=b"",
    version_marker=0x03,
):
    """Assemble a byte-exact batched ART trace.

    Real files are the text preamble, then — after `*end\\n` — a data section
    opening `SLOW` + a version byte whose high nibble flags a streaming write.

    `methods` is an iterable of `(class, name, sig, source)`. The binary tail is
    deliberately given real-looking 16-byte records with tab and newline bytes
    embedded, because that is what defeats a naive parser.
    """
    head = ["*version", str(version), "data-file-overflow=%s" % ("true" if overflow else "false")]
    head += ["clock=dual", "elapsed-time-usec=%d" % elapsed_usec,
             "num-method-calls=%d" % num_method_calls, "clock-call-overhead-nsec=330", "vm=art", "pid=2566"]
    head += ["*threads"] + ["%s\t%s" % t for t in threads] + ["*methods"]
    rows = ["0x%x\t%s\t%s\t%s\t%s" % (i * 0x2C, c, n, s, f) for i, (c, n, s, f) in enumerate(methods)]
    text = "\n".join(head + rows) + "\n*end\n"
    return text.encode() + b"SLOW" + bytes([version_marker, 0x00]) + b"\x00" * 14 + tail


NOISY_TAIL = b"".join(
    bytes([i & 0xFF, 0x00, 0x09, 0x54, 0x41, 0x00, 0x0F, 0x21, 0x1F, 0x00, 0x06, 0x0A, 0x2C, 0x00, 0x31, 0x0A])
    for i in range(400)
)

REALISTIC = [
    ("android.view.View", "draw", "(Landroid/graphics/Canvas;)V", "View.java"),
    ("android.view.View", "<init>", "(Landroid/content/Context;)V", "View.java"),
    ("android.app.Activity", "onCreate", "(Landroid/os/Bundle;)V", "Activity.java"),
    ("java.lang.Object", "<init>", "()V", "Object.java"),
    ("com.android.internal.util.Preconditions", "checkNotNull", "(Ljava/lang/Object;)Ljava/lang/Object;", "Preconditions.java"),
    ("eu.quelltext.gita.activities.ChooseChaptersActivity", "onCreate", "(Landroid/os/Bundle;)V", "ChooseChaptersActivity.java"),
]


class TestBatchedLayout(unittest.TestCase):
    def test_round_trips_the_method_table(self):
        t = P.parse_bytes(batched(REALISTIC), "mem")
        self.assertEqual(t.layout, P.LAYOUT_BATCHED)
        self.assertEqual(t.distinct, len(REALISTIC))
        self.assertEqual(t.table_rows, len(REALISTIC))
        self.assertEqual(t.num_method_calls, 100)
        self.assertEqual(t.elapsed_us, 6282909)
        self.assertIs(t.overflow, False)
        self.assertEqual(sum(t.rejected.values()), 0)

    def test_layout_byte_0x03_is_batched_0xf3_is_streaming(self):
        self.assertEqual(P.parse_bytes(batched(REALISTIC, tail=NOISY_TAIL), "m").layout, "batched")
        streamed = P.parse_bytes(batched(REALISTIC, version_marker=0xF3), "m")
        self.assertEqual(streamed.layout, "batched")
        self.assertEqual(streamed.header.get("streamed"), "true")

    def test_slow_magic_without_preamble_is_continuous(self):
        body = b"SLOW\xf3\x00 \x00" + b"\x00" * 12
        body += b"android.view.View\tdraw\t()V\tView.java\n"
        self.assertEqual(P.parse_bytes(body, "m").layout, "continuous")

    def test_framework_filter_splits_platform_from_app(self):
        t = P.parse_bytes(batched(REALISTIC), "mem")
        self.assertEqual(len(t.framework()), 5)
        self.assertEqual(len(t.app()), 1)
        self.assertEqual(t.app()[0].cls, "eu.quelltext.gita.activities.ChooseChaptersActivity")

    def test_slash_form_matches_dex_method_reference(self):
        t = P.parse_bytes(batched(REALISTIC), "mem")
        by_cls = {m.cls: m for m in t.methods}
        self.assertEqual(
            by_cls["android.view.View"].slash,
            "Landroid/view/View;.draw(Landroid/graphics/Canvas;)V",
        )

    def test_dedup_ignores_source_but_not_signature(self):
        # Same class+name, different signature: two distinct methods.
        # Same class+name+signature, different source string: one method.
        rows = [
            ("android.view.View", "onMeasure", "(II)V", "View.java"),
            ("android.view.View", "onMeasure", "(II)V", "View.java"),
            ("android.view.View", "onMeasure", "(IIII)V", "View.java"),
        ]
        t = P.parse_bytes(batched(rows), "mem")
        self.assertEqual(t.table_rows, 3)
        self.assertEqual(t.distinct, 2)
        self.assertEqual(t.duplicates, 1)
        self.assertEqual(t.table_rows, t.distinct + t.duplicates + sum(t.rejected.values()))

    def test_row_accounting_is_complete_on_every_fixture(self):
        rows = REALISTIC + [("628", "x", "()V", "X.java"), ("android.view.View", "y", "nope", "View.java")]
        t = P.parse_bytes(batched(rows), "mem")
        self.assertEqual(t.table_rows, t.distinct + t.duplicates + sum(t.rejected.values()))
        self.assertEqual(sum(t.rejected.values()), 2)

    def test_namespaces_are_reported_for_audit(self):
        t = P.parse_bytes(batched(REALISTIC), "mem")
        self.assertEqual(dict(t.namespaces()), {"android": 3, "java": 1, "com": 1, "eu": 1})


class TestFrameworkClassification(unittest.TestCase):
    def test_platform_namespaces_are_framework(self):
        for cls in ("android.view.View", "java.util.List", "javax.net.ssl.SSLContext",
                    "sun.misc.Unsafe", "libcore.io.IoBridge", "dalvik.system.VMDebug",
                    "jdk.internal.misc.VM", "org.apache.harmony.xnet.provider.jsse.SSLContextImpl",
                    "com.android.internal.util.Preconditions", "com.android.icu.util.ULocale",
                    "com.android.org.conscrypt.OpenSSLProvider"):
            self.assertTrue(P.is_framework(cls), cls)

    def test_app_and_system_app_namespaces_are_not_framework(self):
        for cls in ("eu.quelltext.gita.Main", "com.example.foo.Bar",
                    "com.google.android.gms.ads.AdView",
                    "com.android.providers.contacts.ContactsProvider",
                    "com.android.vending.AssetBrowserActivity",
                    "kotlinx.coroutines.BuildersKt"):
            self.assertFalse(P.is_framework(cls), cls)


class TestArtefactRejection(unittest.TestCase):
    """Every test here corresponds to a way a laxer parser inflates results."""

    def test_header_is_never_read_as_a_record(self):
        # The reported failure: a header value read as a class named `628`.
        data = batched(REALISTIC, elapsed_usec=6282909)
        self.assertIn(b"elapsed-time-usec=6282909", data)

        # Reproduce the mechanism. A parser that forgets the binary data
        # section is not text, and so flattens the *whole* file on tabs and
        # newlines and reads 5 tokens at a time as
        # (address, class, method, signature, source), consumes the header as
        # method records and produces digit-named and `key=value`-named classes:
        chunks = [
            tuple(re.split(r"[\t\n]", data.decode("utf-8", "replace"))[i : i + 5])
            for i in range(0, len(re.split(r"[\t\n]", data.decode("utf-8", "replace"))) - 4, 5)
        ]
        naive_classes = {c[1] for c in chunks}
        self.assertIn("3", naive_classes)  # the bare `*version` line number
        self.assertIn("elapsed-time-usec=6282909", {c[4] for c in chunks})
        self.assertTrue(
            [c for c in naive_classes if re.fullmatch(r"\d+", c)],
            "the naive chunker must produce digit-named classes, or this test is not testing the defect",
        )

        # The parser: scoped to *methods, so the header is unreachable.
        t = P.parse_bytes(data, "mem")
        self.assertEqual(t.distinct, len(REALISTIC))
        self.assertFalse([m for m in t.methods if re.fullmatch(r"\d+", m.cls)])
        self.assertFalse([m for m in t.methods if "=" in m.cls])
        self.assertNotIn("elapsed-time-usec=6282909", {m.cls for m in t.methods})

    def test_scanning_past_end_inflates_the_row_count(self):
        # The other half of the same defect: the binary data section decodes,
        # lossily, into a very large number of apparent rows.
        data = batched(REALISTIC, tail=NOISY_TAIL)
        to_eof = data[data.find(b"*methods") + 8:]
        naive_rows = len([r for r in to_eof.decode("utf8", "replace").split("\n") if r.strip()])
        self.assertEqual(P.parse_bytes(data, "mem").table_rows, len(REALISTIC))
        self.assertGreater(naive_rows, 100 * len(REALISTIC))

    def test_digit_leading_class_is_rejected(self):
        rows = [("628", "foo", "()V", "Foo.java")]
        t = P.parse_bytes(batched(rows), "mem")
        self.assertEqual(t.distinct, 0)
        self.assertEqual(t.rejected["class-not-dotted-identifier"], 1)

    def test_key_value_class_is_rejected(self):
        rows = [("elapsed-time-usec", "6282909", "()V", "Foo.java")]
        t = P.parse_bytes(batched(rows), "mem")
        self.assertEqual(t.distinct, 0)
        self.assertEqual(t.rejected["class-not-dotted-identifier"], 1)

    def test_undotted_class_is_rejected(self):
        t = P.parse_bytes(batched([("View", "draw", "()V", "View.java")]), "mem")
        self.assertEqual(t.distinct, 0)
        self.assertEqual(t.rejected["class-not-dotted-identifier"], 1)

    def test_non_descriptor_signature_is_rejected(self):
        for sig in ("628", "Ljava/lang/Object;", "no-parens", "()Q", "(I)Vextra"):
            t = P.parse_bytes(batched([("android.view.View", "draw", sig, "View.java")]), "mem")
            self.assertEqual(t.distinct, 0, sig)
            self.assertEqual(t.rejected["signature-not-descriptor"], 1, sig)

    def test_valid_descriptors_are_accepted(self):
        for sig in ("()V", "(I)Z", "(Ljava/lang/Object;)Ljava/lang/Class;",
                    "([Landroid/view/View;I)Landroid/view/View;", "(J[D)Ljava/lang/String;",
                    "()[I", "()[Ljava/lang/Object;", "()[Ljava/lang/String;",
                    "([CI)[C", "(I)[Landroid/content/pm/ApplicationInfo;",
                    "()[Landroid/content/res/Configuration;"):
            t = P.parse_bytes(batched([("android.view.View", "draw", sig, "View.java")]), "mem")
            self.assertEqual(t.distinct, 1, sig)
            self.assertEqual(sum(t.rejected.values()), 0, sig)

    def test_d8_access_methods_are_kept(self):
        # Real rows from gita_full.trace. A parser that requires a Java
        # identifier at position 0 drops 108 of that trace's 4,650 rows.
        rows = [("android.os.Trace", "-$$Nest$fgetthreadLocalEnabled", "()Z", "Trace.java"),
                ("libcore.io.IoBridge", "-$$Nest$mgetEntry", "(Ljava/lang/String;)J", "IoBridge.java")]
        t = P.parse_bytes(batched(rows), "mem")
        self.assertEqual(t.distinct, 2)
        self.assertEqual(sum(t.rejected.values()), 0)

    def test_bad_names_are_rejected(self):
        t = P.parse_bytes(batched([("android.view.View", "not a name", "()V", "View.java")]), "mem")
        self.assertEqual(t.rejected["name-not-identifier"], 1)
        t = P.parse_bytes(batched([("android.view.View", "9lives", "()V", "View.java")]), "mem")
        self.assertEqual(t.rejected["name-not-identifier"], 1)

    def test_special_ctor_names_are_accepted(self):
        rows = [("android.view.View", "<init>", "()V", "View.java"),
                ("android.view.View", "<clinit>", "()V", "View.java")]
        t = P.parse_bytes(batched(rows), "mem")
        self.assertEqual(t.distinct, 2)

    def test_source_sentinels_are_accepted(self):
        rows = [("android.view.ViewRootImpl$$ExternalSyntheticLambda0", "<init>", "()V", "D8$$SyntheticClass"),
                ("android.view.View", "x", "()V", "Unknown Source")]
        t = P.parse_bytes(batched(rows), "mem")
        self.assertEqual(t.distinct, 2)
        self.assertEqual(sum(t.rejected.values()), 0)

    def test_binary_tail_is_not_parsed(self):
        data = batched(REALISTIC, tail=NOISY_TAIL)
        t = P.parse_bytes(data, "mem")
        self.assertEqual(t.table_rows, len(REALISTIC))
        self.assertEqual(t.distinct, len(REALISTIC))
        self.assertEqual(sum(t.rejected.values()), 0)


    def test_wrong_field_count_is_rejected_with_its_own_reason(self):
        text = (
            b"*version\n3\n*threads\n1\tmain\n*methods\n"
            + b"0x2c\tandroid.view.View\tdraw\t()V\tView.java\n"      # 5 fields: good
            + b"0x30\tandroid.view.View\tdraw\n"                        # 3 fields
            + b"0x34\ta\tb\tc\td\te\n"                                  # 6 fields
            + b"*end\n"
            + b"SLOW\x03\x00" + b"\x00" * 14
        )
        t = P.parse_bytes(text, "mem")
        self.assertEqual(t.distinct, 1)
        self.assertEqual(t.rejected["field-count-3"], 1)
        self.assertEqual(t.rejected["field-count-6"], 1)

    def test_empty_trace_reports_zero_methods_not_an_error(self):
        # A legitimate trace of an app that entered nothing still has a table.
        t = P.parse_bytes(batched([]), "mem")
        self.assertEqual(t.distinct, 0)
        self.assertEqual(t.table_rows, 0)


class TestFailedCaptureDetection(unittest.TestCase):
    def test_zero_byte_file_raises(self):
        with self.assertRaises(ValueError) as ctx:
            P.parse_bytes(b"", "balancetheball.run1.trace")
        self.assertIn("failed capture", str(ctx.exception))

    def test_non_trace_file_raises(self):
        with self.assertRaises(ValueError) as ctx:
            P.parse_bytes(b"not a trace at all", "x")
        self.assertIn("not an ART method trace", str(ctx.exception))

    def test_truncated_preamble_raises(self):
        with self.assertRaises(ValueError):
            P.parse_bytes(b"*version\n3\n*threads\n1\tmain\n*end\n", "x")


class TestCoverageLabelling(unittest.TestCase):
    def test_data_file_overflow_downgrades_exhaustive_to_a_lower_bound(self):
        # ART sets this when its ring buffer fills and entries are dropped. The
        # method table is then a subset of what ran, so calling it exhaustive
        # would be a lower bound presented as a measurement.
        t = P.parse_bytes(batched(REALISTIC, overflow=True), "m", P.MODE_EXHAUSTIVE)
        self.assertIs(t.overflow, True)
        self.assertFalse(t.exhaustive)
        self.assertIn("TRUNCATED", t.coverage_label)
        self.assertIn("lower bound", t.coverage_label)
        # A non-overflowing exhaustive trace keeps the strong claim.
        ok = P.parse_bytes(batched(REALISTIC, overflow=False), "m", P.MODE_EXHAUSTIVE)
        self.assertIs(ok.overflow, False)
        self.assertTrue(ok.exhaustive)
        self.assertEqual(ok.coverage_label, "exhaustive")

    def test_undetermined_by_default_and_not_claimed_exhaustive(self):
        t = P.parse_bytes(batched(REALISTIC), "mem")
        self.assertEqual(t.mode, P.MODE_UNDETERMINED)
        self.assertFalse(t.exhaustive)
        self.assertIn("lower bound", t.coverage_label)

    def test_exhaustive_and_sampled_labels(self):
        self.assertEqual(P.parse_bytes(batched(), "m", P.MODE_EXHAUSTIVE).coverage_label, "exhaustive")
        s = P.parse_bytes(batched(), "m", P.MODE_SAMPLED, 100)
        self.assertIn("sampled@100us", s.coverage_label)
        self.assertIn("lower bound", s.coverage_label)

    def test_sidecar_supplies_mode_and_absent_sidecar_is_undetermined(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.trace")
            with open(p, "wb") as fh:
                fh.write(batched(REALISTIC))
            self.assertEqual(P.load_sidecar(p), (P.MODE_UNDETERMINED, None))
            with open(p + ".json", "w") as fh:
                json.dump({"mode": "sampled", "sampling_us": 100}, fh)
            self.assertEqual(P.load_sidecar(p), (P.MODE_SAMPLED, 100))
            with open(p + ".json", "w") as fh:
                json.dump({"mode": "nonsense"}, fh)
            self.assertEqual(P.load_sidecar(p), (P.MODE_UNDETERMINED, None))


class TestContinuousLayout(unittest.TestCase):
    def test_inline_method_records_are_parsed(self):
        rows = REALISTIC
        body = b"SLOW\xf3\x00 \x00" + b"\x00" * 12
        for c, n, s, f in rows:
            body += b"\x00\x01V\x00" + ("%s\t%s\t%s\t%s\n" % (c, n, s, f)).encode()
        t = P.parse_bytes(body, "m", P.MODE_EXHAUSTIVE)
        self.assertEqual(t.layout, P.LAYOUT_CONTINUOUS)
        self.assertEqual(t.distinct, len(rows))
        self.assertEqual(len(t.framework()), 5)
        self.assertIsNone(t.num_method_calls)  # no preamble: honestly absent
        self.assertEqual(t.coverage_label, "exhaustive")

    def test_torn_trailing_record_is_dropped_not_half_read(self):
        body = b"SLOW\xf3\x00 \x00" + b"\x00" * 12
        body += b"android.view.View\tdraw\t()V\tView.java\n"
        body += b"android.view.View\tmeasu"  # cut by a flush boundary
        t = P.parse_bytes(body, "m", P.MODE_EXHAUSTIVE)
        self.assertEqual(t.distinct, 1)

    def test_garbage_around_records_is_ignored(self):
        body = b"SLOW\xf3\x00 \x00" + bytes(range(256)) * 4
        body += b"android.view.View\tdraw\t()V\tView.java\n"
        body += b"\x00\x00\x00\x00\x00\x00\x00\x00" * 32
        t = P.parse_bytes(body, "m", P.MODE_EXHAUSTIVE)
        self.assertEqual(t.distinct, 1)
        self.assertEqual(sum(t.rejected.values()), 0)


class TestSetArithmetic(unittest.TestCase):
    def sets(self, *specs):
        return [P.method_keys(P.parse_bytes(batched(s), "m").framework()) for s in specs]

    def test_jaccard(self):
        a, b = {1, 2, 3}, {2, 3, 4}
        self.assertAlmostEqual(P.jaccard(a, b), 2 / 4)
        self.assertEqual(P.jaccard(a, a), 1.0)
        self.assertEqual(P.jaccard(set(), set()), 1.0)

    def test_convergence_is_monotone_and_ends_at_the_union(self):
        s1, s2, s3 = self.sets(REALISTIC[:2], REALISTIC[1:4], REALISTIC)
        curve = P.convergence([s1, s2, s3])
        self.assertEqual(curve, sorted(curve))
        self.assertEqual(curve[-1], len(s1 | s2 | s3))
        self.assertEqual(curve[0], len(s1))


class TestRealTraces(unittest.TestCase):
    """Runs against a real capture when one is present; skipped otherwise.

    These pin the *shape* of a real ART file rather than a fixture, which is
    the part a hand-built fixture can get wrong.
    """

    RUNS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "runs")

    def captures(self):
        if not os.path.isdir(self.RUNS):
            return []
        out = []
        for name in sorted(os.listdir(self.RUNS)):
            if name.endswith(".trace"):
                out.append(os.path.join(self.RUNS, name))
        return out

    def test_every_real_capture_parses_and_rejects_nothing_it_should_not(self):
        paths = self.captures()
        if not paths:
            self.skipTest("no captures in trace/runs/")
        for p in paths:
            with self.subTest(path=os.path.basename(p)):
                if os.path.getsize(p) == 0:
                    # A recorded failed capture. Asserted separately, because
                    # "0 bytes" must raise rather than parse as "no methods".
                    with self.assertRaises(ValueError):
                        P.parse_file(p)
                    continue
                t = P.parse_file(p)
                self.assertIn(t.layout, (P.LAYOUT_BATCHED, P.LAYOUT_CONTINUOUS))
                self.assertGreater(t.size, 0)
                if t.layout == P.LAYOUT_BATCHED:
                    # Complete row accounting: every table row is either a
                    # distinct method, a duplicate naming of one, or rejected
                    # with a reason. Nothing is dropped silently.
                    self.assertEqual(
                        t.table_rows, t.distinct + t.duplicates + sum(t.rejected.values())
                    )
                self.assertFalse(
                    [m for m in t.methods if re.fullmatch(r"\d+", m.cls)],
                    "a digit-named class survived parsing",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
