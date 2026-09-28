#!/bin/sh
# negative-tests.sh -- prove that validate.mjs can actually fail.
#
# A validator that accepts everything is worse than no validator, and a
# schema-check that only ever sees well-formed input proves nothing. Each case
# below takes a known-good fixture, breaks exactly one thing, and asserts that
# the validator REJECTS the result. A single wrongly-accepted case fails this
# script and therefore fails `make test`.
#
# Cases are not limited to JSON Schema assertions: several target the
# cross-field invariants in validate.mjs, which is the point -- the invariants
# are where a plausible-looking lie would otherwise slip through.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
VALIDATOR="$HERE/validate.mjs"
EX="$HERE/../schema/examples"
MINIMAL="$EX/minimal.recording.json"
FULL="$EX/full.recording.json"
TMP="$HERE/../.tmp-test"

NODE=${NODE:-node}
command -v "$NODE" >/dev/null 2>&1 || { echo "node not found"; exit 2; }

rm -rf "$TMP"
mkdir -p "$TMP" || exit 2

PASS=0
FAIL=0

# mutate FILE OUT JSNAME JSVALUE -- set a top-level field to a JSON value
mutate() {
	"$NODE" -e '
		const fs = require("fs");
		const [f, o, expr] = process.argv.slice(1);
		const d = JSON.parse(fs.readFileSync(f, "utf8"));
		eval(expr);
		fs.writeFileSync(o, JSON.stringify(d, null, 2));
	' "$1" "$2" "$3" || { echo "  SETUP ERROR for $4"; exit 2; }
}

neg() {
	# neg NAME FILE
	if "$NODE" "$VALIDATOR" "$2" >"$TMP/out.$1" 2>&1; then
		echo "  FAIL $1: validator ACCEPTED a recording it must reject"
		sed 's/^/       /' "$TMP/out.$1"
		FAIL=$((FAIL + 1))
	else
		echo "  ok   $1: rejected"
		PASS=$((PASS + 1))
	fi
}

echo "== negative tests: every case below MUST be rejected"

mutate "$MINIMAL" "$TMP/missing-key.json" \
	'delete d.environment;' missing_required_key
neg missing_required_key "$TMP/missing-key.json"

mutate "$MINIMAL" "$TMP/extra-key.json" \
	'd.surprise = 1;' additional_property
neg additional_property "$TMP/extra-key.json"

mutate "$MINIMAL" "$TMP/synthetic-lies.json" \
	'd.provenance.execution_performed = true;' synthetic_claims_execution
neg synthetic_claims_execution "$TMP/synthetic-lies.json"

mutate "$MINIMAL" "$TMP/bad-terminal.json" \
	'd.lifecycle.terminal = "L3_STEADY_STATE";' terminal_contradicts_events
neg terminal_contradicts_events "$TMP/bad-terminal.json"

mutate "$MINIMAL" "$TMP/bad-start.json" \
	'd.lifecycle.activity_started = 42;' convenience_field_contradicts_events
neg convenience_field_contradicts_events "$TMP/bad-start.json"

# Claim JNI calls while saying none were obtained.
mutate "$MINIMAL" "$TMP/jni-lies.json" \
	'd.synthetic=false; d.provenance.execution_performed=true; d.provenance.synthetic_reason=null;
	 d.capture.install.method="adb_install"; d.capture.launch.method="am_start";
	 d.capture_quality.completeness="complete"; d.capture_quality.warnings=["real capture"];
	 d.app.is_synthetic=false; d.jni.obtained=true;
	 d.jni.calls=[{seq:0,t_mono_ms:1,direction:"java_to_native",symbol:"Java_x_y",source:"adb_shell",tier:"T1_LOGCAT"}];' \
	jni_obtained_contradiction
neg jni_obtained_contradiction "$TMP/jni-lies.json"

# Claim a filesystem access trace while saying none was obtained.
mutate "$MINIMAL" "$TMP/fs-lies.json" \
	'd.synthetic=false; d.provenance.execution_performed=true; d.provenance.synthetic_reason=null;
	 d.capture.install.method="adb_install"; d.capture.launch.method="am_start";
	 d.capture_quality.completeness="complete"; d.capture_quality.warnings=["real capture"];
	 d.app.is_synthetic=false;
	 d.filesystem.accesses=[{seq:0,t_mono_ms:0,op:"open",path:"/x",size_bytes:0,result:"ok",source:"adb_shell",tier:"T1_LOGCAT"}];' \
	fs_trace_contradiction
neg fs_trace_contradiction "$TMP/fs-lies.json"

mutate "$FULL" "$TMP/bad-pointer.json" \
	'd.substrate_probe_hits=[{assumption_id:"SUB.TIME.MONOTONIC",family:"SUB.TIME",hit_count:1,
	   evidence:["/lifecycle/events/99/t_mono_ms"],source:"analyst_annotation",tier:"T3_INFERRED"}];
	 d.summary.families_touched=["SUB.TIME"]; d.summary.distinct_families_touched=1;' \
	evidence_pointer_unresolvable
neg evidence_pointer_unresolvable "$TMP/bad-pointer.json"

mutate "$FULL" "$TMP/bad-family.json" \
	'd.substrate_probe_hits[0].family = "SUB.HW";
	 d.summary.families_touched = [...new Set(d.substrate_probe_hits.map(h=>h.family))].sort();
	 d.summary.distinct_families_touched = d.summary.families_touched.length;' \
	family_contradicts_id
neg family_contradicts_id "$TMP/bad-family.json"

mutate "$FULL" "$TMP/bad-id.json" \
	'd.substrate_probe_hits[0].assumption_id = "not-an-id";
	 d.summary.families_touched = [...new Set(d.substrate_probe_hits.map(h=>h.family))].sort();
	 d.summary.distinct_families_touched = d.summary.families_touched.length;' \
	malformed_assumption_id
neg malformed_assumption_id "$TMP/bad-id.json"

mutate "$FULL" "$TMP/bad-summary.json" \
	'd.summary.event_count = 999;' summary_disagrees_with_arrays
neg summary_disagrees_with_arrays "$TMP/bad-summary.json"

mutate "$FULL" "$TMP/out-of-order.json" \
	'd.lifecycle.events[1].t_mono_ms = 99999;' events_out_of_order
neg events_out_of_order "$TMP/out-of-order.json"

mutate "$FULL" "$TMP/impossible-verdict.json" \
	'd.environment.attestation.observed_verdict = "MEETS_STRONG_INTEGRITY";' \
	container_claims_strong_integrity
neg container_claims_strong_integrity "$TMP/impossible-verdict.json"

mutate "$FULL" "$TMP/leak.json" \
	'd.network.attempts[1].path = "/v1/x?token=SECRET";' query_string_in_path
neg query_string_in_path "$TMP/leak.json"

mutate "$FULL" "$TMP/bodies.json" \
	'd.network.attempts[0].body_captured = true;' body_captured
neg body_captured "$TMP/bodies.json"

mutate "$FULL" "$TMP/bad-header.json" \
	'd.network.attempts[1].headers.authorization = "Bearer SECRET";' unallowlisted_header
neg unallowlisted_header "$TMP/bad-header.json"

mutate "$FULL" "$TMP/window.json" \
	'd.capture.observation_window_ms = 100;' event_outside_observation_window
neg event_outside_observation_window "$TMP/window.json"

# T0_DIRECT with neither a root shell nor a debuggable build.
mutate "$MINIMAL" "$TMP/t0-no-root.json" \
	'd.synthetic=false; d.provenance.execution_performed=true; d.provenance.synthetic_reason=null;
	 d.provenance.capture_script_sha256 = "a".repeat(64);
	 d.app.is_synthetic=false; d.app.apk_paths=["/data/app/x/base.apk"];
	 d.capture.install.method="adb_install"; d.capture.launch.method="am_start";
	 d.capture.root_shell=false; d.app.debuggable=false;
	 d.capture_quality.completeness="complete"; d.capture_quality.warnings=["real capture"];
	 d.classes.loaded=["a.B"]; d.classes.loaded_obtained=true;
	 d.native.libraries_loaded=["/x/libc.so"]; d.native.mapping_obtained=true; d.native.obtained=true;
	 d.summary={lifecycle_terminal:d.lifecycle.terminal,time_to_first_frame_ms:null,
	   event_count:d.lifecycle.events.length,network_attempt_count:0,network_destinations:0,
	   exception_count:0,fatal_count:0,class_count:1,native_library_count:1,
	   distinct_families_touched:0,families_touched:[]};
	 d.filesystem.access_trace_obtained=true;
	 d.filesystem.accesses=[{seq:0,t_mono_ms:0,op:"open",path:"/x",size_bytes:0,result:"ok",source:"adb_shell",tier:"T0_DIRECT"}];
	 d.jni.obtained=true;
	 d.jni.calls=[{seq:0,t_mono_ms:0,direction:"java_to_native",symbol:"J_x",source:"adb_shell",tier:"T1_LOGCAT"}];' \
	t0_direct_without_root
neg t0_direct_without_root "$TMP/t0-no-root.json"

# A real-looking capture that claims completeness while declaring a signal
# unimplemented.
mutate "$FULL" "$TMP/false-complete.json" \
	'd.synthetic=false; d.provenance.execution_performed=true; d.provenance.synthetic_reason=null;
	 d.provenance.capture_script_sha256 = "b".repeat(64);
	 d.app.is_synthetic=false;
	 d.capture_quality.completeness = "complete";' complete_while_unimplemented
neg complete_while_unimplemented "$TMP/false-complete.json"

# LF_UNRESOLVED as a free pass. Guarded on synthetic: a synthetic fixture may
# legitimately be unresolved, but a real capture that was COMPLETE and did
# obtain lifecycle logcat was determinable, so claiming otherwise is a
# non-measurement dressed up as a measurement.
mutate "$FULL" "$TMP/free-pass.json" \
	'd.synthetic=false; d.provenance.execution_performed=true; d.provenance.synthetic_reason=null;
	 d.provenance.capture_script_sha256 = "c".repeat(64);
	 d.app.is_synthetic=false;
	 d.capture.install.method="adb_install"; d.capture.launch.method="am_start";
	 d.capture_quality.completeness = "complete";
	 d.capture_quality.signals_obtained = [...new Set([...d.capture_quality.signals_obtained, "lifecycle_logcat"])];
	 d.lifecycle.terminal = "LF_UNRESOLVED"; d.summary.lifecycle_terminal = "LF_UNRESOLVED";' \
	lf_unresolved_without_cause
neg lf_unresolved_without_cause "$TMP/free-pass.json"

# ... and the converse: LF_UNRESOLVED IS permitted when logcat was unavailable.
mutate "$FULL" "$TMP/unresolved-legit.json" \
	'd.synthetic=false; d.provenance.execution_performed=true; d.provenance.synthetic_reason=null;
	 d.provenance.capture_script_sha256 = "c".repeat(64);
	 d.app.is_synthetic=false;
	 d.capture.install.method="adb_install"; d.capture.launch.method="am_start";
	 d.capture_quality.completeness = "degraded";
	 d.capture_quality.signals_obtained = d.capture_quality.signals_obtained.filter(s => s !== "lifecycle_logcat");
	 d.lifecycle.terminal = "LF_UNRESOLVED"; d.summary.lifecycle_terminal = "LF_UNRESOLVED";
	 d.capture_quality.warnings = [...new Set([...d.capture_quality.warnings, "logcat -d returned nothing"])];' \
	unresolved_is_permitted_when_logcat_absent
if "$NODE" "$VALIDATOR" "$TMP/unresolved-legit.json" >"$TMP/out.unresolved-legit" 2>&1; then
	echo "  ok   unresolved_is_permitted_when_logcat_absent: accepted, as intended"
	PASS=$((PASS + 1))
else
	echo "  FAIL unresolved_is_permitted_when_logcat_absent: validator over-rejected."
	sed 's/^/       /' "$TMP/out.unresolved-legit"
	FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
# substrate_policy: the optional substrate-only block. It is optional, and every
# constraint inside it is a `const` or an `enum`, so each of these is a place
# where a plausible-looking lie could otherwise pass. If a future edit relaxes
# any of them, the corresponding case below goes green-when-red and this script
# fails.
# ---------------------------------------------------------------------------
SHIM_LEFT="${HERE}/../../shim/recordings/differential-left.fabricated.recording.json"
if [ -f "$SHIM_LEFT" ]; then
	mutate "$SHIM_LEFT" "$TMP/policy-ok.json" \
		'd.substrate_policy.axis_declarations[0].governs = ["app"];' policy_axis_may_not_govern_the_app_class
neg policy_axis_may_not_govern_the_app_class "$TMP/policy-ok.json"

	mutate "$SHIM_LEFT" "$TMP/policy-egress.json" \
		'd.substrate_policy.invariants.egress = "allowed_by_policy";' policy_egress_invariant_must_be_structural
neg policy_egress_invariant_must_be_structural "$TMP/policy-egress.json"

	mutate "$SHIM_LEFT" "$TMP/policy-body.json" \
		'd.substrate_policy.invariants.bodies_captured = true;' policy_may_not_capture_bodies
neg policy_may_not_capture_bodies "$TMP/policy-body.json"

	mutate "$SHIM_LEFT" "$TMP/policy-value.json" \
		'd.substrate_policy.identity = "loudest_possible";' policy_axis_value_must_be_in_the_enum
neg policy_axis_value_must_be_in_the_enum "$TMP/policy-value.json"

	mutate "$SHIM_LEFT" "$TMP/policy-version.json" \
		'd.substrate_policy.policy_version = "1";' policy_version_must_be_an_integer
neg policy_version_must_be_an_integer "$TMP/policy-version.json"

	mutate "$SHIM_LEFT" "$TMP/policy-required.json" \
		'delete d.substrate_policy.reproducible;' policy_must_declare_reproducibility
neg policy_must_declare_reproducibility "$TMP/policy-required.json"

	mutate "$SHIM_LEFT" "$TMP/policy-scaled.json" \
		'd.substrate_policy.time = {mode:"scaled", args:{numerator:3, denominator:0}};' policy_scale_denominator_may_not_be_zero
neg policy_scale_denominator_may_not_be_zero "$TMP/policy-scaled.json"

	# And the control: the unmodified shim recording must still be ACCEPTED, or
	# the six cases above would be passing for the wrong reason. A negative suite
	# with no positive control is a suite that proves nothing.
	if "$NODE" "$VALIDATOR" "$SHIM_LEFT" >"$TMP/out.policy-control" 2>&1; then
		echo "  ok   policy_control_substrate_recording_is_accepted: accepted, as intended"
		PASS=$((PASS + 1))
	else
		echo "  FAIL policy_control_substrate_recording_is_accepted: the schema rejects a \
recording the shim itself produces."
		sed 's/^/       /' "$TMP/out.policy-control"
		FAIL=$((FAIL + 1))
	fi
fi

# A well-formed JSON document that is not a recording at all.
printf '{"hello":"world"}\n' >"$TMP/not-a-recording.json"
neg not_a_recording "$TMP/not-a-recording.json"

# A file that does not exist.
neg missing_file "$TMP/does-not-exist.json"

echo "-- $PASS case(s) correctly rejected, $FAIL wrongly accepted"
if [ "$FAIL" -ne 0 ]; then
	echo "== negative tests: FAIL"
	exit 1
fi
echo "== negative tests: PASS"
rm -rf "$TMP"
exit 0
