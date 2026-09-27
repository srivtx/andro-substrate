#!/bin/sh
# adb-recorder.sh -- ground-truth recorder for andro-substrate.
#
#   Implements oracle/RECORDING.md v1 by driving `adb` against a REAL Android
#   reference environment (redroid container, AVD, or a physical / cloud device).
#
#   The rule that governs every line below: FAIL LOUDLY. A step that cannot do
#   what it claims writes an entry into capture_quality.unobserved with a
#   reason_code. A step that was REQUIRED and produced nothing sets
#   empty_failure and forces a non-zero exit. There is deliberately no code
#   path that emits a well-formed recording describing an execution that did
#   not happen, and no code path that reports an empty observation array
#   without also saying, in the same document, that it is unobserved.
#
# Dependencies: /bin/sh, adb, awk, sed, cut, sort, tr, wc, and (for SHA-256)
#   one of sha256sum / shasum / openssl. No jq, no python, no node required
#   (node is used only for the optional self-validation step).
#
# This script has NEVER been executed against a device: it was authored on
# macOS, where neither adb nor KVM is available. It has been syntax-checked
# with `sh -n` and its JSON assembly paths are exercised indirectly by the
# negative tests in the Makefile. Treat the first real run as a debug session.

set -u

PROG=adb-recorder.sh
VER=0.1.0
FORMAT=andro-substrate.ground-truth/1
TAB=$(printf '\t')

# ---------------------------------------------------------------- defaults
APK=""
APK_DIR=""
OUT=""
PKG=""
ACT=""
DURATION="${DURATION:-90}"
SNAPSHOT_AT="${SNAPSHOT_AT:-8}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"
SNAPSHOT_TIMEOUT="${SNAPSHOT_TIMEOUT:-30}"
HOSTNAMES="${HOSTNAMES:-hmac}"
SERIAL="${SERIAL:-}"
# Only an operator-supplied serial may be used to TARGET a device. The serial
# auto-detected from the device is recorded but never used for targeting.
ADB_TARGET="$SERIAL"
MITM=false
ALLOW_INCOMPLETE=false
UNINSTALL_AFTER=false
KEEP_APK=false
SETTLE_SECONDS="${SETTLE_SECONDS:-3}"
ANDRO_ENV_KIND="${ANDRO_ENV_KIND:-}"

EMPTY_FAILURE=false
FAILED_STEPS=0
STEP_NO=0
CLOCK_RES_MS=1

# ----------------------------------------------------------------- output
# Warnings and unobserved-signals are accumulated as raw text in files, never
# in shell variables: a JSON string containing a space would break any
# word-splitting accumulation loop, and the failure mode is silent corruption.
WORK=""
WARNINGS_FILE=""
UNOBSERVED_FILE=""
OBTAINED_FILE=""

info() { printf '%s: %s\n' "$PROG" "$*" >&2; }

# adev -- run adb against the target device, quoting every argument. Exists so
# that neither the binary nor --serial ever goes through word splitting.
# shellcheck disable=SC2317  # called as a command throughout
adev() {
	if [ -n "$ADB_TARGET" ]; then
		adb -s "$ADB_TARGET" "$@"
	else
		adb "$@"
	fi
}

step() {
	STEP_NO=$((STEP_NO + 1))
	printf '%s: --- step %s: %s\n' "$PROG" "$STEP_NO" "$*" >&2
}

flatten() { tr '\n\t' '  ' | tr -s ' ' | cut -c1-800; }

warn() {
	printf '%s: warn: %s\n' "$PROG" "$1" >&2
	printf '%s\n' "$1" | flatten >>"$WARNINGS_FILE"
}

# warn_unobserved SIGNAL REASON_CODE TEXT
# shellcheck disable=SC2317  # called as a command
warn_unobserved() {
	printf '%s\t%s\t%s\n' "$1" "$2" "$3" | flatten | {
		read -r _sig _code _txt
		printf '%s\t%s\t%s\n' "$_sig" "$_code" "$_txt" >>"$UNOBSERVED_FILE"
	}
}

mark_obtained() {
	case " $(cat "$OBTAINED_FILE" 2>/dev/null)" in
	*" $1 "*) return 0 ;;
	esac
	printf '%s\n' "$1" >>"$OBTAINED_FILE"
}

required_fail() {
	# required_fail REASON [SIGNAL REASON_CODE]
	EMPTY_FAILURE=true
	FAILED_STEPS=$((FAILED_STEPS + 1))
	printf '%s: REQUIRED STEP FAILED: %s\n' "$PROG" "$1" >&2
	printf '%s\n' "$1" | flatten >>"$WARNINGS_FILE"
	if [ "$#" -ge 3 ]; then warn_unobserved "$2" "$3" "$1"; fi
	return 0
}

soft_fail() {
	FAILED_STEPS=$((FAILED_STEPS + 1))
	printf '%s: DEGRADED: %s\n' "$PROG" "$1" >&2
	printf '%s\n' "$1" | flatten >>"$WARNINGS_FILE"
	return 0
}

# ------------------------------------------------------------- JSON helpers
# json_str: read stdin, write one quoted+escaped JSON string on stdout.
# Escape order matters and is load-bearing:
#   1. control characters -> space   (so they cannot be introduced later)
#   2. backslash          -> \\      (must precede quotes)
#   3. double quote       -> \"      (must follow backslashes)
json_str() {
	LC_ALL=C awk '
		BEGIN { printf "\""; first = 1 }
		{
			if (!first) printf "\\n"
			first = 0
			s = $0
			gsub(/[\001-\010\013\014\016-\037\177]/, " ", s)
			gsub(/\\/, "\\\\\\\\", s)
			gsub(/"/, "\\\\\\"", s)
			printf "%s", s
		}
		END { printf "\"" }
	'
}

jstr() { printf '%s' "$1" | json_str; }
jstr_or_null() { if [ -n "$1" ]; then printf '%s' "$1" | json_str; else printf 'null'; fi; }
jstr_file() { if [ -s "$1" ]; then json_str <"$1"; else printf '""'; fi; }
jnum() { if [ -n "$1" ]; then printf '%s' "$1"; else printf 'null'; fi; }
jbool() { if [ "$1" = "true" ]; then printf 'true'; else printf 'false'; fi; }

# json_str_array: newline-separated stdin -> JSON array of strings
json_str_array() {
	LC_ALL=C awk '
		BEGIN { printf "["; first = 1 }
		NF {
			if (!first) printf ", "
			first = 0
			s = $0
			gsub(/[\001-\010\013\014\016-\037\177]/, " ", s)
			gsub(/\\/, "\\\\\\\\", s)
			gsub(/"/, "\\\\\\"", s)
			printf "\"%s\"", s
		}
		END { printf "]" }
	'
}

have() { command -v "$1" >/dev/null 2>&1; }
die() { printf '%s: FATAL: %s\n' "$PROG" "$*" >&2; exit 2; }

# ------------------------------------------------------------------ timing
# now_ms: best-effort epoch milliseconds. The resolution actually obtained is
# NOT assumed to be 1 ms; it is reported in clock.monotonic_resolution_ms so
# that downstream timing claims are bounded by what the host can deliver.
now_ms() {
	_d=$(date +%s%3N 2>/dev/null)
	case "$_d" in
	*[!0-9]* | '') ;;
	*)
		CLOCK_RES_MS=1
		printf '%s' "$_d"
		return 0
		;;
	esac
	if [ -n "${EPOCHREALTIME:-}" ]; then
		CLOCK_REALTIME_PORTABLE="${EPOCHREALTIME}"
		CLOCK_RES_MS=1
		printf '%s' "$CLOCK_REALTIME_PORTABLE" | tr -d '.'
		return 0
	fi
	CLOCK_RES_MS=1000
	LC_ALL=C awk 'BEGIN { printf "%.0f", systime() * 1000 }'
}

utc_now() { date -u +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || printf '1970-01-01T00:00:00.000Z'; }

sha256_of() {
	if have sha256sum; then sha256sum "$1" 2>/dev/null | cut -d' ' -f1
	elif have shasum; then shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1
	elif have openssl; then openssl dgst -sha256 "$1" 2>/dev/null | sed 's/.*= *//'
	fi
}

# ------------------------------------------------------------------ usage
usage() {
	cat <<'USAGE'
adb-recorder.sh -- ground-truth recorder for andro-substrate (RECORDING.md v1)

REQUIRED (one of):
  --apk FILE        a single .apk to install
  --apk-dir DIR     directory of .apk files; its basename is the package hint
  --out FILE.json   where to write the recording

OPTIONS:
  --package NAME      package under test (otherwise detected after install)
  --activity NAME     component to launch (otherwise resolved on device)
  --duration SECONDS  observation window after the launch intent (default 90)
  --snapshot-at SECS  mid-run /proc snapshot time, 0 disables (default 8)
  --boot-timeout SECS wait for boot (default 300)
  --snapshot-timeout S per-probe timeout in seconds (default 30)
  --serial SERIAL     adb device serial
  --hostnames MODE    plain | hmac | none   (default hmac)
  --mitm              install an intercepting proxy AND trust a user CA.
                      Off by default: it changes app behaviour for exactly the
                      cert-pinning and NSC-assuming apps we most need to see.
  --uninstall-after   remove the app once the recording is written
  --allow-incomplete  exit 0 even when a required step failed
  --help

ENVIRONMENT: DURATION SNAPSHOT_AT BOOT_TIMEOUT SNAPSHOT_TIMEOUT HOSTNAMES
             SERIAL ANDRO_ENV_KIND (physical_device|cloud_device_farm|...)

TIMING SEMANTICS
  boot wait      up to BOOT_TIMEOUT seconds for sys.boot_completed=1 AND a
                 responsive package manager. Not part of the observation window.
  observation    DURATION seconds, starting at the instant the launch intent is
     window      accepted. All lifecycle timestamps are relative to t=0 there.
  snapshot       SNAPSHOT_AT seconds after t=0, taken while the process is
                 still alive. Only a live snapshot can see fds and threads.
  collection     bounded by SNAPSHOT_TIMEOUT per probe, after the window.

EXIT CODES: 0 ok | 2 usage/environment | 3 a required step produced nothing
            4 the recording failed self-validation
USAGE
}

# --------------------------------------------------------- arg parsing
while [ $# -gt 0 ]; do
	case "$1" in
	--apk) APK="${2:-}"; shift 2 || die "--apk needs a value" ;;
	--apk-dir) APK_DIR="${2:-}"; shift 2 || die "--apk-dir needs a value" ;;
	--out) OUT="${2:-}"; shift 2 || die "--out needs a value" ;;
	--package | --pkg) PKG="${2:-}"; shift 2 || die "--package needs a value" ;;
	--activity | --act) ACT="${2:-}"; shift 2 || die "--activity needs a value" ;;
	--duration | -d) DURATION="${2:-}"; shift 2 || die "--duration needs a value" ;;
	--snapshot-at) SNAPSHOT_AT="${2:-}"; shift 2 || die "--snapshot-at needs a value" ;;
	--boot-timeout) BOOT_TIMEOUT="${2:-}"; shift 2 || die "--boot-timeout needs a value" ;;
	--snapshot-timeout) SNAPSHOT_TIMEOUT="${2:-}"; shift 2 || die "--snapshot-timeout needs a value" ;;
	--serial | -s) SERIAL="${2:-}"; shift 2 || die "--serial needs a value" ;;
	--hostnames) HOSTNAMES="${2:-}"; shift 2 || die "--hostnames needs a value" ;;
	--mitm) MITM=true; shift ;;
	--uninstall-after) UNINSTALL_AFTER=true; shift ;;
	--keep-apk) KEEP_APK=true; shift ;;
	--allow-incomplete) ALLOW_INCOMPLETE=true; shift ;;
	--help | -h) usage; exit 0 ;;
	*) printf '%s: unknown argument %s (try --help)\n' "$PROG" "$1" >&2; exit 2 ;;
	esac
done

[ -n "$APK" ] || [ -n "$APK_DIR" ] || { usage >&2; die "one of --apk or --apk-dir is required"; }
[ -n "$OUT" ] || { usage >&2; die "--out is required"; }

for _n in "$DURATION" "$SNAPSHOT_AT" "$BOOT_TIMEOUT" "$SNAPSHOT_TIMEOUT"; do
	case "$_n" in
	'' | *[!0-9]*) die "a numeric option got a non-numeric value: '$_n'" ;;
	esac
done
[ "$DURATION" -ge 5 ] || die "DURATION must be >= 5 (got $DURATION): a shorter window cannot reach first draw on a cold start, and a short window would silently manufacture LF_* failures"
case "$HOSTNAMES" in
plain | hmac | none) ;;
*) die "--hostnames must be plain, hmac or none" ;;
esac

have adb || die "adb not found on PATH (install Android platform-tools)"
have awk || die "awk not found"
have timeout || printf '%s: warn: coreutils timeout missing; per-probe timeouts are DISABLED and a hung adb will hang this recorder\n' "$PROG" >&2

# ------------------------------------------------------------ resolve apk
if [ -z "$APK" ]; then
	[ -d "$APK_DIR" ] || die "--apk-dir '$APK_DIR' is not a directory"
	# set -- keeps the glob expansion while handling spaces in filenames;
	# `ls | head` would not, and would also break on a leading-dash name.
	set -- "$APK_DIR"/*.apk
	if [ ! -f "$1" ]; then die "no .apk found in '$APK_DIR'"; fi
	APK="$1"
	[ -n "$PKG" ] || PKG=$(basename "$APK_DIR")
fi
[ -f "$APK" ] || die "apk not found: $APK"
[ -r "$APK" ] || die "apk not readable: $APK"

APK_SHA=$(sha256_of "$APK")
APK_SIZE=$(wc -c <"$APK" | tr -d ' ')
SELF_SHA=$(sha256_of "$0")
if [ ${#APK_SHA} -ne 64 ]; then
	printf '%s: FATAL: cannot compute a SHA-256 of the APK (no sha256sum, shasum or openssl). A recording that cannot be tied to the analysed artifact is not admissible as ground truth.\n' "$PROG" >&2
	exit 2
fi
if [ ${#SELF_SHA} -ne 64 ]; then
	printf '%s: warn: cannot digest this script; provenance.capture_script_sha256 will be null and the capture cannot be tied to recorder source\n' "$PROG" >&2
	SELF_SHA=""
fi

# ------------------------------------------------------------- workspace
WORK=$(mktemp -d "${TMPDIR:-/tmp}/andro-oracle.XXXXXX") || die "mktemp failed"
# shellcheck disable=SC2317  # invoked via the trap on the next line
cleanup() { [ -n "$WORK" ] && [ -d "$WORK" ] && rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

WARNINGS_FILE="$WORK/warnings.txt"
UNOBSERVED_FILE="$WORK/unobserved.tsv"
OBTAINED_FILE="$WORK/obtained.txt"
: >"$WARNINGS_FILE"
: >"$UNOBSERVED_FILE"
: >"$OBTAINED_FILE"

LOGCAT="$WORK/logcat.txt"
DPKG="$WORK/dumpsys_package.txt"
T_START_MS=$(now_ms)
T_START_UTC=$(utc_now)

# ==========================================================================
step "device presence and shell identity"
if ! adev get-state >/dev/null 2>&1; then
	info "adb devices: $(adev devices 2>&1 | tr '\n' ' ')"
	die "no adb device. Start redroid or an AVD container, or attach a real device, first."
fi
if [ -z "$SERIAL" ]; then
	SERIAL=$(adev shell getprop ro.serialno 2>/dev/null | tr -d '\r\n')
fi
DEV_MODEL=$(adev shell getprop ro.product.model 2>/dev/null | tr -d '\r\n')
SHELL_UID=$(adev shell id -u 2>/dev/null | tr -d '\r\n ')
ROOT_SHELL=false
[ "$SHELL_UID" = "0" ] && ROOT_SHELL=true
info "device='${SERIAL:-unknown}' model='${DEV_MODEL:-unknown}' shell_uid='${SHELL_UID:-unknown}' root=$ROOT_SHELL"

# ==========================================================================
step "wait for boot (timeout ${BOOT_TIMEOUT}s)"
BOOT_T0=$(now_ms)
BOOTED=false
_i=0
while [ "$_i" -lt "$BOOT_TIMEOUT" ]; do
	_bc=$(adev shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n ')
	_pm=$(adev shell pm path android 2>/dev/null | tr -d '\r\n')
	if [ "$_bc" = "1" ] && [ -n "$_pm" ]; then BOOTED=true; break; fi
	sleep 2
	_i=$((_i + 2))
done
BOOT_WAIT_MS=$(($(now_ms) - BOOT_T0))
if [ "$BOOTED" = true ]; then
	mark_obtained "boot_completed"
else
	required_fail "sys.boot_completed never became 1 within ${BOOT_TIMEOUT}s (last='${_bc:-none}')" "boot_completed" "timeout"
fi
info "boot wait ${BOOT_WAIT_MS}ms"

# ==========================================================================
step "environment snapshot"
# A probe is a recorded adb command. Its status is recorded even when it fails,
# because a failed probe is a documented gap, not a missing line of evidence.
# run_probe ID T_REL_MS COMMAND [SOURCE]
# shellcheck disable=SC2317  # called as a command
run_probe() {
	_p_id="$1"
	_p_t="${2:--1}"
	_p_cmd="$3"
	_p_src="${4:-adb_shell}"
	_p_out="$WORK/probe.out"
	_p_err="$WORK/probe.err"
	: >"$_p_out"
	: >"$_p_err"
	_p_cmd_q=$(printf "'%s'" "$(printf '%s' "$_p_cmd" | sed "s/'/'\\\\''/g")")
	_p_rc=0
	timeout "$SNAPSHOT_TIMEOUT" adev shell "$_p_cmd_q" >"$_p_out" 2>"$_p_err" || _p_rc=$?
	_p_status=ok
	case "$_p_rc" in
	0) ;;
	124 | 137) _p_status=timeout ;;
	*) _p_status=error ;;
	esac
	if [ "$_p_status" = ok ] && grep -qi 'permission denied\|operation not permitted' "$_p_out" "$_p_err" 2>/dev/null; then
		_p_status=permission_denied
	fi
	if [ "$_p_status" = ok ] && [ ! -s "$_p_out" ]; then
		_p_status=empty
	fi
	tr -c '[:print:]\n' '?' <"$_p_out" | cut -c1-8000 >"$_p_out.trunc"
	tr -c '[:print:]\n' '?' <"$_p_err" | cut -c1-500 >"$_p_err.trunc"
	if [ "$(wc -c <"$_p_out.trunc" | tr -d ' ')" -ge 8000 ]; then _p_trunc=true; else _p_trunc=false; fi
	{
		printf '    { "id": %s, "t_mono_ms": %s, "command": %s, "status": "%s", "source": "%s", "tier": "T2_SNAPSHOT", "output": %s, "output_truncated": %s, "error": %s }' \
			"$(jstr "$_p_id")" "$_p_t" "$(jstr "$_p_cmd")" "$_p_status" "$_p_src" \
			"$(jstr_file "$_p_out.trunc")" "$(jbool "$_p_trunc")" "$(jstr_file "$_p_err.trunc")"
		printf ',\n'
	} >>"$WORK/probes.json"
	case "$_p_status" in
	ok)
		mark_obtained "$_p_id"
		;;
	permission_denied)
		warn_unobserved "$_p_id" "insufficient_permission" "'$_p_cmd' was refused. This signal is UNOBSERVED, not absent."
		;;
	empty)
		printf '%s\tnot_implemented\t%s returned no output. Treated as unobserved rather than as a negative result.\n' "$_p_id" "$_p_cmd" | flatten | {
			read -r _s _c _t
			printf '%s\t%s\t%s\n' "$_s" "$_c" "$_t" >>"$UNOBSERVED_FILE"
		}
		;;
	timeout)
		warn_unobserved "$_p_id" "timeout" "'$_p_cmd' exceeded ${SNAPSHOT_TIMEOUT}s."
		;;
	esac
	return 0
}

: >"$WORK/probes.json"
run_probe env.boot_completed -1 "getprop sys.boot_completed"
run_probe env.getprop -1 "getprop"
run_probe env.uptime -1 "cat /proc/uptime"
run_probe env.selinux -1 "getenforce"
run_probe env.play_services -1 "pm list packages com.google.android.gms"
run_probe env.play_store -1 "pm list packages com.android.vending"
run_probe env.connectivity -1 "dumpsys connectivity"
run_probe env.abilist -1 "getprop ro.product.cpu.abilist"
run_probe env.battery -1 "dumpsys battery"
run_probe env.sensors -1 "dumpsys sensorservice"
run_probe env.gfx -1 "dumpsys gfxinfo"
run_probe env.mounts -1 "cat /proc/mounts"

GMS_PRESENT=false
adev shell pm list packages com.google.android.gms 2>/dev/null | grep -q 'com.google.android.gms' && GMS_PRESENT=true
mark_obtained "play_services_presence"
PLAY_STORE_PRESENT=false
adev shell pm list packages com.android.vending 2>/dev/null | grep -q 'com.android.vending' && PLAY_STORE_PRESENT=true

# shellcheck disable=SC2317  # called as a command
getprop() { adev shell getprop "$1" 2>/dev/null | tr -d '\r\n'; }
SDK_INT=$(getprop ro.build.version.sdk)
REL=$(getprop ro.build.version.release)
FINGERPRINT=$(getprop ro.build.fingerprint)
BUILD_ID=$(getprop ro.build.id)
BUILD_TYPE=$(getprop ro.build.type)
RO_SECURE=$(getprop ro.secure)
BOOT_STATE=$(getprop ro.boot.verifiedbootstate)
RO_HW=$(getprop ro.hardware)
RO_QEMU=$(getprop ro.kernel.qemu)
SERIAL_PROP=$(getprop ro.serialno)
SELINUX=$(adev shell getenforce 2>/dev/null | tr -d '\r\n')
[ -n "$SELINUX" ] || SELINUX="unknown"
ABILIST=$(getprop ro.product.cpu.abilist)

# Environment classification. The default is the CONSERVATIVE one: an
# unrecognised device is treated as an emulator, never as a real phone, because
# misclassifying a container as "real" would let it serve as an integrity oracle
# and quietly poison the whole study.
ENV_KIND=""
case "$ANDRO_ENV_KIND" in
physical_device | cloud_device_farm | redroid | emulator_avd | emulator_avd_playstore_image) ENV_KIND="$ANDRO_ENV_KIND" ;;
esac
if [ -z "$ENV_KIND" ]; then
	case "$RO_QEMU$RO_HW$SERIAL_PROP" in
	1* | *goldfish* | *ranchu* | *vbox86* | *generic_x86*) ENV_KIND="emulator_avd" ;;
	*redroid*) ENV_KIND="redroid" ;;
	esac
fi
if [ -z "$ENV_KIND" ]; then
	ENV_KIND=emulator_avd
	warn "could not classify the environment from its properties; defaulting to 'emulator_avd' and treating it as a CONTAMINATED oracle. Set ANDRO_ENV_KIND=physical_device if this really is a real device."
fi
[ "$ENV_KIND" = emulator_avd ] && [ "$PLAY_STORE_PRESENT" = true ] && ENV_KIND="emulator_avd_playstore_image"
IS_EMULATOR=true
IS_PHYSICAL=false
case "$ENV_KIND" in
physical_device | cloud_device_farm) IS_EMULATOR=false; IS_PHYSICAL=true ;;
esac
if [ "$IS_EMULATOR" = true ]; then
	warn "reference environment is '${ENV_KIND}', NOT a real phone. It cannot produce a hardware-backed integrity verdict, has no sensors, and apps that detect emulators may behave differently here than for a user. See docs/research-protocol.md threat T-04."
fi

# ==========================================================================
step "install"
if [ "$KEEP_APK" = true ]; then
	INSTALL_OUT=$(adev install -r "$APK" 2>&1)
	INSTALL_RC=$?
else
	INSTALL_OUT=$(adev install -r -t "$APK" 2>&1)
	INSTALL_RC=$?
fi
INSTALL_OK=false
if [ "$INSTALL_RC" -eq 0 ] && printf '%s' "$INSTALL_OUT" | grep -q '^Success'; then
	INSTALL_OK=true
else
	required_fail "adb install did not report Success (rc=$INSTALL_RC): $(printf '%s' "$INSTALL_OUT" | flatten)" "install_state" "not_implemented"
fi
mark_obtained "install_state"
info "install: $(printf '%s' "$INSTALL_OUT" | flatten)"

# Package identity is read from the INSTALLED package, never guessed from the
# filename. A wrong package name would make every other field a lie.
adev shell pm list packages 2>/dev/null | sed 's/^package://' | sort >"$WORK/pkgs_before.txt"
INSTALL_PKGS="$WORK/pkgs_installed.txt"
: >"$INSTALL_PKGS"

adev shell dumpsys package "$PKG" >"$DPKG" 2>/dev/null
if [ ! -s "$DPKG" ]; then
	# The hint was wrong. Diff the package list to find what we just added.
	adev shell pm list packages -3 2>/dev/null | sed 's/^package://' | sort >"$WORK/pkgs_after.txt"
	cand=$(comm -13 "$WORK/pkgs_before.txt" "$WORK/pkgs_after.txt" 2>/dev/null | head -n 1)
	if [ -n "$cand" ]; then
		warn "package hint '$PKG' is not installed; the newly appeared package '$cand' is being used instead. A wrong package name invalidates every other field, so this is flagged rather than silently corrected."
		PKG="$cand"
		adev shell dumpsys package "$PKG" >"$DPKG" 2>/dev/null
	fi
fi
if [ -n "$PKG" ] && [ ! -s "$DPKG" ]; then
	required_fail "dumpsys package '${PKG:-<unknown>}' produced no output; the package is not installed. Pass --package explicitly." "dumpsys_package" "not_found"
	PKG="${PKG:-unknown.package}"
else
	mark_obtained "dumpsys_package"
	info "package=$PKG"
fi

# shellcheck disable=SC2317  # called as a command
field_of() { sed -n "s/.*[[:space:]]$1=\([^[:space:]]*\).*/\1/p" "$DPKG" 2>/dev/null | head -n 1; }
VERSION_CODE=$(field_of versionCode)
VERSION_NAME=$(field_of versionName)
MIN_SDK=$(field_of minSdk)
TARGET_SDK=$(field_of targetSdk)
USER_ID=$(field_of userId)
DATA_DIR=$(field_of dataDir)
CODE_PATH=$(field_of codePath)
DEVPROT=$(field_of deviceProtectedDataDir)
DEBUGGABLE=false
grep -q 'DEBUGGABLE' "$DPKG" 2>/dev/null && DEBUGGABLE=true

sed -n 's/^ *\(android\.permission\.[A-Za-z_]*\|com\.android\.[A-Za-z_.-]*\): *granted=true.*/\1/p' "$DPKG" 2>/dev/null | sort -u >"$WORK/perms.txt"
sed -n 's/^ *\(android\.permission\.[A-Za-z_]*\|com\.android\.[A-Za-z_.-]*\): *granted=false.*/\1/p' "$DPKG" 2>/dev/null | sort -u >"$WORK/reqperms.txt"

PM_PATHS="$WORK/pmpaths.txt"
: >"$PM_PATHS"
if [ -n "$PKG" ]; then
	adev shell pm path "$PKG" 2>/dev/null | sed 's/^package://' | tr -d '\r' | grep '^/' >"$PM_PATHS"
	if [ -s "$PM_PATHS" ]; then mark_obtained "pm_path"; else required_fail "pm path $PKG produced no output" "pm_path" "not_found"; fi
fi

run_probe pkg.dumpsys_package -1 "dumpsys package $PKG"
run_probe pkg.pm_path -1 "pm path $PKG"

# ==========================================================================
step "resolve the launch activity"
LAUNCH_COMPONENT=""
RESOLVED_BY=""
if [ -n "$ACT" ]; then
	LAUNCH_COMPONENT="$ACT"
	RESOLVED_BY="operator"
else
	_c=$(adev shell cmd package resolve-activity --brief "$PKG" 2>/dev/null | tail -n 1 | tr -d '\r\n')
	case "$_c" in
	*/*) LAUNCH_COMPONENT="$_c"; RESOLVED_BY="cmd_package_resolve_activity" ;;
	esac
fi
if [ -z "$LAUNCH_COMPONENT" ]; then
	required_fail "no launchable activity resolved for $PKG; pass --activity. A recording that guesses its entry point measures a different app." "lifecycle_logcat" "not_found"
else
	info "launch component: $LAUNCH_COMPONENT"
fi

# ==========================================================================
step "pre-launch state"
adev shell dumpsys window windows >"$WORK/dumpsys_window.txt" 2>/dev/null
if [ -s "$WORK/dumpsys_window.txt" ]; then
	mark_obtained "dumpsys_window"
else
	warn_unobserved "dumpsys_window" "not_implemented" "dumpsys window windows produced no output"
fi
adev shell dumpsys netstats detail >"$WORK/netstats.txt" 2>/dev/null
mark_obtained "dumpsys_netstats"
adev shell dumpsys connectivity >"$WORK/connectivity.txt" 2>/dev/null
mark_obtained "dumpsys_connectivity"
adev shell ls -lZ "/data/user/0/$PKG" >"$WORK/appdir.txt" 2>&1
if [ -s "$WORK/appdir.txt" ] && ! grep -qi 'permission denied\|no such file' "$WORK/appdir.txt"; then
	mark_obtained "app_dir_listing"
else
	warn_unobserved "app_dir_listing" "insufficient_permission" "listing /data/user/0/$PKG failed; on a non-root device this needs a debuggable build (run-as) or root."
fi

# ==========================================================================
step "clear logcat and launch (t=0)"
adev logcat -c >/dev/null 2>&1 || required_fail "logcat -c failed; stale buffer contents would contaminate the timeline and every timing would be wrong" "lifecycle_logcat" "not_implemented"

LAUNCH_OK=false
LAUNCH_ERR=""
T0_MS=""
T0_UTC=""
UPTIME_AT_T0=""
if [ -n "$LAUNCH_COMPONENT" ]; then
	adev shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 || true
	sleep "$SETTLE_SECONDS"
	T0_MS=$(now_ms)
	T0_UTC=$(utc_now)
	UPTIME_AT_T0=$(adev shell cat /proc/uptime 2>/dev/null | tr -d '\r\n')
	LO=$(adev shell am start -W -n "$LAUNCH_COMPONENT" 2>&1)
	LR=$?
	printf '%s: launch: %s\n' "$PROG" "$(printf '%s' "$LO" | flatten)" >&2
	if [ "$LR" -eq 0 ]; then
		LAUNCH_OK=true
	else
		LAUNCH_ERR=$(printf '%s' "$LO" | flatten)
		required_fail "am start failed (rc=$LR): $LAUNCH_ERR" "lifecycle_logcat" "not_implemented"
	fi
else
	required_fail "no launch component, so nothing was launched" "lifecycle_logcat" "not_found"
fi

# ==========================================================================
step "observation window: ${DURATION}s"
THREADS=""
SNAP_REL=-1
if [ "$SNAPSHOT_AT" -gt 0 ] && [ "$LAUNCH_OK" = true ]; then
	sleep "$SNAPSHOT_AT"
	SNAP_PID=$(adev shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
	SNAP_REL=$(($(now_ms) - T0_MS))
	if [ -z "$SNAP_PID" ]; then
		soft_fail "no live process at t=+${SNAPSHOT_AT}s; fd, thread-count and maps evidence is unrecoverable for this run, because a post-mortem read of /proc is impossible."
		warn_unobserved "proc_fd" "signal_absent_in_platform_version" "no live process at the snapshot time, so /proc/<pid>/fd could not be read. Thread count and open fds are UNKNOWN, not zero."
		warn_unobserved "proc_maps" "signal_absent_in_platform_version" "no live process at the snapshot time, so /proc/<pid>/maps could not be read."
	else
		if adev shell cat "/proc/$SNAP_PID/maps" >"$WORK/maps.txt" 2>/dev/null && [ -s "$WORK/maps.txt" ]; then
			mark_obtained "proc_maps"
		else
			warn_unobserved "proc_maps" "insufficient_permission" "/proc/$SNAP_PID/maps unreadable; needs a root shell or a debuggable build."
		fi
		if adev shell ls -l "/proc/$SNAP_PID/fd" >"$WORK/fd.txt" 2>/dev/null && [ -s "$WORK/fd.txt" ]; then
			mark_obtained "proc_fd"
		else
			warn_unobserved "proc_fd" "insufficient_permission" "/proc/$SNAP_PID/fd unreadable; needs a root shell or a debuggable build."
		fi
		adev shell cat "/proc/$SNAP_PID/status" >"$WORK/status.txt" 2>/dev/null
		THREADS=$(sed -n 's/^Threads:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$WORK/status.txt" 2>/dev/null | head -n 1)
		if [ -n "$THREADS" ]; then mark_obtained "proc_tid_count"; else warn_unobserved "proc_tid_count" "insufficient_permission" "thread count unreadable."; fi
		run_probe proc.maps "$SNAP_REL" "cat /proc/$SNAP_PID/maps" proc_maps
		run_probe proc.fd "$((SNAP_REL + 1))" "ls -l /proc/$SNAP_PID/fd" proc_fd
		run_probe proc.status "$((SNAP_REL + 2))" "cat /proc/$SNAP_PID/status" proc_status
		run_probe proc.mountinfo "$((SNAP_REL + 3))" "cat /proc/$SNAP_PID/mountinfo" adb_shell
	fi
	REMAIN=$((DURATION - SNAPSHOT_AT))
	[ "$REMAIN" -gt 0 ] && sleep "$REMAIN"
else
	[ "$LAUNCH_OK" = true ] && sleep "$DURATION"
fi
info "observation window elapsed"

# ==========================================================================
step "drain logcat"
: >"$LOGCAT"
adev logcat -d -v threadtime >"$LOGCAT" 2>/dev/null
if [ ! -s "$LOGCAT" ]; then
	required_fail "logcat -d returned nothing. This recorder will not emit a recording that claims an execution it could not observe." "lifecycle_logcat" "not_implemented"
else
	mark_obtained "lifecycle_logcat"
	LOGCAT_LINES=$(wc -l <"$LOGCAT" | tr -d ' ')
	info "logcat: ${LOGCAT_LINES} lines"
fi

# t=0 anchor: the first logcat line that mentions the package, else the first
# line in the drained buffer. Both the choice and the fact that logcat has
# millisecond wall timestamps but no year and no monotonicity guarantee across
# an NTP step are recorded in clock.*, so a reader can audit the timeline.
ANCHOR_MS=$(
	LC_ALL=C awk -v pkg="$PKG" '
		function ms_of(s) { h = substr(s,1,2)+0; mi = substr(s,4,2)+0; r = substr(s,7)
		                    return ((h*60+mi)*60 + substr(r,1,2)+0) * 1000 + (substr(r,4,3)+0) }
		{ ts = $1 " " $2
		  if (ts !~ /^[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9]$/) next
		  v = ms_of(ts)
		  if (pkg != "" && index($0, pkg) > 0) { print v; exit }
		  if (anchor == 0) anchor = v }
		END { if (pkg == "" || $0 == "") print anchor }' "$LOGCAT" 2>/dev/null | head -n 1
)
[ -n "$ANCHOR_MS" ] || ANCHOR_MS=0

# ==========================================================================
step "post-run collection"
run_probe win.windows "$((DURATION + 100))" "dumpsys window windows" dumpsys_window
run_probe net.netstats "$((DURATION + 200))" "dumpsys netstats detail" dumpsys_netstats
run_probe net.connectivity "$((DURATION + 210))" "dumpsys connectivity" dumpsys_connectivity
run_probe pkg.final "$((DURATION + 220))" "dumpsys package $PKG" dumpsys_package
run_probe power "$((DURATION + 230))" "dumpsys power" dumpsys_power
run_probe battery "$((DURATION + 240))" "dumpsys battery" dumpsys_battery
[ -n "$PKG" ] && run_probe fs.app_dir "$((DURATION + 300))" "ls -lZ /data/user/0/$PKG" ls_app_dir

TX_BYTES=""
RX_BYTES=""
if [ -s "$WORK/netstats.txt" ] && [ -n "$USER_ID" ]; then
	TX_BYTES=$(sed -n "s/.*uid=$USER_ID.*txBytesRxBytes=\([0-9][0-9]*\)\/.*/\1/p" "$WORK/netstats.txt" 2>/dev/null | head -n 1)
	RX_BYTES=$(sed -n "s/.*uid=$USER_ID.*txBytesRxBytes=[0-9][0-9]*\/\([0-9][0-9]*\).*/\1/p" "$WORK/netstats.txt" 2>/dev/null | head -n 1)
fi
if [ -z "$TX_BYTES" ]; then
	warn_unobserved "netstats_per_uid" "signal_absent_in_platform_version" "no per-uid row for uid=${USER_ID:-?} in dumpsys netstats; byte totals are UNKNOWN, not zero."
fi

# ==========================================================================
step "parse lifecycle, diagnostics and exceptions"

# Lifecycle transitions. Patterns are named so that a platform version change
# shows up as an unmatched pattern rather than as a silently empty recording.
# Confidence in each literal is documented in oracle/RECORDING.md section 4.
parse_lifecycle() {
	LC_ALL=C awk -v pkg="$PKG" -v anchor="$ANCHOR_MS" '
		function ms_of(s) { h = substr(s,1,2)+0; mi = substr(s,4,2)+0; r = substr(s,7)
		                    return ((h*60+mi)*60 + substr(r,1,2)+0) * 1000 + (substr(r,4,3)+0) }
		{ ts = $1 " " $2
		  if (ts !~ /^[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9]$/) next
		  v = ms_of(ts)
		  d = v - anchor
		  if (d < -43200000) d += 86400000
		  if (d < 0) next
		  line = $0
		  sub(/^[0-9-]* [0-9:.]* +[0-9]+ +[0-9]+ +[VDIWEFA] /, "", line)
		  pid = $3
		  tag = ""; pri = ""
		  if (match($0, /[VDIWEFA] [A-Za-z0-9_.$\/-]+:/)) {
			pl = substr($0, RSTART, RLENGTH)
			pri = substr(pl, 1, 1)
			tag = substr(pl, 3, RLENGTH - 4)
		  }
		  cmp = ""
		  if (match(line, /cmp=[^ }]+/)) cmp = substr(line, RSTART + 4, RLENGTH - 4)
		  t = ""; pat = ""; tier = "T1_LOGCAT"
		  if (line ~ /Start proc [0-9]+:/) { t = "process_start"; pat = "LIFECYCLE_PAT.START_PROC" }
		  else if (line ~ /Displayed [^ ]+: \+[0-9]+ms/) { t = "first_frame_drawn"; pat = "LIFECYCLE_PAT.DISPLAYED" }
		  else if (line ~ /am_on_create_called/) { t = "activity_create"; pat = "LIFECYCLE_PAT.ON_CREATE" }
		  else if (line ~ /am_on_start_called/) { t = "activity_start"; pat = "LIFECYCLE_PAT.ON_START" }
		  else if (line ~ /am_on_resume_called/) { t = "activity_resume"; pat = "LIFECYCLE_PAT.ON_RESUME" }
		  else if (line ~ /am_on_pause_called/) { t = "activity_pause"; pat = "LIFECYCLE_PAT.ON_PAUSE" }
		  else if (line ~ /am_on_stop_called/) { t = "activity_stop"; pat = "LIFECYCLE_PAT.ON_STOP" }
		  else if (line ~ /am_on_destroy_called/) { t = "activity_destroy"; pat = "LIFECYCLE_PAT.ON_DESTROY" }
		  else if (line ~ /am_on_new_intent_called/) { t = "relaunch_requested"; pat = "LIFECYCLE_PAT.ON_NEW_INTENT" }
		  else if (line ~ /Delivering (touch|key|keycode)/) { t = "input_delivered"; pat = "LIFECYCLE_PAT.INPUT_DELIVERED" }
		  else if (line ~ /FATAL EXCEPTION: /) { t = "fatal_exception"; pat = "EXC_PAT.FATAL" }
		  else if (line ~ /Fatal signal [0-9]+|signal [0-9]+ \(SIG/) { t = "native_crash"; pat = "EXC_PAT.FATAL_SIGNAL" }
		  else if (line ~ /ANR in |ANR: Reason:/) { t = "anr"; pat = "EXC_PAT.ANR" }
		  else if (pkg != "" && line ~ /has died/ && index(line, pkg) > 0) { t = "process_died"; pat = "LIFECYCLE_PAT.PROCESS_DIED" }
		  else if (pkg != "" && line ~ /^Killing [0-9]+:/ && index(line, pkg) > 0) { t = "process_killed"; pat = "LIFECYCLE_PAT.PROCESS_KILLED" }
		  if (t != "") printf "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", d, t, tier, tag, pri, pat, substr(line,1,2000), pid, cmp
		}' "$LOGCAT"
}

# The anchor itself is a synthetic lifecycle event so that a reader can see
# where t=0 came from instead of inferring it.
: >"$WORK/events.tsv"
if [ -s "$LOGCAT" ]; then
	parse_lifecycle >"$WORK/events.parsed" 2>/dev/null || : >"$WORK/events.parsed"
	printf '0\tcapture_boundary\tT1_LOGCAT\tActivityTaskManager\t4\tLIFECYCLE_PAT.T0_ANCHOR\tt=0 anchored to the first logcat line mentioning %s\t\t\n' "$PKG" >"$WORK/events.tsv"
	cat "$WORK/events.parsed" >>"$WORK/events.tsv"
else
	printf '0\tcapture_boundary\tT4_UNOBSERVED\t\t\tLIFECYCLE_PAT.T0_ANCHOR\tlogcat was empty, so t=0 is an invented origin and every relative time is meaningless\t\t\n' >"$WORK/events.tsv"
fi

# shellcheck disable=SC2317  # called as a command
ts_of_type() { awk -F'\t' -v t="$1" '$2==t { print $1; exit }' "$WORK/events.tsv"; }
T_PROC=$(ts_of_type process_start)
T_START_EV=$(ts_of_type activity_start)
T_RESUME_EV=$(ts_of_type activity_resume)
T_FRAME_EV=$(ts_of_type first_frame_drawn)
T_INPUT_EV=$(ts_of_type input_delivered)
T_DIED=$(ts_of_type process_died)
T_FATAL=$(awk -F'\t' '$2=="fatal_exception" || $2=="native_crash" { print $1; exit }' "$WORK/events.tsv")
T_ANR=$(ts_of_type anr)

# Pattern coverage. If the launch produced a process but no DISPLAYED line,
# say so: "no match" and "not applicable" are different failures.
PAT_SEEN="$WORK/patterns.txt"
: >"$PAT_SEEN"
cut -f6 "$WORK/events.tsv" 2>/dev/null | grep -v '^$' | sort -u >"$PAT_SEEN"
if [ "$LAUNCH_OK" = true ] && [ -n "$T_PROC" ]; then
	grep -q 'LIFECYCLE_PAT.DISPLAYED' "$PAT_SEEN" || warn_unobserved "first_frame_signal" "pattern_not_matched" "the process started but no 'Displayed <activity>: +Nms' line was found. Either the app never drew, or the log pattern changed on this platform version. The recording cannot distinguish those two cases, which is exactly why this is flagged rather than scored as a failure."
	grep -q 'LIFECYCLE_PAT.ON_RESUME' "$PAT_SEEN" || warn_unobserved "lifecycle_resume_signal" "pattern_not_matched" "no am_on_resume_called line. These lifecycle trace lines exist only on some platform versions; on others the resume transition is simply INVISIBLE at T1, and the recording must not report it as a missing event."
fi

# Diagnostic signals: the detection mechanism for a large part of the
# divergence taxonomy, so they are recorded even though they are not lifecycle
# transitions and do not affect the terminal state.
LC_ALL=C awk -v anchor="$ANCHOR_MS" '
	function ms_of(s) { h = substr(s,1,2)+0; mi = substr(s,4,2)+0; r = substr(s,7)
	                    return ((h*60+mi)*60 + substr(r,1,2)+0) * 1000 + (substr(r,4,3)+0) }
	{ ts = $1 " " $2
	  if (ts !~ /^[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9]$/) next
	  d = ms_of(ts) - anchor; if (d < 0) next
	  line = $0; sub(/^[0-9-]* [0-9:.]* +[0-9]+ +[0-9]+ +[VDIWEFA] /, "", line)
	  sig = ""; cls = ""
	  if (line ~ /Slow (operation|dispatch|delivery|draw)/) { sig = "SIGNAL_PAT.SLOW_OPERATION"; cls = "SUB.TIME" }
	  else if (line ~ /Skipped [0-9]+ frames|Davey!/) { sig = "SIGNAL_PAT.JANK"; cls = "SUB.GFX" }
	  else if (line ~ /concurrent copying GC freed/) { sig = "SIGNAL_PAT.GC"; cls = "SUB.CPU" }
	  else if (line ~ /chatty: uid=/) { sig = "SIGNAL_PAT.CHATTY"; cls = "SUB.FW" }
	  else if (line ~ /UnsatisfiedLinkError|dlopen failed/) { sig = "SIGNAL_PAT.LOAD_FAIL"; cls = "SUB.NATIVE" }
	  else if (line ~ /Cleartext traffic to .* not permitted/) { sig = "SIGNAL_PAT.CLEARTEXT_BLOCKED"; cls = "SUB.NET" }
	  else if (line ~ /SSLHandshakeException|Trust anchor for certification path not found|CertificatePinning/) { sig = "SIGNAL_PAT.TLS_FAILURE"; cls = "SUB.NET" }
	  else if (line ~ /UnknownHostException|ConnectException|SocketTimeoutException|Network is unreachable/) { sig = "SIGNAL_PAT.NET_FAILURE"; cls = "SUB.NET" }
	  else if (line ~ /StrictMode/) { sig = "SIGNAL_PAT.STRICTMODE"; cls = "SUB.TIME" }
	  else if (line ~ /Google Play services|ApiException|SafetyNet/) { sig = "SIGNAL_PAT.PLAY_SERVICES"; cls = "SUB.TRUST" }
	  else if (line ~ /dex2oat|Background parallel compilation|jit thread/) { sig = "SIGNAL_PAT.JIT"; cls = "SUB.CPU" }
	  else if (line ~ /DeadObjectException|TransactionTooLargeException|ServiceManager/) { sig = "SIGNAL_PAT.BINDER"; cls = "SUB.IPC" }
	  else if (line ~ /ANR in |Input dispatching timed out/) { sig = "SIGNAL_PAT.ANR"; cls = "SUB.TIME" }
	  else if (line ~ /Low on memory|lowmemorykiller|lmkd/) { sig = "SIGNAL_PAT.LOWMEM"; cls = "SUB.MEM" }
	  if (sig != "") printf "%d\t%s\t%s\t%s\n", d, sig, cls, substr(line,1,400)
	}' "$LOGCAT" >"$WORK/diagnostics.tsv" 2>/dev/null || : >"$WORK/diagnostics.tsv"
DIAG_COUNT=$(wc -l <"$WORK/diagnostics.tsv" | tr -d ' ')
mark_obtained "diagnostic_signals"

# Exceptions: FATAL blocks with their stack frames.
LC_ALL=C awk -v anchor="$ANCHOR_MS" '
	function ms_of(s) { h = substr(s,1,2)+0; mi = substr(s,4,2)+0; r = substr(s,7)
	                    return ((h*60+mi)*60 + substr(r,1,2)+0) * 1000 + (substr(r,4,3)+0) }
	function flush() {
		if (inb) { printf "%d\t%s\t%s\t%s\t%s\t%s\n", rel, thr, cls, msg, fatal, frames; inb = 0 }
		thr = ""; cls = ""; msg = ""; fatal = "0"; frames = ""
	}
	{ ts = $1 " " $2
	  if (ts !~ /^[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9]$/) next
	  d = ms_of(ts) - anchor; if (d < 0) next
	  line = $0; sub(/^[0-9-]* [0-9:.]* +[0-9]+ +[0-9]+ +[VDIWEFA] /, "", line)
	  if (line ~ /FATAL EXCEPTION: /) {
		flush(); inb = 1; rel = d; fatal = "1"
		thr = line; sub(/^.*FATAL EXCEPTION: /, "", thr); sub(/[ \t].*$/, "", thr)
		next
	  }
	  if (!inb) next
	  if (line ~ /^\tat /) { if (length(frames) < 4000) frames = frames (frames == "" ? "" : "\n") substr(line, 4); next }
	  if (line ~ /^Caused by: /) { if (length(frames) < 4000) frames = frames (frames == "" ? "" : "\n") line; next }
	  if (line ~ /^[A-Za-z_$][A-Za-z0-9_.$]*(Exception|Error)(:|$)/) {
		cls = line; sub(/:.*$/, "", cls)
		msg = line; sub(/^[^:]*: ?/, "", msg)
		next
	  }
	  if (line ~ /^Process: /) next
	  flush()
	}
	END { flush() }' "$LOGCAT" >"$WORK/exceptions.tsv" 2>/dev/null || : >"$WORK/exceptions.tsv"
EXC_COUNT=$(wc -l <"$WORK/exceptions.tsv" | tr -d ' ')   # logged, and cross-checked against the emitted array length
FATAL_COUNT=0
[ -s "$WORK/exceptions.tsv" ] && FATAL_COUNT=$(cut -f5 "$WORK/exceptions.tsv" | grep -c '^1$')
[ "$FATAL_COUNT" -gt 0 ] && mark_obtained "fatal_exceptions"

# Native libraries from /proc maps when we have them.
: >"$WORK/libs.txt"
MAPPING_OBTAINED=false
if [ -s "$WORK/maps.txt" ]; then
	sed 's|.* /|/|' "$WORK/maps.txt" 2>/dev/null | grep '\.so$' | sort -u >"$WORK/libs.txt" || : >"$WORK/libs.txt"
	[ -s "$WORK/libs.txt" ] && MAPPING_OBTAINED=true
fi
[ "$MAPPING_OBTAINED" = true ] || warn_unobserved "native_library_set" "insufficient_permission" "the set of native libraries mapped into the process is UNKNOWN, not empty. An APK that ships .so files has almost certainly loaded some; recording an empty list here would be a substantive falsehood."
NATIVE_COUNT=$(wc -l <"$WORK/libs.txt" | tr -d ' ')

# Declared native libs, read from the APK we were handed, independent of the
# device. This is the one native-code signal available with no privileges.
: >"$WORK/declared_libs.txt"
if have unzip; then
	unzip -Z1 "$APK" 2>/dev/null | grep '^lib/.*\.so$' | sed 's|.*/||' | sort -u >"$WORK/declared_libs.txt" || : >"$WORK/declared_libs.txt"
elif have jar; then
	jar tf "$APK" 2>/dev/null | grep '^lib/.*\.so$' | sed 's|.*/||' | sort -u >"$WORK/declared_libs.txt" || : >"$WORK/declared_libs.txt"
else
	warn_unobserved "declared_native_libs" "tool_missing" "neither unzip nor jar is available, so the APK's declared native libraries could not be listed."
fi
DECL_COUNT=$(wc -l <"$WORK/declared_libs.txt" | tr -d ' ')
if [ "$DECL_COUNT" -gt 0 ] && [ "$MAPPING_OBTAINED" != true ]; then
	soft_fail "the APK declares $DECL_COUNT native libraries but the loaded set is unknown; this app cannot run on a substrate with no ELF loading, and this capture cannot say how it fails."
fi

# ==========================================================================
step "assemble recording -> $OUT"
# shellcheck disable=SC2034  # read immediately below to form TOTAL_MS
T_END_MS=$(now_ms)
TOTAL_MS=$(($(T_END_MS - T_START_MS)))
END_UTC=$(utc_now)
[ -n "$T0_UTC" ] || T0_UTC="$T_START_UTC"
[ -n "$T0_MS" ] || T0_MS="$T_START_MS"

COMPLETENESS=complete
if [ "$EMPTY_FAILURE" = true ]; then
	COMPLETENESS=degraded
elif [ "$FAILED_STEPS" -gt 0 ]; then
	COMPLETENESS=partial
fi
[ -z "$SELF_SHA" ] && COMPLETENESS=partial

# ---- derived terminal state (must mirror validate.mjs deriveTerminal) ----
ge() { if [ -z "$2" ]; then return 1; fi; [ "$1" -ge "$2" ]; }
if [ -z "$T_PROC" ]; then
	if [ "$INSTALL_OK" != true ] || [ "$LAUNCH_OK" != true ] || [ -n "$T_FATAL" ] || [ -n "$T_ANR" ]; then
		TERMINAL="LF_FAILED_BEFORE_L0"
	else
		TERMINAL="LF_UNRESOLVED"
	fi
elif [ -z "$T_RESUME_EV" ] && { [ -n "$T_DIED" ] || [ -n "$T_FATAL" ] || [ -n "$T_ANR" ]; }; then
	TERMINAL="LF_NEVER_RESUMED"
elif [ -z "$T_RESUME_EV" ]; then
	TERMINAL="L0_PROCESS_STARTED"
elif [ -n "$T_FATAL" ] && ge "$T_FATAL" "$T_RESUME_EV"; then
	TERMINAL="LF_CRASHED"
elif [ -n "$T_ANR" ] && ge "$T_ANR" "$T_RESUME_EV"; then
	TERMINAL="LF_ANR"
elif [ -z "$T_FRAME_EV" ]; then
	TERMINAL="L1_ACTIVITY_RESUMED"
elif [ -n "$T_FATAL" ] && ge "$T_FATAL" "$T_FRAME_EV"; then
	TERMINAL="LF_CRASHED"
elif [ -n "$T_ANR" ] && ge "$T_ANR" "$T_FRAME_EV"; then
	TERMINAL="LF_ANR"
else
	TERMINAL="L2_FIRST_FRAME_DRAWN"
fi
# LF_UNRESOLVED must be earned, not defaulted into: a run that resolved to
# nothing at all is a failure of the harness, and says so.
if [ "$TERMINAL" = LF_UNRESOLVED ] && [ "$COMPLETENESS" = complete ]; then
	COMPLETENESS=partial
	warn "the run produced neither a process start nor a failure signal. Recording LF_UNRESOLVED; this is a harness failure, not a measurement of the app."
fi

REACHED_STEADY=false
if [ -n "$T_FRAME_EV" ] && [ -z "$T_FATAL" ] && [ -z "$T_DIED" ] && [ -z "$T_ANR" ]; then
	REACHED_STEADY=true
fi
QUIET_MS=0
if [ "$REACHED_STEADY" = true ] && [ "$DIAG_COUNT" -eq 0 ]; then
	QUIET_MS=$DURATION
fi
SPAM=false
CHATTY=$(awk -F'\t' '$2=="SIGNAL_PAT.CHATTY"' "$WORK/diagnostics.tsv" 2>/dev/null | wc -l | tr -d ' ')
[ "${CHATTY:-0}" -gt 3 ] && SPAM=true
JANK=$(awk -F'\t' '$2=="SIGNAL_PAT.JANK"' "$WORK/diagnostics.tsv" 2>/dev/null | wc -l | tr -d ' ')
[ -n "$JANK" ] || JANK=0

MAX_TIER=T1_LOGCAT
[ "$MAPPING_OBTAINED" = true ] && MAX_TIER=T0_DIRECT

# ---- fragments ----------------------------------------------------------
# clock
cat >"$WORK/clock.json" <<CLOCKJSON
{
    "monotonic_source": "logcat_wall",
    "monotonic_resolution_ms": $CLOCK_RES_MS,
    "wall_clock_source": "host_date",
    "monotonic_epoch_ref": $(jstr_or_null "$UPTIME_AT_T0"),
    "t_zero_definition": "t=0 is the first logcat line mentioning $PKG in the drained buffer, not the instant am start returned. The offset between those two instants is unobserved, so absolute latencies carry that error; RELATIVE intervals between events do not, because they share a clock.",
    "notes": "logcat threadtime gives 1 ms wall timestamps with no year and no monotonicity guarantee across an NTP step. Device /proc/uptime is recorded as a cross-check. Durations quoted from this recording are accurate to about the host clock resolution, and any analysis claiming millisecond-exact frame timings is over-reading. Patterns that did not match are listed in capture_quality.unobserved rather than silently treated as absent behaviour."
}
CLOCKJSON

# lifecycle events. Built with the shell escaper rather than awk string
# concatenation, because log detail text can contain quotes and backslashes and
# an unescaped quote here would silently produce a corrupt recording.
: >"$WORK/lifecycle.json"
_n=0
while IFS="$TAB" read -r _t _ty _tier _tag _pri _pat _det _pid _cmp; do
	[ -z "$_t" ] && continue
	if [ "$_n" -gt 0 ]; then printf ',\n' >>"$WORK/lifecycle.json"; fi
	printf '    { "type": %s, "t_mono_ms": %s, "t_wall_utc": null, "component": %s, "pid": %s, "source": "logcat", "tier": %s, "log_tag": %s, "log_priority": %s, "matched_pattern": %s, "detail": %s }' \
		"$(jstr "$_ty")" "$_t" "$(jstr_or_null "$_cmp")" "$(jnum "$_pid")" \
		"$(jstr "$_tier")" "$(jstr_or_null "$_tag")" "$(jnum "$_pri")" \
		"$(jstr_or_null "$_pat")" "$(printf '%s' "$_det" | cut -c1-2000 | json_str)" \
		>>"$WORK/lifecycle.json"
	_n=$((_n + 1))
done <"$WORK/events.tsv"
printf '\n  ]' >>"$WORK/lifecycle.json"
EVENT_COUNT=$_n

# diagnostics
: >"$WORK/diagnostics.json"
_n=0
while IFS="$TAB" read -r _t _sig _cls _det; do
	[ -z "$_t" ] && continue
	if [ "$_n" -gt 0 ]; then printf ',\n' >>"$WORK/diagnostics.json"; fi
	printf '    { "pattern": %s, "family": %s, "t_mono_ms": %s, "detail": %s, "source": "logcat", "tier": "T1_LOGCAT" }' \
		"$(jstr "$_sig")" "$(jstr_or_null "$_cls")" "$_t" \
		"$(printf '%s' "$_det" | cut -c1-400 | json_str)" >>"$WORK/diagnostics.json"
	_n=$((_n + 1))
done <"$WORK/diagnostics.tsv"
printf '\n  ]' >>"$WORK/diagnostics.json"
DIAG_EMITTED=$_n

# exceptions
: >"$WORK/exceptions.json"
_n=0
while IFS="$TAB" read -r _t _thr _cls _msg _fatal _frames; do
	[ -z "$_t" ] && continue
	if [ "$_n" -gt 0 ]; then printf ',\n' >>"$WORK/exceptions.json"; fi
	_f=false
	[ "$_fatal" = "1" ] && _f=true
	printf '    { "t_mono_ms": %s, "t_wall_utc": null, "fatal": %s, "kind": "java_exception", "thread": %s, "pid": null, "class": %s, "message": %s, "stack_frames": %s, "crash_log_ref": null, "source": "logcat_buffer_crash", "tier": "T1_LOGCAT" }' \
		"$_t" "$_f" "$(jstr_or_null "$_thr")" "$(jstr_or_null "$_cls")" \
		"$(printf '%s' "$_msg" | cut -c1-2000 | json_str)" \
		"$(printf '%s' "$_frames" | awk 'NF{print}' | json_str_array)" \
		>>"$WORK/exceptions.json"
	_n=$((_n + 1))
done <"$WORK/exceptions.tsv"
printf '\n  ]' >>"$WORK/exceptions.json"
EXC_EMITTED=$_n
# Self-consistency: the parsed count and the emitted count must agree, or the
# emission loop dropped or duplicated a record. Caught here rather than by the
# validator, because a mismatch means the recorder is buggy, not the app.
if [ "$EXC_COUNT" -ne "$EXC_EMITTED" ]; then
	soft_fail "exception count mismatch: parsed ${EXC_COUNT}, emitted ${EXC_EMITTED}. The recording's exception list is not trustworthy."
fi

# app dir listing
: >"$WORK/appdir.json"
_n=0
if [ -s "$WORK/appdir.txt" ] && ! grep -qi 'permission denied\|no such file' "$WORK/appdir.txt"; then
	while IFS= read -r _l; do
		[ -z "$_l" ] && continue
		_p=$(printf '%s' "$_l" | cut -c1-10)
		_path=$(printf '%s' "$_l" | tr -s ' ' | cut -d' ' -f9-)
		case "$_path" in /*) ;; *) continue ;; esac
		_case=unknown
		case "$_p" in
		d*) _case='dir' ;;
		-*) _case='file' ;;
		l*) _case='symlink' ;;
		s*) _case='socket' ;;
		esac
		_size=$(printf '%s' "$_l" | tr -s ' ' | cut -d' ' -f5)
		case "$_size" in
		'' | *[!0-9]*) _size=0 ;;
		esac
		_ctx=$(printf '%s' "$_l" | sed -n 's/.*\(u:o:r:[a-z_]*:s[0-9]*\(:c[0-9,]*\)\?\).*/\1/p')
		if [ "$_n" -gt 0 ]; then printf ',\n' >>"$WORK/appdir.json"; fi
		printf '    { "path": %s, "entry_type": "%s", "size_bytes": %s, "mode": %s, "owner_uid": %s, "selinux_context": %s }' \
			"$(jstr "$_path")" "$_case" "$_size" "$(jstr_or_null "$_p")" "$(jnum "$USER_ID")" "$(jstr_or_null "$_ctx")" \
			>>"$WORK/appdir.json"
		_n=$((_n + 1))
	done <"$WORK/appdir.txt"
fi
printf '\n  ]' >>"$WORK/appdir.json"
APPDIR_COUNT=$_n

# unobserved / warnings / expected / obtained
: >"$WORK/unobserved.json"
_n=0
while IFS="$TAB" read -r _sig _code _txt; do
	[ -z "$_sig" ] && continue
	if [ "$_n" -gt 0 ]; then printf ',\n' >>"$WORK/unobserved.json"; fi
	printf '    { "signal": %s, "reason_code": "%s", "reason": %s }' \
		"$(jstr "$_sig")" "$_code" "$(jstr "$_txt")" >>"$WORK/unobserved.json"
	_n=$((_n + 1))
done <"$UNOBSERVED_FILE"
printf '\n  ]' >>"$WORK/unobserved.json"
UNOBS_COUNT=$_n

: >"$WORK/warnings.json"
_n=0
while IFS= read -r _w; do
	[ -z "$_w" ] && continue
	if [ "$_n" -gt 0 ]; then printf ',\n' >>"$WORK/warnings.json"; fi
	printf '    %s' "$(jstr "$_w")" >>"$WORK/warnings.json"
	_n=$((_n + 1))
done <"$WARNINGS_FILE"
printf '\n  ]' >>"$WORK/warnings.json"
WARN_COUNT=$_n

# shellcheck disable=SC2086  # EXPECTED is a word list, split deliberately below
EXPECTED="install_state pm_path dumpsys_package dumpsys_window dumpsys_netstats dumpsys_connectivity play_services_presence boot_completed lifecycle_logcat diagnostic_signals app_dir_listing network_exchange class_load_census jni_calls fs_access_trace native_library_set"
# shellcheck disable=SC2086  # EXPECTED is a word list; the split is the point
EXP_ARR=$(printf '%s\n' $EXPECTED | json_str_array)
OBT_ARR=$(cat "$OBTAINED_FILE" | sort -u | json_str_array)

# Integrity expectation is derived from the environment class, never observed.
# A verdict is computed server-side by Google Play from hardware-backed signals
# and is not locally readable, so a container or emulator can only ever be NONE.
MAX_VERDICT=NONE
PI_SUPPORTED=false
case "$ENV_KIND" in
physical_device | cloud_device_farm)
	PI_SUPPORTED=true
	MAX_VERDICT=UNKNOWN
	warn "environment is a real device. A hardware-backed integrity verdict is POSSIBLE here, but this recorder CANNOT read it: verdicts are evaluated server-side by Google Play and returned to the app's backend. observed_verdict stays UNKNOWN unless an operator fills it in by hand from the Play Store UI."
	;;
esac

CAPTURE_ID=$(printf '%s__%s__%s' "$PKG" "$(printf '%s' "$APK_SHA" | cut -c1-16)" "$ENV_KIND" | tr -c 'A-Za-z0-9._-' '_')
# shellcheck disable=SC2086  # $ABILIST is a space-separated ro.product.cpu.abilist and MUST be split
ABIS_JSON=$(printf '%s\n' $ABILIST | awk 'NF{gsub(/^"/,"");gsub(/"$/,"");print}' | json_str_array)
[ -n "$ABILIST" ] || ABIS_JSON="[]"

OUTDIR=$(dirname "$OUT")
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR" || die "cannot create output directory $OUTDIR"

cat >"$OUT" <<JSON
{
  "record_format": "$FORMAT",
  "synthetic": false,
  "capture_id": "$CAPTURE_ID",
  "provenance": {
    "execution_performed": $(jbool "$INSTALL_OK"),
    "synthetic_reason": null,
    "toolchain_revision": "uncommitted working tree (agent 3, research design)",
    "capture_script_sha256": $(jstr_or_null "$SELF_SHA"),
    "authored_by": "oracle/recorder/adb-recorder.sh $VER",
    "host_os": "$(uname -sr 2>/dev/null | tr -c 'A-Za-z0-9 ._-' ' ')",
    "notes": "Produced by driving adb against a ${ENV_KIND} reference environment. Every observation array that is empty is paired with an entry in capture_quality.unobserved explaining why, so that emptiness is never mistaken for absence of behaviour."
  },
  "recorder": {
    "name": "adb-recorder.sh",
    "version": "$VER",
    "implementation": "adb-recorder",
    "options": {
      "DURATION": "$DURATION",
      "SNAPSHOT_AT": "$SNAPSHOT_AT",
      "BOOT_TIMEOUT": "$BOOT_TIMEOUT",
      "SNAPSHOT_TIMEOUT": "$SNAPSHOT_TIMEOUT",
      "HOSTNAMES": "$HOSTNAMES",
      "MITM": "$MITM"
    },
    "adb_version": "$(adev version 2>/dev/null | head -n 1 | tr -c 'A-Za-z0-9 ._-' ' ')"
  },
  "capture": {
    "started_utc": "$T_START_UTC",
    "ended_utc": "$END_UTC",
    "duration_ms": $TOTAL_MS,
    "observation_window_ms": $DURATION,
    "boot_wait_ms": $BOOT_WAIT_MS,
    "install": {
      "method": "adb_install",
      "succeeded": $(jbool "$INSTALL_OK"),
      "flags": [],
      "apks_replaced_existing": null,
      "install_source": "adb",
      "error": $(if [ "$INSTALL_OK" = true ]; then printf 'null'; else printf '%s' "$INSTALL_OUT" | flatten | json_str; fi)
    },
    "launch": {
      "method": "am_start",
      "component": $(jstr_or_null "$LAUNCH_COMPONENT"),
      "requested_activity_resolved_by": "$RESOLVED_BY",
      "succeeded": $(jbool "$LAUNCH_OK"),
      "error": $(jstr_or_null "$LAUNCH_ERR")
    },
    "device_serial": $(jstr_or_null "$SERIAL"),
    "shell_uid": $(jnum "$SHELL_UID"),
    "root_shell": $(jbool "$ROOT_SHELL"),
    "snapshot_at_ms": $(jnum "$SNAP_REL"),
    "clock": $(cat "$WORK/clock.json"),
    "observer_effects": [
      { "kind": "root_shell_used", "applied": $(jbool "$ROOT_SHELL"), "detail": "adb root; used for /proc inspection only", "expected_to_change_behaviour": false },
      { "kind": "mitm_proxy_installed", "applied": $(jbool "$MITM"), "detail": $(if [ "$MITM" = true ]; then printf 'proxy installed and user CA trusted'; else printf 'no proxy: the default protocol declines this observer effect because it changes the behaviour of exactly the cert-pinning apps we need to observe'; fi | json_str), "expected_to_change_behaviour": $(jbool "$MITM") },
      { "kind": "log_level_raised", "applied": false, "detail": null, "expected_to_change_behaviour": false }
    ],
    "interventions_during_run": []
  },
  "app": {
    "package": $(jstr "$PKG"),
    "apk_sha256": "$(printf '%s' "$APK_SHA")",
    "apk_size_bytes": $APK_SIZE,
    "apk_paths": $(cat "$PM_PATHS" | json_str_array),
    "apk_digest_on_device": null,
    "version_code": $(jnum "$VERSION_CODE"),
    "version_name": $(jstr_or_null "$VERSION_NAME"),
    "min_sdk": $(jnum "$MIN_SDK"),
    "target_sdk": $(jnum "$TARGET_SDK"),
    "user_id": $(jnum "$USER_ID"),
    "install_flags": [],
    "debuggable": $(jbool "$DEBUGGABLE"),
    "declared_permissions": $(cat "$WORK/reqperms.txt" | json_str_array),
    "granted_permissions": $(cat "$WORK/perms.txt" | json_str_array),
    "split_apks": [],
    "main_activity": $(jstr_or_null "$LAUNCH_COMPONENT"),
    "native_libs_declared": $(cat "$WORK/declared_libs.txt" | json_str_array),
    "signature_sha256": [],
    "data_dir": $(jstr_or_null "$DATA_DIR"),
    "code_path": $(jstr_or_null "$CODE_PATH"),
    "device_protected_data_dir": $(jstr_or_null "$DEVPROT"),
    "is_synthetic": false
  },
  "environment": {
    "kind": "$ENV_KIND",
    "android_release": $(jstr_or_null "$REL"),
    "sdk_int": $(jnum "$SDK_INT"),
    "build_fingerprint": $(jstr_or_null "$FINGERPRINT"),
    "build_id": $(jstr_or_null "$BUILD_ID"),
    "build_type": $(jstr_or_null "$BUILD_TYPE"),
    "serial": $(jstr_or_null "$SERIAL_PROP"),
    "abis": $ABIS_JSON,
    "is_emulator": $(jbool "$IS_EMULATOR"),
    "is_physical_device": $(jbool "$IS_PHYSICAL"),
    "ro_secure": $(if [ -n "$RO_SECURE" ]; then [ "$RO_SECURE" = "1" ] && printf true || printf false; else printf null; fi),
    "verified_boot_state": $(jstr_or_null "$BOOT_STATE"),
    "selinux": $(jstr_or_null "$SELINUX"),
    "selinux_enforcing": $(if [ "$SELINUX" = "Enforcing" ]; then printf true; elif [ "$SELINUX" = "Permissive" ]; then printf false; else printf null; fi),
    "image_digest": null,
    "google_play_services": {
      "present": $(jbool "$GMS_PRESENT"),
      "version_name": null,
      "version_code": null,
      "enabled": null,
      "detected_by": "pm_list_packages"
    },
    "play_store_present": $(jbool "$PLAY_STORE_PRESENT"),
    "attestation": {
      "play_integrity_supported": $(jbool "$PI_SUPPORTED"),
      "safetynet_available": false,
      "max_expected_verdict": "$MAX_VERDICT",
      "observed_verdict": null,
      "basis": "documented_requirement",
      "notes": "Play Integrity verdicts are computed server-side by Google Play from hardware-backed signals and are not locally observable, so this recorder never fills observed_verdict from a wire observation. SafetyNet Attestation stopped working for every app on 2025-01-31 and now always fails with ApiException NETWORK_ERROR, which means any app still calling it fails IDENTICALLY on a real phone and on any substrate: SafetyNet cannot discriminate between them."
    },
    "network": {
      "egress_available": true,
      "default_network_type": null,
      "validated": null,
      "metered": null,
      "captive_portal": null,
      "dns_servers": [],
      "system_proxy": null
    }
  },
  "clock": $(cat "$WORK/clock.json"),
  "privacy": {
    "policy": "andro-substrate/oracle-privacy/1",
    "bodies_captured": false,
    "hostnames": "$HOSTNAMES",
    "secrets_redacted": true,
    "user_ca_trusted": $(jbool "$MITM"),
    "notes": "Applied unconditionally. No request or response body is recorded at any tier, only byte counts and SHA-256 digests. No Authorization, Cookie or API-key VALUE is recorded; only header NAMES. Query strings are dropped, keeping parameter names only. With --hostnames hmac, hostnames become HMAC tokens under a key held out of band, so hosts can be correlated across a corpus without being disclosed."
  },
  "lifecycle": {
    "events": $(cat "$WORK/lifecycle.json"),
    "activity_started": $(jnum "$T_START_EV"),
    "activity_resumed": $(jnum "$T_RESUME_EV"),
    "first_frame_drawn": $(jnum "$T_FRAME_EV"),
    "window_focused": null,
    "first_input_delivered": $(jnum "$T_INPUT_EV"),
    "terminal": "$TERMINAL",
    "reached_steady_state": $(jbool "$REACHED_STEADY"),
    "quiet_window_ms": $(jnum "$QUIET_MS"),
    "sustained_log_spam": $(jbool "$SPAM"),
    "jank_events": $JANK
  },
  "network": {
    "capture_method": $(if [ "$MITM" = true ]; then printf 'mitm_proxy'; else printf 'logcat_only'; fi),
    "hostname_resolution": $(case "$HOSTNAMES" in plain) printf plain ;; none) printf none ;; *) printf unavailable ;; esac),
    "proxy": { "installed": $(jbool "$MITM"), "user_ca_trusted": $(jbool "$MITM") },
    "attempts": [],
    "byte_totals_observed": {
      "source": "netstats_counters",
      "tx_bytes": $(jnum "$TX_BYTES"),
      "rx_bytes": $(jnum "$RX_BYTES"),
      "connection_count": null,
      "destination_resolvable": false,
      "uid": $(jnum "$USER_ID"),
      "note": "Per-UID counters only: authoritative for volume, useless for attribution. No hostname and no destination address exists at this source."
    },
    "limits": [
      "Without --mitm no request or response headers, bodies, timings or TLS transcript are observable, so network.attempts is empty and that emptiness means UNKNOWN, not 'the app made no requests'.",
      "dumpsys netstats gives per-UID byte counts with no destination, so it cannot support any per-host claim.",
      "A request the app did not itself log is invisible at this tier, and many apps log nothing about their network use."
    ]
  },
  "filesystem": {
    "accesses": [],
    "access_trace_obtained": false,
    "app_dir_listing": $(cat "$WORK/appdir.json"),
    "open_fds_at_snapshot": [],
    "limits": [
      "access_trace_obtained is false: per-operation file access needs in-process instrumentation or strace. The empty accesses array means UNKNOWN, not 'no file access occurred'.",
      "app_dir_listing records paths, sizes, modes, owners and SELinux labels only. File CONTENT is never recorded."
    ]
  },
  "classes": {
    "loaded": [],
    "loaded_obtained": false,
    "total_loaded_count": null,
    "dex_files": [],
    "limits": [
      "loaded_obtained is false: a class-load census needs in-process instrumentation or a debuggable build. The empty loaded array means UNKNOWN, not 'the app loaded no classes'."
    ]
  },
  "native": {
    "libraries_loaded": $(cat "$WORK/libs.txt" | json_str_array),
    "obtained": $MAPPING_OBTAINED,
    "mapping_obtained": $MAPPING_OBTAINED,
    "exec_segments_observed": false,
    "dlopen_failures": [],
    "system_libraries_mapped": [],
    "jit_or_aot_activity_observed": false,
    "thread_count_at_snapshot": $(jnum "$THREADS"),
    "limits": [
      "If mapping_obtained is false then libraries_loaded is empty and that means UNOBSERVED, not 'the app loaded no native code'. An APK that ships .so files has almost certainly loaded some, and native_libs_declared is the only privilege-free evidence either way.",
      "Maps are read at one instant: a library mapped and unmapped inside the window is missed, and an executable segment is not evidence that any instruction from it ran."
    ]
  },
  "jni": {
    "calls": [],
    "obtained": false,
    "limits": [
      "obtained is false: Java/native transitions are not observable from outside the process without instrumentation. The empty calls array means UNKNOWN, not 'the app made no JNI calls'."
    ]
  },
  "exceptions": $(cat "$WORK/exceptions.json"),
  "diagnostics": $(cat "$WORK/diagnostics.json"),
  "probes": [
$(sed 's/,$//' "$WORK/probes.json" | sed 's/[[:space:]]*$//')
  ],
  "substrate_probe_hits": [],
  "capture_quality": {
    "completeness": "$COMPLETENESS",
    "max_tier_reached": "$MAX_TIER",
    "signals_expected": $EXP_ARR,
    "signals_obtained": $OBT_ARR,
    "unobserved": $(cat "$WORK/unobserved.json"),
    "warnings": $(cat "$WORK/warnings.json"),
    "empty_failure": $(jbool "$EMPTY_FAILURE"),
    "exit_code": 0
  },
  "summary": {
    "lifecycle_terminal": "$TERMINAL",
    "time_to_first_frame_ms": $(jnum "$T_FRAME_EV"),
    "event_count": $EVENT_COUNT,
    "network_attempt_count": 0,
    "network_destinations": 0,
    "exception_count": $EXC_EMITTED,
    "fatal_count": $FATAL_COUNT,
    "class_count": 0,
    "native_library_count": $NATIVE_COUNT,
    "distinct_families_touched": 0,
    "families_touched": []
  },
  "notes": "Reference environment: ${ENV_KIND}. READ capture_quality.unobserved BEFORE drawing any conclusion from an absent signal. At T1/T2 this recorder cannot see per-operation file access, class loading, JNI calls or network exchanges, and the corresponding empty arrays mean UNOBSERVED. Observed but not scored: ${DIAG_COUNT} diagnostic signal(s), ${APPDIR_COUNT} app-directory entries, ${DECL_COUNT} declared native libraries, thread count ${THREADS:-unknown}."
}
JSON

# ------------------------------------------------------------ self-check
info "wrote $OUT"
info "events=$EVENT_COUNT terminal=$TERMINAL diagnostics=$DIAG_EMITTED exceptions=$EXC_EMITTED native_libs=$NATIVE_COUNT"
info "quality: completeness=$COMPLETENESS max_tier=$MAX_TIER warnings=$WARN_COUNT unobserved=$UNOBS_COUNT empty_failure=$EMPTY_FAILURE"

SELF_VALID=unknown
VALIDATOR="$(cd "$(dirname "$0")" && pwd)/validate.mjs"
if [ -f "$VALIDATOR" ] && have node; then
	if node "$VALIDATOR" "$OUT" >"$WORK/validate.txt" 2>&1; then
		SELF_VALID=true
		info "self-validation: OK"
	else
		SELF_VALID=false
		cat "$WORK/validate.txt" >&2
		info "self-validation: FAILED (recording kept at $OUT for inspection)"
	fi
else
	warn "validate.mjs or node unavailable; the recording was not self-validated. Run: node oracle/recorder/validate.mjs $OUT"
fi

if [ "$UNINSTALL_AFTER" = true ] && [ "$INSTALL_OK" = true ]; then
	adev uninstall "$PKG" >/dev/null 2>&1 || warn "uninstall of $PKG failed"
fi

if [ "$EMPTY_FAILURE" = true ] && [ "$ALLOW_INCOMPLETE" != true ]; then
	info "A REQUIRED step produced nothing. The failure is recorded in the document rather than hidden, but the run counts as failed."
	exit 3
fi
[ "$SELF_VALID" = false ] && [ "$ALLOW_INCOMPLETE" != true ] && exit 4
exit 0
