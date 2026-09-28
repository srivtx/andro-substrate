#!/usr/bin/env bash
#
# capture.sh — reproducible ART method traces from a real app on a real device.
#
#   trace/capture.sh --apk <apk> --package <pkg> [options]
#
# # What this decides
#
# One trace file, captured the same way every time, with a written-down record
# of *how* it was captured. Everything downstream in `trace/` is a function of
# the capture record next to the trace, so a number can always be traced back to
# the command that produced it.
#
# # Capture modes
#
# `--activity-clear-task` forces the activity to be re-created, and while doing
# so it also tears the *previous* activity down. Both halves land inside the
# profiling window, so the count includes teardown methods the app would never
# call on a first launch. That is the `recreate` mode, kept because it is the
# method the earlier numbers were taken with, and quantified against the others.
#
#   recreate   profile start -> `am start --activity-clear-task`
#              CREATION + TEARDOWN. The original method. Confounded.
#   create     profile start -> `am start`
#              CREATION only. The activity is finished with BACK *before*
#              profiling starts, so there is nothing left to tear down.
#   teardown   profile start -> BACK
#              TEARDOWN only, no creation.
#   idle       profile start -> `am start` (no re-creation)
#              NOISE FLOOR. The app is already resumed, so this is what an
#              otherwise-idle profiling window looks like.
#   startprof  `am start --start-profiler <file> --streaming`
#              FROM PROCESS START, no teardown, no clear-task. Writes the
#              *continuous* layout. This is the only mode that observes a cold
#              first launch. Requires `--streaming`: without it ART buffers the
#              trace and flushes it on a clean process exit, which an Android
#              app never performs, so the file stays 0 bytes forever.
#
# # Why 0 bytes is a mode, not a run
#
# A failed capture leaves a 0-byte file, and a 0-byte file parsed naively reads
# as "this app called no framework methods". Every run is therefore classified
# and recorded before it is allowed to be counted: `ok`, `failed-zero-bytes`,
# or `failed-unrecognised`. `measure.mjs` refuses to average a failure in.
#
# # Idempotency
#
# Run slots are named deterministically (`<pkg>.<mode>.run<K>.trace`), so a
# second invocation overwrites the same files rather than accumulating. The APK
# is hashed before install and the hash is recorded in every capture record and
# in `runs/apks.sha256`, so a later report cannot be attributed to a different
# APK than the one that was measured. No APK is ever copied into the repo.
#
# # Usage
#
#   trace/capture.sh --apk A.apk --package p --runs 3
#   trace/capture.sh --apk A.apk --package p --runs 3 --mode create
#   trace/capture.sh --apk A.apk --package p --runs 3 --sampling 100
#   trace/capture.sh --list-devices
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="$HERE/runs"
APK=""
PACKAGE=""
RUNS=1
MODE=recreate
SAMPLING=""
SERIAL=""
SETTLE=3
WINDOW=5
REUSE=0

die() { printf 'capture.sh: %s\n' "$*" >&2; exit 2; }
say() { printf '%s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --apk)       APK="$2"; shift 2 ;;
    --package)   PACKAGE="$2"; shift 2 ;;
    --runs)      RUNS="$2"; shift 2 ;;
    --mode)      MODE="$2"; shift 2 ;;
    --sampling)  SAMPLING="$2"; shift 2 ;;
    --outdir)    OUTDIR="$2"; shift 2 ;;
    --serial)    SERIAL="$2"; shift 2 ;;
    --settle)    SETTLE="$2"; shift 2 ;;
    --window)    WINDOW="$2"; shift 2 ;;
    --reuse)     REUSE=1; shift ;;
    --list-devices) exec adb devices ;;
    -h|--help)   sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$APK" ]     || die "--apk is required"
[ -n "$PACKAGE" ] || die "--package is required"
[ -f "$APK" ]     || die "no such APK: $APK"
case "$MODE" in recreate|create|teardown|idle|startprof) ;; *) die "--mode must be one of recreate create teardown idle startprof" ;; esac
case "$RUNS" in ''|*[!0-9]*) die "--runs must be a positive integer" ;; esac
[ "$RUNS" -gt 0 ] || die "--runs must be >= 1"

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

# ---------------------------------------------------------------- device ----

wait_boot() {
  local deadline=$(( $(date +%s) + 180 )) done_
  while [ "$(date +%s)" -lt "$deadline" ]; do
    done_=$("${ADB[@]}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r\n')
    [ "$done_" = "1" ] && return 0
    sleep 2
  done
  die "device did not reach sys.boot_completed=1 within 180s"
}

adb_sh() { "${ADB[@]}" shell "$@" 2>/dev/null | tr -d '\r'; }

# Resolve the launcher activity the same way the platform would. `--brief`
# prints `package/.Class`; an app with no launcher activity prints nothing,
# which is a legitimate "this app cannot be measured" and not an error to
# paper over.
resolve_component() {
  local out
  out="$(adb_sh cmd package resolve-activity --brief "$1" | tail -1)"
  case "$out" in
    */*.*) printf '%s' "$out" ;;
    *)     return 1 ;;
  esac
}

# Is the app's activity still the resumed one?
#
# The `create` and `teardown` modes need the activity to be *gone* before or
# during the profiling window. BACK is the cheapest way to finish an activity,
# but delivery is racy in an emulator and an app is free to consume the key: a
# game with a "press BACK to pause" handler leaves its activity resumed, and the
# window then contains no creation at all — the run looks perfectly valid and is
# silently an idle trace. So BACK is retried, and the precondition is *checked*
# rather than assumed; a run that cannot establish it is recorded as a failure
# instead of as data.
activity_is_resumed() {
  adb_sh dumpsys activity activities | grep 'topResumedActivity' | grep -q -- "$PACKAGE"
}

BACK_ATTEMPTS=4
finish_activity() {
  local i
  for i in $(seq 1 "$BACK_ATTEMPTS"); do
    activity_is_resumed || return 0
    adb_sh input keyevent 4
    sleep 2
  done
  activity_is_resumed && return 1
  return 0
}

# ---------------------------------------------------------------- install ---

mkdir -p "$OUTDIR"

APK_SHA="$(shasum -a 256 "$APK" | cut -d' ' -f1)"
APK_BASE="$(basename "$APK")"
printf '%s  %s\n' "$APK_SHA" "$APK_BASE" >> "$OUTDIR/apks.sha256"
sort -u -o "$OUTDIR/apks.sha256" "$OUTDIR/apks.sha256"
say "apk  $APK_BASE  sha256=$APK_SHA"

wait_boot
say "device booted"

install_apk() {
  local out
  out="$("${ADB[@]}" install -r -g "$APK" 2>&1 | tr -d '\r' || true)"
  case "$out" in
    *Success*) return 0 ;;
    *) say "install failed: $out"; return 1 ;;
  esac
}

if ! "${ADB[@]}" shell pm path "$PACKAGE" >/dev/null 2>&1; then
  install_apk || die "could not install $APK"
fi

COMPONENT="$(resolve_component "$PACKAGE")" \
  || die "$PACKAGE has no launcher activity to trace (resolve-activity returned nothing)"
say "component $COMPONENT"

# ------------------------------------------------------------------ modes ---

DEV_DIR=/data/local/tmp/andro-substrate-trace
adb_sh mkdir -p "$DEV_DIR"

# Write the capture record beside a trace. $1 outcome, $2 deviceBytes, $3 pulledBytes.
#
# The record is the only place the sampling mode is written down: the batched
# trace layout does not record it, so a trace with no record has to be treated as
# `undetermined`, i.e. a lower bound.
write_record() {
  local outcome="$1" size="$2" got="$3"
  if [ -n "$SAMPLING" ]; then
    local jmode="sampled" jsampling="$SAMPLING"
  else
    local jmode="exhaustive" jsampling="null"
  fi
  cat > "$rec" <<JSON
{
  "package": "$PACKAGE",
  "apk": "$APK_BASE",
  "apkSha256": "$APK_SHA",
  "component": "$COMPONENT",
  "captureMode": "$MODE",
  "mode": "$jmode",
  "sampling_us": $jsampling,
  "deviceBytes": $size,
  "run": $k,
  "outcome": "$outcome",
  "detail": "${PRECONDITION:-}",
  "serial": "${SERIAL:-default}",
  "settleSeconds": $SETTLE,
  "windowSeconds": $WINDOW
}
JSON
}

# $1 = device path, $2 = run index
capture_one() {
  local devfile="$1" k="$2"
  local dst="$OUTDIR/$PACKAGE.$TAG.run$k.trace"
  local rec="$dst.json"

  if [ "$REUSE" = 1 ] && [ -s "$dst" ]; then
    say "run $k: reusing $dst"
    return 0
  fi

  adb_sh rm -f "$devfile"
  adb_sh am force-stop "$PACKAGE"
  sleep 1

  case "$MODE" in
    startprof)
      # From process start. `--streaming` is mandatory: see the header comment.
      adb_sh am start --start-profiler "$devfile" --streaming -n "$COMPONENT" >/dev/null
      sleep "$WINDOW"
      # Streaming has already flushed; force-stop so the next run is clean.
      adb_sh am force-stop "$PACKAGE"
      ;;
    teardown|idle)
      adb_sh am start -n "$COMPONENT" >/dev/null
      sleep "$SETTLE"
      if [ -n "$SAMPLING" ]; then
        adb_sh am profile start --sampling "$SAMPLING" "$PACKAGE" "$devfile" >/dev/null
      else
        adb_sh am profile start "$PACKAGE" "$devfile" >/dev/null
      fi
      sleep 1
      if [ "$MODE" = teardown ]; then
        if ! finish_activity; then
          PRECONDITION="activity still resumed after BACK; this app consumes the BACK key"
          adb_sh rm -f "$devfile" >/dev/null
          : > "$dst"
          write_record "failed-precondition-not-destroyed" 0 0
          say "run $k: failed-precondition-not-destroyed (BACK did not destroy $COMPONENT)"
          return 1
        fi
      else
        adb_sh am start -n "$COMPONENT" >/dev/null   # already resumed: no re-creation
      fi
      sleep "$WINDOW"
      adb_sh am profile stop "$PACKAGE" >/dev/null
      ;;
    create|recreate)
      adb_sh am start -n "$COMPONENT" >/dev/null
      sleep "$SETTLE"
      if [ "$MODE" = create ]; then
        # Finish the activity BEFORE profiling, so the window that follows
        # contains a creation with no teardown in it.
        if ! finish_activity; then
          # Record the failure and skip: a `create` run in which the activity
          # survived BACK is an idle trace wearing the wrong label.
          PRECONDITION="activity still resumed after BACK; this app consumes the BACK key"
          adb_sh rm -f "$devfile" >/dev/null
          : > "$dst"
          write_record "failed-precondition-not-destroyed" 0 0
          say "run $k: failed-precondition-not-destroyed (BACK did not destroy $COMPONENT)"
          return 1
        fi
      fi
      if [ -n "$SAMPLING" ]; then
        adb_sh am profile start --sampling "$SAMPLING" "$PACKAGE" "$devfile" >/dev/null
      else
        adb_sh am profile start "$PACKAGE" "$devfile" >/dev/null
      fi
      sleep 1
      if [ "$MODE" = recreate ]; then
        adb_sh am start --activity-clear-task -n "$COMPONENT" >/dev/null
      else
        adb_sh am start -n "$COMPONENT" >/dev/null
      fi
      sleep "$WINDOW"
      adb_sh am profile stop "$PACKAGE" >/dev/null
      ;;
  esac
  sleep 1

  local size
  size="$(adb_sh stat -c %s "$devfile" 2>/dev/null || echo 0)"
  case "$size" in ''|*[!0-9]*) size=0 ;; esac

  local outcome
  : > "$dst"                       # never leave a stale file that could be counted
  if [ "$size" -gt 0 ]; then
    "${ADB[@]}" pull "$devfile" "$dst" >/dev/null 2>&1 || true
  fi
  adb_sh rm -f "$devfile" >/dev/null

  # Classify from the bytes we actually received, not from what we asked for.
  # `am` and ART both fail silently: a wrong flag combination leaves a real,
  # correctly-named, 0-byte file, and `pm path` succeeding says nothing about
  # whether a trace was written.
  local got magic4 magic8
  got="$(wc -c < "$dst" | tr -d ' ')"
  magic8="$(head -c 8 "$dst" 2>/dev/null || true)"
  magic4="$(head -c 4 "$dst" 2>/dev/null || true)"
  if [ "$got" -eq 0 ]; then
    outcome="failed-zero-bytes"
  elif [ "$size" != "$got" ]; then
    outcome="failed-truncated-pull"
  elif [ "$magic8" = "*version" ] || [ "$magic4" = "SLOW" ]; then
    # Both layouts start with something parse.py recognises: `*version` for the
    # batched preamble, `SLOW` for the continuous data section.
    outcome="ok"
  else
    outcome="failed-unrecognised"
  fi

  write_record "$outcome" "$size" "$got"

  say "run $k: $outcome (${got}B device ${size}B) -> $(basename "$dst")"
  [ "$outcome" = "ok" ]
}

# ------------------------------------------------------------------- main ---

TAG="$MODE"
[ -n "$SAMPLING" ] && TAG="$MODE-s$SAMPLING"

FAILED=0
for k in $(seq 1 "$RUNS"); do
  devfile="$DEV_DIR/$PACKAGE.$TAG.run$k.trace"
  if ! capture_one "$devfile" "$k"; then
    FAILED=$((FAILED + 1))
  fi
done

say ""
say "captured $((RUNS - FAILED))/$RUNS usable run(s) into $OUTDIR"
[ "$FAILED" -eq 0 ] || say "$FAILED run(s) recorded as FAILED CAPTURES — see the .trace.json records"
exit 0
