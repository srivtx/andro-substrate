#!/bin/bash
# Regenerate fixtures/device-android13.jsonl: build the calibration APK, push
# the corpus, run it on the AVD, pull the answers back.
#
#   tools/run_calibration.sh                 # use the already-running emulator
#   ANDROID_SERIAL=emulator-5554 tools/run_calibration.sh
#
# The APK source lives in tools/calapp/. It is a deliberately tiny Android app:
# it reads fixtures/cases.jsonl and calls android.graphics.Paint, and it writes
# down whatever the framework says. It contains no measurement logic of its own,
# because a calibration harness that measures its own model is not a harness.
set -euo pipefail
cd "$(dirname "$0")/.."

SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="$SDK/build-tools/34.0.0"
ADB="$SDK/platform-tools/adb"
WORK="${TMPDIR:-/tmp}/substrate-text-cal"
PKG=org.substrate.cal
SERIAL="${ANDROID_SERIAL:-emulator-5554}"
ADB="$ADB -s $SERIAL"

AJ="$WORK/platforms/android-33/android.jar"
if [ ! -f "$AJ" ]; then
  echo "fetching android-33 platform jar (one-off, ~60MB)"
  mkdir -p "$WORK"
  export JAVA_HOME="$(/usr/libexec/java_home)"
  yes | "$HOME/Library/Android/sdk/cmdline-tools/latest/bin/sdkmanager" --sdk_root="$WORK" "platforms;android-33" >/dev/null 2>&1 || true
fi

if ! $ADB shell true 2>/dev/null; then
  echo "no device at $SERIAL. Start it with:"
  echo "  \$ANDROID_HOME/emulator/emulator -avd sub -no-snapshot-load &"
  exit 1
fi

echo "== building calibration apk"
rm -rf "$WORK/build"
mkdir -p "$WORK/build/compiled" "$WORK/build/classes" "$WORK/build/gen"
"$BT/aapt2" compile --dir tools/calapp/res -o "$WORK/build/compiled/res.zip"
"$BT/aapt2" link -o "$WORK/build/base.apk" -I "$AJ" \
  --manifest tools/calapp/AndroidManifest.xml --java "$WORK/build/gen" \
  --min-sdk-version 26 --target-sdk-version 33 "$WORK/build/compiled/res.zip"
javac -source 8 -target 8 -nowarn -bootclasspath "$AJ" -d "$WORK/build/classes" \
  $(find tools/calapp/src "$WORK/build/gen" -name '*.java') 2>&1 |
  grep -v 'bootstrap class path' || true
"$BT/d8" --output "$WORK/build" --lib "$AJ" --min-api 26 \
  $(find "$WORK/build/classes" -name '*.class')
cp "$WORK/build/base.apk" "$WORK/build/cal.apk"
( cd "$WORK/build" && zip -q -X cal.apk classes.dex )
[ -f "$WORK/debug.keystore" ] || keytool -genkeypair -keystore "$WORK/debug.keystore" \
  -storepass android -keypass android -alias cal -keyalg RSA -keysize 2048 \
  -validity 10000 -dname "CN=substrate text calibration" >/dev/null 2>&1
"$BT/zipalign" -f 4 "$WORK/build/cal.apk" "$WORK/build/aligned.apk"
"$BT/apksigner" sign --ks "$WORK/debug.keystore" --ks-pass pass:android \
  --key-pass pass:android --out "$WORK/build/cal-signed.apk" "$WORK/build/aligned.apk"

$ADB uninstall "$PKG" >/dev/null 2>&1 || true
$ADB install -g "$WORK/build/cal-signed.apk" >/dev/null
# The app data dir is created by the installer with the right owner and label,
# but a previous run leaves a root-owned `files/` behind and the app then cannot
# read its own corpus. Fix ownership first, then the SELinux label, because
# restorecon derives the label from the owner.
APPUID=$($ADB shell dumpsys package "$PKG" | grep -m1 userId= | tr -d ' \r' | cut -d= -f2)
$ADB shell "mkdir -p /data/data/$PKG/files && chown -R $APPUID:$APPUID /data/data/$PKG" >/dev/null
$ADB shell "restorecon -RF /data/data/$PKG" >/dev/null 2>&1 || true

echo "== pushing $(wc -l < fixtures/cases.jsonl) cases"
$ADB push fixtures/cases.jsonl "/data/local/tmp/cases.jsonl" >/dev/null
$ADB shell "cp /data/local/tmp/cases.jsonl /data/data/$PKG/files/cases.jsonl" >/dev/null
$ADB shell "chown $APPUID:$APPUID /data/data/$PKG/files/cases.jsonl" >/dev/null

for LOCALE in ${LOCALES:-en-US}; do
  echo "== running locale=$LOCALE"
  $ADB shell am force-stop "$PKG"
  if [ "$LOCALE" = "en-US" ]; then
    $ADB shell am start -n "$PKG/.CalActivity" >/dev/null
    OUT=fixtures/device-android13.jsonl
  else
    $ADB shell am start -n "$PKG/.CalActivity" --es locale "$LOCALE" >/dev/null
    OUT="fixtures/device-android13-$LOCALE.jsonl"
  fi
  # Wait for the row count on the device to reach the corpus size. Polling the
  # *remote* line count rather than sleeping a fixed time is not a nicety: a
  # truncated recording parses cleanly and averages over a subset, which is
  # precisely the failure this harness exists to catch. `Report::missing`
  # catches it anyway, but only if the tool does not hand it a short file in
  # the first place.
  WANT=$(( $(wc -l < fixtures/cases.jsonl) + 1 ))
  for _ in $(seq 1 240); do
    GOT=$($ADB shell "cat /data/data/$PKG/files/device.jsonl 2>/dev/null | wc -l" | tr -d ' \r')
    [ -n "$GOT" ] && [ "$GOT" -ge "$WANT" ] && break
    sleep 0.5
  done
  if [ "$LOCALE" = "en-US" ]; then
    $ADB shell "cat /data/data/$PKG/files/device.jsonl" > "$OUT"
  else
    $ADB shell "cat /data/data/$PKG/files/device-$LOCALE.jsonl" > "$OUT"
  fi
  echo "   -> $OUT ($(wc -l < "$OUT") lines)"
done

echo "== done"
