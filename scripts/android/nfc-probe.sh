#!/usr/bin/env bash
# Builds the NFC probe (scripts/android/nfc-probe/), installs it on the Android phone adb sees,
# starts it and follows its log. The probe runs the FIDO applet checks against a device held to
# the phone: SELECT, getInfo, selection by the tap, command chaining, and a screen answered on the
# device while the phone polls for status updates.
#
#   scripts/android/nfc-probe.sh [steps]
#
# steps: a comma-separated subset of select,info,selection,chain,wait (all by default).
# Needs the Android SDK (ANDROID_HOME, or Android Studio's ~/Library/Android/sdk) with a platform
# and build tools, a JDK, and adb authorized on the phone.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
sdk=${ANDROID_HOME:-$HOME/Library/Android/sdk}
build_tools=$(find "$sdk/build-tools" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -1)
platform=$(find "$sdk/platforms" -mindepth 1 -maxdepth 1 -type d -name 'android-*' | sort -V | tail -1)
android_jar="$platform/android.jar"
keystore="$HOME/.android/debug.keystore"
package=world.structured.passkeys.nfcprobe

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
mkdir "$out/classes"

if [[ ! -f "$keystore" ]]; then
    mkdir -p "$(dirname "$keystore")"
    keytool -genkeypair -keystore "$keystore" -storepass android -keypass android \
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US" >/dev/null
fi

"$build_tools/aapt2" link -o "$out/base.apk" --manifest "$here/nfc-probe/AndroidManifest.xml" \
    -I "$android_jar"
find "$here/nfc-probe/src" -name '*.java' >"$out/sources"
javac -source 11 -target 11 -Xlint:-options -classpath "$android_jar" -d "$out/classes" \
    @"$out/sources"
find "$out/classes" -name '*.class' >"$out/class-files"
"$build_tools/d8" --min-api 28 --lib "$android_jar" --output "$out" @"$out/class-files"
(cd "$out" && zip -q base.apk classes.dex)
"$build_tools/zipalign" -f 4 "$out/base.apk" "$out/aligned.apk"
"$build_tools/apksigner" sign --ks "$keystore" --ks-pass pass:android --out "$out/probe.apk" \
    "$out/aligned.apk"

adb install -r "$out/probe.apk" >/dev/null
adb logcat -c
adb shell am start -n "$package/.MainActivity" ${1:+--es steps "$1"} >/dev/null
echo "probe started; hold the device to the phone"
exec adb logcat -s NfcProbe:I
