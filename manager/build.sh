#!/bin/bash
# Build the root manager app: javac + aapt2 + d8 + zipalign + apksigner.
# Toolchain paths and ordering come from tools/sdk/README.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
BT="$ROOT/tools/sdk/build-tools/34.0.0"
ANDROID_JAR="$ROOT/tools/sdk/platforms/android-29/android.jar"
HERE="$(cd "$(dirname "$0")" && pwd)"

rm -rf "$HERE/build" "$HERE/out"
mkdir -p "$HERE/build/compiled" "$HERE/build/gen" "$HERE/build/classes" "$HERE/build/dex" "$HERE/out"

"$BT/aapt2" compile --dir "$HERE/res" -o "$HERE/build/compiled/res.zip"

"$BT/aapt2" link \
    -o "$HERE/build/base.apk" \
    -I "$ANDROID_JAR" \
    --manifest "$HERE/AndroidManifest.xml" \
    --java "$HERE/build/gen" \
    --min-sdk-version 29 --target-sdk-version 29 \
    --version-code 1 --version-name 1.0 \
    "$HERE/build/compiled/res.zip"

find "$HERE/src" "$HERE/build/gen" -name '*.java' > "$HERE/build/sources.txt"
javac --release 11 -nowarn -d "$HERE/build/classes" \
    -classpath "$ANDROID_JAR" @"$HERE/build/sources.txt"

find "$HERE/build/classes" -name '*.class' > "$HERE/build/classes.txt"
"$BT/d8" --min-api 29 --lib "$ANDROID_JAR" --output "$HERE/build/dex" @"$HERE/build/classes.txt"

cp "$HERE/build/base.apk" "$HERE/build/unsigned.apk"
(cd "$HERE/build/dex" && zip -q -X "$HERE/build/unsigned.apk" classes.dex)
"$BT/zipalign" -f -p 4 "$HERE/build/unsigned.apk" "$HERE/build/aligned.apk"

if [ ! -f "$HERE/sumgr.keystore" ]; then
    keytool -genkeypair -keystore "$HERE/sumgr.keystore" -storepass android -keypass android \
        -alias sumgr -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Root Manager, OU=dev, O=matepad, L=x, ST=x, C=US"
fi

"$BT/apksigner" sign --ks "$HERE/sumgr.keystore" --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias sumgr --v1-signing-enabled true --v2-signing-enabled true \
    --v4-signing-enabled false --out "$HERE/out/sumgr.apk" "$HERE/build/aligned.apk"

"$BT/apksigner" verify --min-sdk-version 21 "$HERE/out/sumgr.apk"
echo "[+] $HERE/out/sumgr.apk"
