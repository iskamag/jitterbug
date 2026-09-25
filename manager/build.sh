#!/bin/bash
# Build the root manager app: javac + aapt2 + d8 + zipalign + apksigner.
#
# Needs an Android SDK build-tools + platform.  Point SDK_DIR at it (or set
# BT/ANDROID_JAR directly):
#
#   SDK_DIR=~/Android/Sdk ./build.sh
#
# SU_DIR (the daemon's toolbox dir) is substituted into SuClient.java so the
# app connects to the same socket sud listens on.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if [ -z "${BT:-}" ] || [ -z "${ANDROID_JAR:-}" ]; then
    SDK_DIR="${SDK_DIR:-${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}}"
    [ -n "$SDK_DIR" ] || { echo "build.sh: set SDK_DIR (or BT and ANDROID_JAR)"; exit 2; }
    BT="${BT:-$(ls -d "$SDK_DIR"/build-tools/* 2>/dev/null | sort -V | tail -1)}"
    ANDROID_JAR="${ANDROID_JAR:-$(ls "$SDK_DIR"/platforms/*/android.jar 2>/dev/null | sort -V | tail -1)}"
fi
[ -x "$BT/aapt2" ] || { echo "build.sh: no aapt2 in $BT"; exit 2; }
[ -f "$ANDROID_JAR" ] || { echo "build.sh: no android.jar ($ANDROID_JAR)"; exit 2; }

SU_DIR="${SU_DIR:-/data/local/tmp}"
SRC="$HERE/build/src"
rm -rf "$HERE/build" "$HERE/out"
mkdir -p "$HERE/build/compiled" "$HERE/build/gen" "$HERE/build/classes" \
         "$HERE/build/dex" "$HERE/out" "$SRC"

# copy the sources and point SuClient at the configured socket
cp -r "$HERE/src/." "$SRC/"
sed -i "s#/data/local/tmp/su.sock#${SU_DIR}/su.sock#" "$SRC/com/matepad/sumgr/SuClient.java"

"$BT/aapt2" compile --dir "$HERE/res" -o "$HERE/build/compiled/res.zip"

"$BT/aapt2" link \
    -o "$HERE/build/base.apk" \
    -I "$ANDROID_JAR" \
    --manifest "$HERE/AndroidManifest.xml" \
    --java "$HERE/build/gen" \
    --min-sdk-version 29 --target-sdk-version 29 \
    --version-code 1 --version-name 1.0 \
    "$HERE/build/compiled/res.zip"

find "$SRC" "$HERE/build/gen" -name '*.java' > "$HERE/build/sources.txt"
javac --release 11 -nowarn -d "$HERE/build/classes" \
    -classpath "$ANDROID_JAR" @"$HERE/build/sources.txt"

find "$HERE/build/classes" -name '*.class' > "$HERE/build/classes.txt"
"$BT/d8" --min-api 29 --lib "$ANDROID_JAR" --output "$HERE/build/dex" @"$HERE/build/classes.txt"

cp "$HERE/build/base.apk" "$HERE/build/unsigned.apk"
(cd "$HERE/build/dex" && zip -q -X "$HERE/build/unsigned.apk" classes.dex)
"$BT/zipalign" -f -p 4 "$HERE/build/unsigned.apk" "$HERE/build/aligned.apk"

# a debug key, generated on first build; never commit it
KS="${KS:-$HERE/sumgr.keystore}"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$KS" -storepass android -keypass android \
        -alias sumgr -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Root Manager, OU=dev, O=matepad, L=x, ST=x, C=US"
fi

"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias sumgr --v1-signing-enabled true --v2-signing-enabled true \
    --v4-signing-enabled false --out "$HERE/out/sumgr.apk" "$HERE/build/aligned.apk"

"$BT/apksigner" verify --min-sdk-version 21 "$HERE/out/sumgr.apk"
echo "[+] $HERE/out/sumgr.apk"
