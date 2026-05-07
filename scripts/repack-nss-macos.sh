#!/usr/bin/env bash
# Repack a fresh certutil.osx.zip for Autofirma's configurator using the
# Mozilla NSS toolkit installed via Homebrew. Replaces the 2010-era binaries
# previously bundled in the repo (M3.4, 2026-05-07).
#
# Output: certutil.osx.zip with arm64 (or x86_64) native binaries — no Rosetta 2
# required on Apple Silicon.
#
# Requires: Homebrew (brew install nss).
# Usage:    ./scripts/repack-nss-macos.sh [output-path]
set -euo pipefail

OUTPUT="${1:-${PWD}/certutil.osx.zip}"
WORK_DIR="$(mktemp -d -t nss-macos-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

if ! command -v brew >/dev/null 2>&1; then
    echo "ERROR: Homebrew not found. Install from https://brew.sh." >&2
    exit 1
fi

if ! brew list nss >/dev/null 2>&1; then
    echo ">>> Installing Homebrew nss formula..."
    brew install nss
fi

NSS_PREFIX="$(brew --prefix nss)"
echo ">>> Brew nss prefix: $NSS_PREFIX"
echo ">>> Working dir:     $WORK_DIR"
echo ">>> Output:          $OUTPUT"

mkdir -p "$WORK_DIR/certutil"

# Binary
cp "$NSS_PREFIX/bin/certutil" "$WORK_DIR/certutil/"

# Dylibs. Mirror the filenames of the legacy bundle so ConfiguratorFirefoxMac.java
# can keep its existing relative-path lookups.
for f in libnspr4 libnss3 libnssutil3 libplc4 libplds4 libsmime3 libssl3 \
         libfreebl3 libnssckbi libnssdbm3 libsoftokn3 libsqlite3; do
    src="$NSS_PREFIX/lib/${f}.dylib"
    if [ -f "$src" ]; then
        cp "$src" "$WORK_DIR/certutil/"
    else
        # Try the unversioned link inside the cellar
        cellar=$(find "$NSS_PREFIX/lib/" -maxdepth 1 -name "${f}*.dylib" -print -quit 2>/dev/null || true)
        if [ -n "$cellar" ]; then
            cp "$cellar" "$WORK_DIR/certutil/${f}.dylib"
        else
            echo "WARNING: ${f}.dylib not found under $NSS_PREFIX/lib/ (skipping)" >&2
        fi
    fi
done

# NSPR libs may live alongside (Homebrew nss depends on nspr; bring its dylibs too).
NSPR_PREFIX="$(brew --prefix nspr 2>/dev/null || true)"
if [ -n "$NSPR_PREFIX" ] && [ -d "$NSPR_PREFIX/lib" ]; then
    for f in libnspr4 libplc4 libplds4; do
        src="$NSPR_PREFIX/lib/${f}.dylib"
        if [ -f "$src" ] && [ ! -f "$WORK_DIR/certutil/${f}.dylib" ]; then
            cp "$src" "$WORK_DIR/certutil/"
        fi
    done
fi

# Rewrite the install names so certutil finds its dylibs in the same dir
# (otherwise it would resolve absolute paths from /opt/homebrew/...).
echo ">>> Rewriting install names with install_name_tool..."
cd "$WORK_DIR/certutil"
for bin in certutil *.dylib; do
    [ -f "$bin" ] || continue
    # Get the dependencies that point into the brew cellar and rewrite them.
    otool -L "$bin" 2>/dev/null | awk 'NR>1 {print $1}' | while read -r dep; do
        case "$dep" in
            /opt/homebrew/*|/usr/local/Cellar/*|/opt/homebrew/Cellar/*)
                base="$(basename "$dep")"
                # Strip any version suffix in the install name to match our renamed file
                short="${base%%.*}"
                # Find a matching local dylib (libnss3.dylib, libnss3.4.dylib → libnss3.dylib)
                for candidate in "$short.dylib" "$base"; do
                    if [ -f "$WORK_DIR/certutil/$candidate" ]; then
                        install_name_tool -change "$dep" "@executable_path/$candidate" "$bin" 2>/dev/null || true
                        install_name_tool -change "$dep" "@loader_path/$candidate" "$bin" 2>/dev/null || true
                        break
                    fi
                done
                ;;
        esac
    done
done

echo ">>> Bundled binary architecture:"
file certutil
echo
echo ">>> Library list:"
ls -la

cd "$WORK_DIR" && zip -qr "$OUTPUT" certutil/
echo ">>> Wrote: $OUTPUT"
unzip -l "$OUTPUT" | head -20
