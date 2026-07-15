#!/usr/bin/env bash
# Repack a fresh certutil.linux.zip for Autofirma's configurator using the
# Mozilla NSS toolkit shipped in Debian. Replaces the 2010-era binaries
# previously bundled in the repo (M3.4, 2026-05-07).
#
# Output: certutil.linux.zip with x86_64 NSS binaries from Debian's main pool.
# Structure: certutil/<binaries>, matching what ConfiguratorFirefoxLinux.java expects.
#
# Approach: download .deb files from the official Debian mirror, extract their
# contents with `ar` + `tar` (no Docker daemon required, runs on macOS host).
#
# Usage:    ./scripts/repack-nss-linux.sh [output-path]
set -euo pipefail

OUTPUT="${1:-${PWD}/certutil.linux.zip}"
WORK_DIR="$(mktemp -d -t nss-linux-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo ">>> Working dir: $WORK_DIR"
echo ">>> Output:      $OUTPUT"

MIRROR="https://deb.debian.org/debian/pool/main"

# Mapping: <binary-package-name> <source-package-name>. Both come from the
# Debian "main" pool, indexed by first letter of the source package.
PACKAGES=(
	"libnss3 nss"
	"libnss3-tools nss"
	"libsmime3 nss"
	"libssl3 nss"
	"libnssutil3 nss"
	"libnspr4 nspr"
	"libplc4 nspr"
	"libplds4 nspr"
)

fetch_deb() {
	local pkg="$1"
	local src="$2"
	local first="${src:0:1}"
	local index_url="${MIRROR}/${first}/${src}/"
	# Pick the highest-version amd64 deb whose filename starts with <pkg>_.
	local listing
	listing="$(curl -fsSL "$index_url" |
		grep -oE "${pkg}_[^\"']*_amd64\.deb" |
		sort -V | tail -1 || true)"
	if [ -z "$listing" ]; then
		echo "ERROR: could not find $pkg under $index_url" >&2
		return 1
	fi
	if [ -f "${WORK_DIR}/${listing}" ]; then
		return 0 # idempotent
	fi
	echo ">>> Downloading $listing"
	curl -fsSL -o "${WORK_DIR}/${listing}" "${index_url}${listing}"
}

cd "$WORK_DIR"
for entry in "${PACKAGES[@]}"; do
	read -r pkg src <<<"$entry"
	fetch_deb "$pkg" "$src" || {
		echo "WARNING: skipping $pkg" >&2
	}
done

mkdir -p out/certutil tmp_extract
echo ">>> Extracting .deb archives..."
for d in *.deb; do
	[ -f "$d" ] || continue
	extract_dir="$(mktemp -d -p "$WORK_DIR" extract-XXXXXX)"
	(cd "$extract_dir" && ar x "$WORK_DIR/$d")

	if [ -f "$extract_dir/data.tar.zst" ]; then
		if command -v zstd >/dev/null 2>&1; then
			zstd -d -q "$extract_dir/data.tar.zst" -o "$extract_dir/data.tar"
			tar -xf "$extract_dir/data.tar" -C tmp_extract
		else
			tar --use-compress-program='zstd -d' -xf "$extract_dir/data.tar.zst" -C tmp_extract
		fi
	elif [ -f "$extract_dir/data.tar.xz" ]; then
		tar -xJf "$extract_dir/data.tar.xz" -C tmp_extract
	elif [ -f "$extract_dir/data.tar.gz" ]; then
		tar -xzf "$extract_dir/data.tar.gz" -C tmp_extract
	else
		echo "WARNING: no data.tar.* in $d" >&2
	fi
	rm -rf "$extract_dir"
done

LIB_DIR="tmp_extract/usr/lib/x86_64-linux-gnu"

if [ ! -f "tmp_extract/usr/bin/certutil" ]; then
	echo "ERROR: certutil binary not extracted (libnss3-tools missing?)" >&2
	exit 1
fi

cp tmp_extract/usr/bin/certutil out/certutil/
for f in libnss3.so libsmime3.so libssl3.so libnssutil3.so libnspr4.so libplc4.so libplds4.so; do
	if [ -f "$LIB_DIR/$f" ]; then
		cp "$LIB_DIR/$f" out/certutil/
	else
		echo "WARNING: $f not found in $LIB_DIR" >&2
	fi
done
# NSS PKCS#11 modules + signature checks (private subdir of the NSS lib path)
if [ -d "$LIB_DIR/nss" ]; then
	cp -a "$LIB_DIR/nss/"* out/certutil/ 2>/dev/null || true
fi

echo
echo ">>> Bundle inventory:"
ls -la out/certutil/
echo
echo ">>> Binary architecture:"
file out/certutil/certutil 2>/dev/null || echo "(file(1) not informative on this host; ELF 64-bit expected)"

cd out && zip -qr "$OUTPUT" certutil/

echo
echo ">>> Wrote: $OUTPUT"
unzip -l "$OUTPUT" | head -25
