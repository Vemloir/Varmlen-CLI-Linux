#!/bin/sh
# Fetch the pinned xray-core build the daemon runs.
#
# The daemon executes /opt/varmlen-cli/xray; without it nothing connects.
# It is fetched at package time rather than committed, and always checked
# against the digest XTLS publishes beside the archive.
#
# xray-core is MPL-2.0. It is a separate executable the daemon runs as a child
# process, never linked, so bundling it here is mere aggregation; MPL-2.0 §3.3
# additionally permits distribution under a GPL "Secondary License". Its own
# licence ships beside it as LICENSE.xray.
set -eu

XRAY_VERSION=${XRAY_VERSION:-v26.3.27}
OUT=${1:?usage: fetch-xray.sh <output-dir> [arch]}
ARCH=${2:-x86_64}

case "$ARCH" in
    x86_64)  ASSET=Xray-linux-64.zip ;;
    aarch64) ASSET=Xray-linux-arm64-v8a.zip ;;
    *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

BASE=https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "Fetching xray-core $XRAY_VERSION ($ARCH)…"
curl -fsSL "$BASE/$ASSET" -o "$TMP/$ASSET"
curl -fsSL "$BASE/$ASSET.dgst" -o "$TMP/dgst"

published=$(sed -n 's/^SHA2-256=[[:space:]]*//p' "$TMP/dgst" | tr -d '[:space:]')
actual=$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)
[ -n "$published" ] || { echo "no SHA2-256 in the published digest" >&2; exit 1; }
[ "$published" = "$actual" ] || {
    echo "xray checksum mismatch:" >&2
    echo "  published $published" >&2
    echo "  actual    $actual" >&2
    exit 1
}
echo "Checksum verified against the digest published with the release."

mkdir -p "$OUT"
unzip -q -o "$TMP/$ASSET" xray LICENSE -d "$TMP/x"
install -m 0755 "$TMP/x/xray" "$OUT/xray"
install -m 0644 "$TMP/x/LICENSE" "$OUT/LICENSE.xray"
"$OUT/xray" version | head -1
