#!/bin/sh
# Install the CLI, daemon and helper. Run after `cargo build --release`;
# works from any directory.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD=$ROOT/target/release

for binary in varmlend varmlen-net varmlen-cli; do
    [ -f "$BUILD/$binary" ] || {
        echo "missing $BUILD/$binary" >&2
        echo "build first:  cd $ROOT && cargo build --release" >&2
        exit 1
    }
done

# The daemon looks the helper up at this exact path (daemon/src/system.rs).
install -d /usr/libexec/varmlen
install -m 0755 "$BUILD/varmlend"    /usr/libexec/varmlen/varmlend
install -m 0755 "$BUILD/varmlen-net" /usr/libexec/varmlen/varmlen-net
install -m 0755 "$BUILD/varmlen-cli" /usr/bin/varmlen-cli
install -m 0644 "$ROOT/packaging/varmlend@.service" /etc/systemd/system/varmlend@.service
systemctl daemon-reload

echo "Installed. Start the daemon for your user with:"
echo "  sudo systemctl enable --now varmlend@\$(id -u)"
