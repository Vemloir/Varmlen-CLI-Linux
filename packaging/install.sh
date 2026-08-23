#!/bin/sh
# Install the CLI, daemon and helper. Run from the repository root after
# `cargo build --release`.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

# The daemon looks the helper up at this exact path (daemon/src/system.rs).
install -d /usr/libexec/varmlen
install -m 0755 target/release/varmlend    /usr/libexec/varmlen/varmlend
install -m 0755 target/release/varmlen-net /usr/libexec/varmlen/varmlen-net
install -m 0755 target/release/varmlen-cli /usr/bin/varmlen-cli
install -m 0644 packaging/varmlend@.service /etc/systemd/system/varmlend@.service
systemctl daemon-reload

echo "Installed. Start the daemon for your user with:"
echo "  sudo systemctl enable --now varmlend@\$(id -u)"
