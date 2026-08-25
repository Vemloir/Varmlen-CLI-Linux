#!/bin/sh
# Install the CLI, daemon and helper.
#
# Works both from a source checkout (after `scripts/build-release.sh`) and from
# an extracted release tarball, where the binaries sit next to this script.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$HERE/varmlend" ]; then
    BUILD=$HERE                       # extracted release tarball
    UNIT=$HERE/varmlend@.service
else
    BUILD=$HERE/../target/release     # source checkout
    UNIT=$HERE/varmlend@.service
fi

for binary in varmlend varmlen-net varmlen-cli; do
    [ -f "$BUILD/$binary" ] || {
        echo "missing $BUILD/$binary" >&2
        echo "build first:  ./scripts/build-release.sh" >&2
        exit 1
    }
done

# Reinstalling under a running daemon would leave the old process serving from
# a deleted binary until something restarts it.
RESTART=
for instance in $(systemctl list-units --state=active --no-legend 'varmlend@*' 2>/dev/null | cut -d' ' -f1); do
    RESTART="$RESTART $instance"
done
[ -n "$RESTART" ] && systemctl stop $RESTART

# The daemon looks the helper up at this exact path (daemon/src/system.rs).
install -d /usr/libexec/varmlen
install -m 0755 "$BUILD/varmlend"    /usr/libexec/varmlen/varmlend
install -m 0755 "$BUILD/varmlen-net" /usr/libexec/varmlen/varmlen-net
install -m 0755 "$BUILD/varmlen-cli" /usr/bin/varmlen-cli
install -m 0644 "$UNIT" /etc/systemd/system/varmlend@.service
systemctl daemon-reload

if [ -n "$RESTART" ]; then
    systemctl start $RESTART
    echo "Reinstalled and restarted:$RESTART"
else
    echo "Installed. Start the daemon for your user with:"
    echo "  sudo systemctl enable --now varmlend@\$(id -u)"
fi
