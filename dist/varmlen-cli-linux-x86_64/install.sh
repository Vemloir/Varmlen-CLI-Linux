#!/bin/sh
# Install the Varmlen CLI. Needs no privileges.
#
# The client goes on PATH; the daemon, its helper and xray are staged in the
# user's data directory. They are moved into /opt/varmlen-cli as root the first
# time a command actually needs the daemon — see cli/src/setup.rs. The daemon
# cannot run unprivileged, but getting the client should not require deciding to
# trust an installer with root.
#
# Works from a source checkout (after scripts/build-release.sh, with xray
# fetched by scripts/fetch-xray.sh) and from an extracted release tarball.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# An extracted release tarball keeps everything beside this script; a source
# checkout puts it under target/, where the release build is per-target.
if [ -f "$HERE/varmlend" ]; then
    BUILD=$HERE
else
    BUILD=
    for candidate in \
        "$HERE/../target/$(uname -m)-unknown-linux-musl/release" \
        "$HERE/../target/release"
    do
        [ -f "$candidate/varmlend" ] && { BUILD=$candidate; break; }
    done
    [ -n "$BUILD" ] || BUILD=$HERE/../target/release
fi

BIN_DIR=${XDG_BIN_HOME:-$HOME/.local/bin}
STAGE=${XDG_DATA_HOME:-$HOME/.local/share}/varmlen/stage

for component in varmlen-cli varmlend varmlen-net xray; do
    [ -f "$BUILD/$component" ] || {
        echo "missing $BUILD/$component" >&2
        echo "build first:  ./scripts/build-release.sh" >&2
        echo "and fetch xray:  ./scripts/fetch-xray.sh target/release" >&2
        exit 1
    }
done

mkdir -p "$BIN_DIR" "$STAGE"
install -m 0755 "$BUILD/varmlen-cli" "$BIN_DIR/varmlen-cli"
for component in varmlend varmlen-net xray; do
    install -m 0755 "$BUILD/$component" "$STAGE/$component"
done
install -m 0644 "$HERE/varmlen-cli@.service" "$STAGE/varmlen-cli@.service" 2>/dev/null ||
    install -m 0644 "$HERE/../packaging/varmlen-cli@.service" "$STAGE/varmlen-cli@.service"

echo "Installed varmlen-cli to $BIN_DIR."

case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *)
        echo
        echo "$BIN_DIR is not on your PATH. Add it:"
        echo "  echo 'export PATH=\"\$PATH:$BIN_DIR\"' >> ~/.profile"
        echo "and open a new shell, or run it as $BIN_DIR/varmlen-cli."
        ;;
esac
