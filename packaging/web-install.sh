#!/bin/sh
#
# Varmlen CLI installer.
#
#   curl -fsSL https://aegisvpn.org/varmlen-cli-linux/install.sh | sh
#
# Downloads the release tarball from GitHub, verifies its SHA-256 against the
# checksums published with the same release, and installs without privileges:
#
#   ~/.local/bin/varmlen-cli
#   ~/.local/share/varmlen/stage/{varmlend,varmlen-net,xray,varmlen-cli@.service}
#
# The daemon has to run as root, so those staged files are moved into
# /opt/varmlen-cli the first time a command needs it — varmlen-cli asks for
# sudo at that point, and not before. A daemon already running from an earlier
# install is replaced too, because installing a client does not install its
# daemon: the running process keeps the files it started with.
#
# Environment:
#   VARMLEN_VERSION   install a specific tag (default: the latest release)
#
# Source: https://github.com/Vemloir/Varmlen-CLI-Linux   (GPL-3.0-only)
set -eu

REPO=Vemloir/Varmlen-CLI-Linux
VERSION=${VARMLEN_VERSION:-}

die() { echo "varmlen: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }

need tar
need sha256sum
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL "$1" -o "$2"; }
    fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -qO "$2" "$1"; }
    fetch_stdout() { wget -qO- "$1"; }
else
    die "either curl or wget is required"
fi

[ "$(uname -s)" = Linux ] || die "this client is Linux-only"
case "$(uname -m)" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac

command -v systemctl >/dev/null 2>&1 ||
    die "systemd is required: the daemon runs as a systemd service"

if [ -z "$VERSION" ]; then
    VERSION=$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
    [ -n "$VERSION" ] || die "could not determine the latest release"
fi

NAME=varmlen-cli-linux-$ARCH
BASE=https://github.com/$REPO/releases/download/$VERSION

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "Downloading $NAME $VERSION…"
fetch "$BASE/$NAME.tar.gz" "$TMP/$NAME.tar.gz" || die "download failed"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || die "could not fetch checksums"

# Check the archive against the published checksum before anything is unpacked.
( cd "$TMP" && grep " $NAME.tar.gz\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1 ) ||
    die "checksum mismatch — refusing to install"
echo "Checksum verified."

tar -C "$TMP" -xzf "$TMP/$NAME.tar.gz"

sh "$TMP/$NAME/install.sh"

# A daemon that is up keeps answering from the files it started with, so the
# fresh client on disk says nothing about the code actually serving requests;
# the skew surfaces later as a command the old daemon has never heard of. If
# one is answering, let the client judge it: `varmlen-cli update` compares the
# version the daemon reports with its own, and reaches for sudo only when there
# is really something to replace. The socket is probed by name rather than with
# `varmlen-cli status` because that command would install a missing daemon, and
# an installer should not ask for a password to find out nothing is running.
BIN=${XDG_BIN_HOME:-$HOME/.local/bin}/varmlen-cli
if [ -x "$BIN" ] && [ -S "/run/varmlen/daemon-$(id -u).sock" ]; then
    echo
    "$BIN" update ||
        echo "Run \"$BIN update --yes\" to replace the daemon; that brings the tunnel down."
fi

cat <<'NEXT'

Next:
  varmlen-cli sub add <your subscription URL>
  varmlen-cli list
  varmlen-cli connect

The first command that needs the daemon installs it, which asks for sudo once:
the daemon manages routes and firewall rules, so it cannot run unprivileged.

The desktop client, if you also use it, starts its own daemon and only one may
own the network at a time — run one or the other.
NEXT
