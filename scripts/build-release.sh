#!/bin/sh
# Release build: statically linked, and carrying no build-machine paths.
#
# musl rather than glibc, because a glibc binary refuses to start on any system
# whose glibc is older than the one it was built against — a build on Ubuntu
# 26.04 will not run on Debian 12 or RHEL 9, let alone Alpine. Static linking
# removes the question entirely: one binary, every distribution.
#
# The remapped prefixes are computed from the environment. Hardcoding them in
# .cargo/config.toml works only on the machine that file was written on and
# silently stops matching everywhere else, which is how paths leak unnoticed.
set -eu

ARCH=${ARCH:-$(uname -m)}
case "$ARCH" in
    x86_64)  TARGET=x86_64-unknown-linux-musl ;;
    aarch64) TARGET=aarch64-unknown-linux-musl ;;
    *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

CARGO_DIR=${CARGO_HOME:-$HOME/.cargo}
RUSTUP_DIR=${RUSTUP_HOME:-$HOME/.rustup}

rustup target add "$TARGET" >/dev/null 2>&1 || true

RUSTFLAGS="--remap-path-prefix=$CARGO_DIR=/cargo --remap-path-prefix=$RUSTUP_DIR=/rustup"
export RUSTFLAGS
# ring compiles C, so the musl target needs a C compiler for it.
export CC_x86_64_unknown_linux_musl=${CC_x86_64_unknown_linux_musl:-musl-gcc}
export CC_aarch64_unknown_linux_musl=${CC_aarch64_unknown_linux_musl:-aarch64-linux-musl-gcc}

cargo build --release --target "$TARGET" "$@"

OUT=target/$TARGET/release
for binary in varmlen-cli varmlend varmlen-net; do
    path=$OUT/$binary
    if strings "$path" | grep -qF "$CARGO_DIR"; then
        echo "$path still contains $CARGO_DIR" >&2
        exit 1
    fi
    case "$(file -b "$path")" in
        *"statically linked"*|*static-pie*) ;;
        *) echo "$path is not statically linked" >&2; exit 1 ;;
    esac
done
echo "$OUT: static, no build paths"
