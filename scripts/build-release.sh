#!/bin/sh
# Release build with build-machine paths kept out of the binaries.
#
# The remapped prefixes must be computed from the environment: hardcoding them
# in .cargo/config.toml only works on the machine they were written on, and
# silently stops matching everywhere else — which is the failure mode that
# leaks paths without anyone noticing.
set -eu

CARGO_DIR=${CARGO_HOME:-$HOME/.cargo}
RUSTUP_DIR=${RUSTUP_HOME:-$HOME/.rustup}

RUSTFLAGS="--remap-path-prefix=$CARGO_DIR=/cargo --remap-path-prefix=$RUSTUP_DIR=/rustup"
export RUSTFLAGS

cargo build --release "$@"

# Fail loudly rather than shipping a binary that names the build machine.
for binary in varmlen-cli varmlend varmlen-net; do
    path=target/release/$binary
    if strings "$path" | grep -qF "$CARGO_DIR"; then
        echo "$path still contains $CARGO_DIR" >&2
        exit 1
    fi
done
echo "release binaries carry no build paths"
