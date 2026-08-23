# Varmlen CLI (Linux)

A headless client for the Varmlen xray daemon.

It speaks the same unix-socket protocol to the same `varmlend` daemon as the
desktop client, and builds its xray configuration with the same code, so the two
cannot drift apart in what they ask the daemon to do. The difference is what is
missing: no GUI, no WebKit, no X11.

On a GNOME/Wayland desktop, dropping the graphical client removes the Tauri
window, both WebKit processes, and — because the GUI is an X11 client — the
`Xwayland`, `mutter-x11-frames` and `ibus-x11` processes that exist only to
serve it. Measured on one machine: **~345 MB of resident memory**.

## Layout

| Crate | What it is |
|---|---|
| `core` | Subscription parsing and fetching, split-tunnel rules, xray config generation, daemon protocol client. Extracted from the desktop client's Tauri crate; must stay GUI-free. |
| `daemon` | `varmlend`, the privileged networking daemon. Vendored from the desktop client. |
| `helper` | `varmlen-net`, the root-invoked network transaction helper. Vendored. |
| `cli` | `varmlen-cli`, this client. |

## Build and install

```sh
cargo build --release
sudo ./packaging/install.sh
sudo systemctl enable --now varmlend@$(id -u)
```

## Use

```sh
varmlen-cli sub add https://example.com/subscription   # or: varmlen-cli add vless://…
varmlen-cli list
varmlen-cli use "Netherlands 01"
varmlen-cli connect
varmlen-cli status
varmlen-cli disconnect
```

Settings:

```sh
varmlen-cli set mode tun          # or: proxy
varmlen-cli set killswitch on
varmlen-cli set allow-lan off
```

Configuration lives in `~/.config/varmlen/cli.json` (`varmlen-cli config-path`).
It holds proxy credentials, so it is written `0600` in a `0700` directory.

## Notes

**The daemon does not start itself.** The desktop client launches it through
`pkexec`, which needs a polkit authentication agent bound to a graphical
session. A headless system has none, so the daemon runs under systemd instead
and takes the desktop owner's uid as `--owner-uid`. That value was never a trust
token — the daemon is not linked against polkit and performs no authorization
with it; it only tells the daemon whose socket to create.

**One daemon at a time.** `varmlend` holds an exclusive lock on
`/run/varmlen/daemon.lock`. Running the systemd unit while the desktop client's
own daemon is up will fail with `another Varmlen daemon already owns the
network`. Use one or the other.

**Stopping is not the same as killing.** The daemon disconnects on `SIGTERM`, so
`systemctl stop` removes the tunnel's routes, rules and nftables state before
exiting. A `SIGKILL` skips that, and the machine is then left with the tunnel's
routes installed and no working default route until the daemon runs again — its
startup cleanup is what repairs that state.

## Build hygiene

`.cargo/config.toml` remaps `~/.cargo` and `~/.rustup` out of compiled binaries,
and the release profile strips symbols. Without this, Rust embeds the absolute
path of every dependency source file (via `file!()` in panic machinery) into the
binary, which ships the build user's name and home layout, along with an exact
dependency inventory.

Only those two prefixes need remapping: Cargo compiles workspace members
themselves through relative paths, so the checkout location never reaches the
binary and must not be hardcoded here. Verify with:

```sh
strings target/release/varmlen-cli | grep -c "$USER"   # expect 0
```

## Licence

GPL-3.0-only, as the upstream desktop client. `daemon/` and `helper/` are
vendored from [Varmlen-Client-Linux](https://github.com/Vemloir/Varmlen-Client-Linux).
