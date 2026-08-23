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

## Install

```sh
curl -fsSL https://aegisvpn.org/varmlen-cli-linux/install.sh | sh
sudo systemctl enable --now varmlend@$(id -u)
```

The installer verifies the release archive against the SHA-256 checksums
published with it before unpacking anything, and refuses to continue on a
mismatch. `VARMLEN_VERSION=v0.1.0` pins a specific release. x86_64 and aarch64
are built; systemd is required.

### From source

```sh
./scripts/build-release.sh
sudo ./packaging/install.sh
sudo systemctl enable --now varmlend@$(id -u)
```

## Use

```sh
varmlen-cli sub add https://example.com/subscription   # or: varmlen-cli add vless://…
varmlen-cli list
varmlen-cli connect 2                 # by number from `list`
varmlen-cli connect Finland           # or by name — a prefix is enough
varmlen-cli connect                   # reuses the last location connected to
varmlen-cli status
varmlen-cli disconnect
```

Everything after `connect` is taken as the location name, so names with spaces
need no quoting. Where a provider ships several locations under one name, `list`
numbers them and reports the endpoints to choose between.

Settings:

```sh
varmlen-cli set mode tun          # or: proxy
varmlen-cli set killswitch on
varmlen-cli set allow-lan off
varmlen-cli set mtu 1420          # 1280-1500
varmlen-cli set user-agent happ   # varmlen | happ | incy
varmlen-cli set emoji off         # for terminals that cannot draw emoji
varmlen-cli set                   # show every setting and what it accepts
```

`emoji off` is for VTE-based terminals (Ptyxis, GNOME Terminal), which do not
compose regional indicator pairs into flags whatever fonts are installed. A flag
names a country rather than decorating one, so it is turned back into its ISO
letters — `FI Finland | Helsinki` — instead of being dropped; other pictographs
are removed.

`user-agent` selects which client to present as when fetching a subscription.
Panels serve different payloads per client, so this changes what the provider
sends back, not how the tunnel itself looks on the wire.

Split tunnelling:

```sh
varmlen-cli split                              # show both lists
varmlen-cli split apps mode selective          # or: general
varmlen-cli split apps add firefox chromium
varmlen-cli split sites add "*.example.com"
varmlen-cli split sites remove example.com
varmlen-cli split apps clear
```

`selective` tunnels only what is listed; `general` tunnels everything except
what is listed. The two lists carry independent modes, and `split` prints which
way each one currently points.

A site is either an exact host (`example.com`) or a suffix covering its
subdomains (`*.example.com`). Since `*` is a glob the shell expands first, the
suffix form is also accepted as `.example.com`, which needs no quoting.

Latency:

```sh
varmlen-cli ping                  # the last location connected to
varmlen-cli ping Finland          # one location, by number or name
varmlen-cli ping AegisVPN         # everything in one subscription
varmlen-cli ping all              # every location
varmlen-cli ping all --tcp        # TCP handshake only: much faster, less telling
```

Probes run concurrently, so a sweep costs about as long as its slowest member
rather than the sum of every timeout. Results print in `list` order, so the
number beside one is the number to hand to `connect`.

The default probe goes through the proxy — the daemon starts a throwaway xray
on ports it reserves itself and times a real request, so the figure includes the
TLS handshake and the proxy's own latency. `--tcp` times only the handshake to
the endpoint, which says whether the host answers but nothing about the tunnel.
Neither touches the current connection.

Configuration lives in `~/.config/varmlen/cli.json` (`varmlen-cli config-path`).
It holds proxy credentials, so it is written `0600` in a `0700` directory.

Subscriptions are named and numbered rather than addressed by URL, and listings
print the host only:

```sh
varmlen-cli sub list
varmlen-cli sub update AegisVPN
varmlen-cli sub remove 2
```

A subscription URL's path *is* the account token — anyone holding it can pull
the account's servers — and terminal output gets screenshotted and pasted into
bug reports. `sub list --reveal` prints the full URLs when you actually need
them.

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

`scripts/build-release.sh` remaps `$CARGO_HOME` and `$RUSTUP_HOME` out of the
binaries and then asserts they are gone, failing the build rather than shipping
one that names the machine it was built on. The release profile strips symbols.

Without this, Rust embeds the absolute path of every dependency source file
(via `file!()` in panic machinery) into the binary, shipping the build user's
name and home layout along with an exact dependency inventory. Only those two
prefixes need remapping — Cargo compiles workspace members themselves through
relative paths, so the checkout location never reaches the binary.

The prefixes are computed from the environment on purpose. Hardcoding them in
`.cargo/config.toml` works only on the machine that file was written on and
silently stops matching anywhere else, which is precisely the failure that
leaks paths without anyone noticing. CI runs the same script.

```sh
strings target/release/varmlen-cli | grep -c "$USER"   # expect 0
```

## Licence

GPL-3.0-only, as the upstream desktop client. `daemon/` and `helper/` are
vendored from [Varmlen-Client-Linux](https://github.com/Vemloir/Varmlen-Client-Linux).
