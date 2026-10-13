# ♡o。+..:*♡o。+..:*♡o。+..:* Cute+Secure desktop wallet for Ethereum *:..+。o♡:..+。o♡*:..+。o♡

<img width="1899" height="1002" alt="image" src="https://github.com/user-attachments/assets/3eeb3027-728d-461c-a04f-82d9e7768108" />

## ִ ࣪𖤐 Supported chains ༉‧₊˚.

Kao uses [Helios light client](https://github.com/a16z/helios) for verification of RPC data, so the only supported chains are: `Ethereum Mainnet`, `Base` and `Optimism`.

## ⋆˚✿˖° No 3rd party APIs by default (*•̀ᴗ•́*)و

RPC (of your choice) is all you need; you can opt in to an Indexer for better token discovery and address history.

All the assets (like ERC-20 logos) and databases (like 4Bytes or ERC-7730 registry) are bundled during the build, not fetched in the runtime. Although this produces a slightly heavier app, it reduces the attack surface and is way more private.

Note: Apps use their APIs:

- CoW Swap -> api.cow.fi (getting a quote)
- Privacy Pools -> api.0xbow.io (loading pools, ASP feed)

## ( ˶˘ ³˘)♡ No phoning home ε=ε=ε=ε=ε=ε=┌(;￣◇￣)┘

Kao doesn't ship telemetry — neither opt-in nor opt-out. The only metric is GitHub stars (give us a star).

## -ˋˏ✄┈┈┈┈ Built in pure Rust™ (´×ω×`)

For too long we've been relying on slow and vulnerable JavaScript for building user-facing technologies. Kao changes that. No more npm supply chain attacks, no more 500MB Electron bundles, no more 1400-package dependency trees no one will ever audit.

# ‧₊˚♪ 𝄞₊˚⊹ Roadmap ▶︎ •၊၊||၊|။||||| 0:10

- [ ] WalletConnect
- [x] ERC-7730 clear signing support
- Kohaku-aligned integrations:
    - [ ] Stealth Addresses
    - [ ] Privacy Pools
    - [ ] Tornado Cash
    - [ ] Railgun
- [ ] optional Revoke Cash integration
- [x] CoW Swap integration
- [x] Tor support

# ⋆｡˚ ☁︎ Install ˚｡⋆ ( ˘▽˘)っ♨

## ♡ 1. Download a release (recommended)

From the [latest release](https://github.com/kaowallet/kao/releases/latest), grab
the installer for your platform plus `SHA256SUMS` and `SHA256SUMS.sigstore.json`:

| Platform                | File                                                           |
| ----------------------- | -------------------------------------------------------------- |
| macOS (Apple Silicon)   | `kao-vX.Y.Z-aarch64-apple-darwin.dmg`                          |
| Windows (x64)           | `kao-vX.Y.Z-x86_64-pc-windows-msvc-setup.exe`                  |
| Linux (x86_64, aarch64) | `kao-vX.Y.Z-<arch>-unknown-linux-gnu.AppImage`, `.deb` or `.flatpak` |

There's no Intel Mac build; use `cargo install` (option 2) there.

**Check the signature.** Releases are signed in CI with [cosign](https://github.com/sigstore/cosign)
keyless signing: the certificate binds the signature to this repo's `release.yml`
running on the release tag, and the signature is recorded in Sigstore's public
transparency log. Install cosign (`brew install cosign`, your distro's package, or
a binary from [its releases](https://github.com/sigstore/cosign/releases)), then:

```sh
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/kaowallet/kao/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

It must print `Verified OK`. Releases up to v0.2.3 have no `.sigstore.json`; for
those, swap the `--bundle` line for `--signature SHA256SUMS.sig --certificate SHA256SUMS.pem`
(cosign 2 or 3).

**Check the hash** of your download against the now-trusted `SHA256SUMS`. Your
file must show `OK`:

```sh
sha256sum --ignore-missing -c SHA256SUMS        # Linux
shasum -a 256 --ignore-missing -c SHA256SUMS    # macOS
```

On Windows, in PowerShell (prints `True` on a match):

```powershell
$f = "kao-vX.Y.Z-x86_64-pc-windows-msvc-setup.exe"
(Get-FileHash $f).Hash -eq (Select-String -Path SHA256SUMS -SimpleMatch -Pattern $f).Line.Split(" ")[0]
```

Every installer also has its own `.sigstore.json`, so you can verify it directly
the same way: `cosign verify-blob <file> --bundle <file>.sigstore.json …`.

Then install as usual: open the `.dmg`, run the `-setup.exe`,
`sudo apt install ./kao-….deb`, or `chmod +x` the AppImage and run it. On Linux,
Ledger and Trezor need the host's usual udev rules.

Windows builds aren't Authenticode-signed either, so SmartScreen may say
"Windows protected your PC": click **More info → Run anyway**.

### ⊹ ࣪ ˖ macOS: "Kao Wallet is damaged and can't be opened" ૮₍ ˶•⤙•˶ ₎ა

It's not damaged ♡ — our builds just aren't signed with an Apple Developer ID
(that requires a paid, KYC'd Apple account). macOS quarantines unsigned apps it
didn't download itself and shows that scary message. Once you've checked the
signature and hash above, clear the quarantine flag:

```sh
xattr -dr com.apple.quarantine "/Applications/Kao Wallet.app"
```

Then open it normally. (If it lives somewhere other than `/Applications`, point
the path at wherever you put it. Still complaining? `xattr -cr "/Applications/Kao Wallet.app"`
strips every extended attribute.)

## ♡ 2. Build from source with cargo

```sh
cargo install --locked --git https://github.com/kaowallet/kao kao
```

`--locked` builds against the committed `Cargo.lock`, the one `cargo vet` and
`cargo deny` audit; without it cargo re-resolves every dependency to its newest
version. Add `--tag vX.Y.Z` to build a release instead of `main`.

You need Rust 1.95 or newer (`rustup update stable`; `cargo install` uses your
default toolchain, not the repo's `rust-toolchain.toml`), a C compiler, `protoc`
and libclang:

```sh
sudo apt install build-essential protobuf-compiler libclang-dev        # Debian/Ubuntu
sudo dnf install gcc gcc-c++ make perl protobuf-compiler clang-devel   # Fedora
sudo pacman -S --needed base-devel protobuf clang                      # Arch
xcode-select --install && brew install protobuf                        # macOS
```

On Windows: Visual Studio Build Tools (C++ workload), LLVM, and `protoc` on `PATH`.

This puts only the `kao` binary in `~/.cargo/bin`, with no desktop entry or icon.
It shares wallet data with a release install on the same machine (but not with
the Flatpak).

## ♡ 3. Flatpak

Kao isn't on Flathub yet, so install the single-file bundle from a release
(verify it like any other download in option 1; it's in `SHA256SUMS`). It uses
the Freedesktop 26.08 runtime. Wallet files live in the sandbox at
`~/.var/app/com.kaowallet.kao/`, separate from a deb, AppImage or cargo install
(`~/.config/kao` and `~/.local/share/kao`).

```sh
flatpak remote-add --if-not-exists --user flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install --user ./kao-vX.Y.Z-x86_64-unknown-linux-gnu.flatpak
flatpak run com.kaowallet.kao
```

Ledger and Trezor need the host's usual udev rules. The bundle asks for USB
device nodes (`--device=usb`), which Flatpak 1.15.11 and newer honor. On the
Flatpak 1.14 shipped with Ubuntu 24.04 that permission is ignored; software
wallets still run, and `flatpak override --user --device=all com.kaowallet.kao`
opens the device nodes for hardware wallets.

Build a bundle from a Linux release binary with `./flatpak/build.sh target/release/kao dist`.
