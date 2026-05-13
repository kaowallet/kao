# ♡o。+..:*♡o。+..:*♡o。+..:* Cute+Secure desktop wallet for Ethereum *:..+。o♡:..+。o♡*:..+。o♡

## ִ ࣪𖤐 Supported chains ༉‧₊˚.

Kao uses [Helios light client](https://github.com/a16z/helios) for verification of RPC data, so the only supported chains are: `Ethereum mainnet`, `Base` and `Optimism`.

## ⋆˚✿˖° No 3rd party APIs by default (*•̀ᴗ•́*)و

RPC (of your choice) is all you need; you can opt in to an Indexer for better token discovery and address history.

All the assets (like ERC-20 logos) and databases (like 4Bytes or ERC-7730 registry) are bundled during the build, not fetched in the runtime. Although this produces a slightly heavier app, it reduces the attack surface and is way more private.

## ( ˶˘ ³˘)♡ No phoning home ε=ε=ε=ε=ε=ε=┌(;￣◇￣)┘

Kao doesn't ship telemetry — neither opt-in nor opt-out. The only metric is GitHub stars (give us a star).

## -ˋˏ✄┈┈┈┈ Built in pure Rust™ (´×ω×`)

For too long we've been relying on slow and vulnerable JavaScript for building user-facing technologies. Kao changes that. No more npm supply chain attacks, no more 500MB Electron bundles, no more 1400-package dependency trees no one will ever audit.

# ‧₊˚♪ 𝄞₊˚⊹ Roadmap ▶︎ •၊၊||၊|။||||| 0:10

- [ ] WalletConnect
- [ ] ERC-7730 clear signing support
- Kohaku-aligned integrations:
    - [ ] Stealth Addresses
    - [ ] Privacy Pools
    - [ ] Tornado Cash
    - [ ] Railgun
- [ ] optional Revoke Cash integration
- [ ] CoW Swap integration
- [ ] Tor support

