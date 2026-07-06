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

# ⊹ ࣪ ˖ macOS: "Kao Wallet is damaged and can't be opened" ૮₍ ˶•⤙•˶ ₎ა

It's not damaged ♡ — our builds just aren't signed with an Apple Developer ID
(that requires a paid, KYC'd Apple account). macOS quarantines unsigned apps it
didn't download itself and shows that scary message. Clear the quarantine flag:

```sh
xattr -dr com.apple.quarantine "/Applications/Kao Wallet.app"
```

Then open it normally. (If it lives somewhere other than `/Applications`, point
the path at wherever you put it. Still complaining? `xattr -cr "/Applications/Kao Wallet.app"`
strips every extended attribute.)
