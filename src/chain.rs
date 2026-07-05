//! `Chain` is the small UI-side enum used by the RPC config screens to
//! label per-network inputs (Mainnet / Base / Optimism). It deliberately
//! does NOT touch `settings`, `net`, or any wallet plumbing — those layers
//! are still mainnet-only. The L2 entries are placeholders so the UI can
//! grow per-chain RPC fields ahead of the runtime catching up.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Chain {
    #[default]
    Mainnet,
    Base,
    Optimism,
}

impl Chain {
    pub const ALL: [Chain; 3] = [Chain::Mainnet, Chain::Base, Chain::Optimism];

    pub fn label(self) -> &'static str {
        match self {
            Chain::Mainnet => "Mainnet",
            Chain::Base => "Base",
            Chain::Optimism => "Optimism",
        }
    }

    /// EIP-155 chain id. Baked into the EIP-1559 signing hash, so picking the
    /// wrong one here means the broadcast hits a different network than the
    /// review screen claimed.
    pub fn chain_id(self) -> u64 {
        match self {
            Chain::Mainnet => 1,
            Chain::Base => 8453,
            Chain::Optimism => 10,
        }
    }

    /// Map an EIP-155 chain id back to a `Chain`. Inverse of
    /// [`Chain::chain_id`]. Returns `None` for ids Kao doesn't support —
    /// used to locate a `SafeDescriptor` (which stores a raw `chain_id`)
    /// on one of the three supported networks.
    pub fn from_chain_id(id: u64) -> Option<Chain> {
        Chain::ALL.into_iter().find(|c| c.chain_id() == id)
    }

    /// EIP-3770 short name used as the chain segment in Safe Transaction
    /// Service URLs (`https://api.safe.global/tx-service/{shortName}/…`).
    /// These are the registry short names, NOT `label()` lowercased —
    /// Optimism's is `oeth`, not `optimism`.
    pub fn safe_tx_service_shortname(self) -> &'static str {
        match self {
            Chain::Mainnet => "eth",
            Chain::Base => "base",
            Chain::Optimism => "oeth",
        }
    }

    /// Human-friendly network label for the review screen
    /// ("Ethereum Mainnet", "OP Mainnet", "Base"). Distinct from `label()`,
    /// which is the short navigation-row name.
    pub fn display_name(self) -> &'static str {
        match self {
            Chain::Mainnet => "Ethereum Mainnet",
            Chain::Base => "Base",
            Chain::Optimism => "OP Mainnet",
        }
    }

    /// Ticker of the chain's native gas coin. All three built-ins are ETH
    /// today (Base/OP settle in ETH). This is the *authoritative* symbol for a
    /// native (`contract: None`) balance/send row — an indexer's reported
    /// symbol for the native coin is untrusted and must never override it, or
    /// a hostile indexer could label a native-ETH transfer as some ERC-20 the
    /// user thinks they are sending (see `into_live_tokens`).
    pub fn native_symbol(self) -> &'static str {
        match self {
            Chain::Mainnet | Chain::Base | Chain::Optimism => "ETH",
        }
    }

    /// Full name of the chain's native gas coin. Companion to
    /// [`Chain::native_symbol`] — same chain-authoritative-not-indexer rule.
    pub fn native_name(self) -> &'static str {
        match self {
            Chain::Mainnet | Chain::Base | Chain::Optimism => "Ethereum",
        }
    }

    /// Pre-typed default execution-RPC URL shown in the Custom-RPC inputs.
    /// The Mainnet entry mirrors `settings::DEFAULT_RPCS[0]` so the Custom
    /// flow defaults to the same upstream as the "Use Defaults" path.
    pub fn default_exec_url(self) -> &'static str {
        match self {
            Chain::Mainnet => "https://eth.llamarpc.com",
            Chain::Base => "https://mainnet.base.org",
            Chain::Optimism => "https://mainnet.optimism.io",
        }
    }

    /// Pre-typed default consensus (beacon-chain LC) URL. The L2 endpoints
    /// are operationsolarstorm.org's L2 light-client beacon proxies.
    pub fn default_consensus_url(self) -> &'static str {
        match self {
            // ChainSafe's public Lodestar node. Switched away from
            // ethereum-beacon-api.publicnode.com, which is load-balanced across
            // backends that intermittently serve corrupt (out-of-order period)
            // `light_client/updates` responses — helios chokes on the bad entry
            // with `InvalidPeriod` and fails the whole sync. Lodestar served a
            // clean, in-order list on every probe.
            Chain::Mainnet => "https://lodestar-mainnet.chainsafe.io",
            Chain::Base => "https://base.operationsolarstorm.org",
            Chain::Optimism => "https://op-mainnet.operationsolarstorm.org",
        }
    }

    /// Whether the send flow runs local revm preflight on this chain.
    ///
    /// All three chains: send-flow txs (native ETH and ERC-20 `transfer`)
    /// touch no OP-stack-specific precompiles (`0x4200…0015` L1-fee
    /// oracle and friends) and no Prague-only opcodes, so a stock revm
    /// configured for `SpecId::PRAGUE` produces a correct revert reason,
    /// gas-used number, and `Transfer` log set on all three chains. The
    /// review screen surfaces the same UI shape for each.
    ///
    /// What this does NOT cover on L2:
    ///   - **L1 calldata fee.** OP-stack charges `L2 gas` + a separate
    ///     L1-data fee on top. The wallet's `eth_estimateGas` (used for
    ///     `eth_cost_wei`) already returns only L2 gas — the L1 gap
    ///     exists independently of sim. Tracked separately.
    ///   - **OP-specific precompiles.** A user-crafted tx that calls
    ///     `0x4200…` would simulate against an empty account here. The
    ///     send flow never does this, so the gap is theoretical for v1.
    pub fn supports_simulation(self) -> bool {
        // Every chain in Kao's list supports preflight today. Kept as a
        // method (rather than inlining `true`) so a future chain
        // addition that genuinely needs gating has an obvious hook.
        let _ = self;
        true
    }

    /// Canonical Blockscout instance for the chain. Used by the indexer
    /// layer to route per-chain portfolio/history queries when the user
    /// picks Blockscout — Blockscout runs as a separate deployment per
    /// chain, so we can't reuse one base URL across all of them.
    pub fn default_blockscout_url(self) -> &'static str {
        match self {
            Chain::Mainnet => "https://eth.blockscout.com",
            Chain::Base => "https://base.blockscout.com",
            Chain::Optimism => "https://optimism.blockscout.com",
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Identity of any network the wallet can show a balance for: one of the
/// three Helios-verified built-ins, or a user-defined custom network keyed by
/// its EIP-155 chain id.
///
/// This is an *additive* layer over [`Chain`] — `Chain` stays the closed,
/// Helios/Safe/indexer-coupled set, and only the "horizontal" surfaces that
/// must span both worlds (the portfolio rows, the send plan, balance/provider
/// routing) speak `NetworkId`. A `Custom` is always unverified and only ever
/// carries the native coin; the verified plumbing never receives one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkId {
    /// A Helios-verified built-in chain (Mainnet / Base / Optimism).
    Builtin(Chain),
    /// A user-defined custom network, identified by its EIP-155 chain id.
    /// Metadata (name, RPC, symbol) lives in `settings::custom_network`.
    Custom(u64),
}

impl NetworkId {
    /// EIP-155 chain id. For a custom network this is the id itself; for a
    /// built-in it delegates to [`Chain::chain_id`]. Baked into the signing
    /// hash on the send path, so it must be exact.
    pub fn chain_id(self) -> u64 {
        match self {
            NetworkId::Builtin(c) => c.chain_id(),
            NetworkId::Custom(id) => id,
        }
    }

    /// The built-in [`Chain`] this id refers to, or `None` for a custom
    /// network. Used to route to the verified provider/indexer path only when
    /// the network is one Helios actually supports.
    pub fn builtin(self) -> Option<Chain> {
        match self {
            NetworkId::Builtin(c) => Some(c),
            NetworkId::Custom(_) => None,
        }
    }

    /// Whether this is a user-defined custom (unverified) network.
    pub fn is_custom(self) -> bool {
        matches!(self, NetworkId::Custom(_))
    }

    /// Whether the send flow runs local revm preflight on this network.
    /// Custom networks skip it — preflight reads verified state through the
    /// Helios-aware path, which a custom RPC can't provide, and sim is only
    /// ever advisory.
    pub fn supports_simulation(self) -> bool {
        match self {
            NetworkId::Builtin(c) => c.supports_simulation(),
            NetworkId::Custom(_) => false,
        }
    }
}

impl From<Chain> for NetworkId {
    fn from(c: Chain) -> Self {
        NetworkId::Builtin(c)
    }
}

impl Default for NetworkId {
    fn default() -> Self {
        NetworkId::Builtin(Chain::Mainnet)
    }
}

/// Tiny owned per-chain map so screens can hold one value of `T` per chain
/// without dragging in a hashmap dependency. Order matches `Chain::ALL`.
#[derive(Debug, Default, Clone)]
pub struct PerChain<T> {
    pub mainnet: T,
    pub base: T,
    pub optimism: T,
}

impl<T> PerChain<T> {
    pub fn get(&self, chain: Chain) -> &T {
        match chain {
            Chain::Mainnet => &self.mainnet,
            Chain::Base => &self.base,
            Chain::Optimism => &self.optimism,
        }
    }

    pub fn set(&mut self, chain: Chain, value: T) {
        match chain {
            Chain::Mainnet => self.mainnet = value,
            Chain::Base => self.base = value,
            Chain::Optimism => self.optimism = value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_variants_listed() {
        assert_eq!(Chain::ALL.len(), 3);
        assert!(Chain::ALL.contains(&Chain::Mainnet));
        assert!(Chain::ALL.contains(&Chain::Base));
        assert!(Chain::ALL.contains(&Chain::Optimism));
    }

    #[test]
    fn label_distinct_per_chain() {
        let labels: Vec<_> = Chain::ALL.iter().map(|c| c.label()).collect();
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len());
        assert_eq!(Chain::Mainnet.label(), "Mainnet");
        assert_eq!(Chain::Base.label(), "Base");
        assert_eq!(Chain::Optimism.label(), "Optimism");
    }

    #[test]
    fn chain_id_eip155() {
        assert_eq!(Chain::Mainnet.chain_id(), 1);
        assert_eq!(Chain::Base.chain_id(), 8453);
        assert_eq!(Chain::Optimism.chain_id(), 10);
    }

    #[test]
    fn from_chain_id_round_trips() {
        for c in Chain::ALL {
            assert_eq!(Chain::from_chain_id(c.chain_id()), Some(c));
        }
        assert_eq!(Chain::from_chain_id(42161), None); // Arbitrum: unsupported
        assert_eq!(Chain::from_chain_id(0), None);
    }

    #[test]
    fn safe_tx_service_shortnames() {
        // EIP-3770 registry short names — Optimism is `oeth`, a common
        // foot-gun if derived from the label instead.
        assert_eq!(Chain::Mainnet.safe_tx_service_shortname(), "eth");
        assert_eq!(Chain::Base.safe_tx_service_shortname(), "base");
        assert_eq!(Chain::Optimism.safe_tx_service_shortname(), "oeth");
    }

    #[test]
    fn display_name_distinct() {
        assert_eq!(Chain::Mainnet.display_name(), "Ethereum Mainnet");
        assert_eq!(Chain::Base.display_name(), "Base");
        assert_eq!(Chain::Optimism.display_name(), "OP Mainnet");
    }

    #[test]
    fn native_currency_is_eth_on_every_chain() {
        for c in Chain::ALL {
            assert_eq!(c.native_symbol(), "ETH");
            assert_eq!(c.native_name(), "Ethereum");
        }
    }

    #[test]
    fn default_exec_urls_https_and_distinct() {
        for c in Chain::ALL {
            assert!(c.default_exec_url().starts_with("https://"));
        }
        let urls: std::collections::HashSet<_> =
            Chain::ALL.iter().map(|c| c.default_exec_url()).collect();
        assert_eq!(urls.len(), 3);
    }

    #[test]
    fn default_consensus_urls_https_and_distinct() {
        for c in Chain::ALL {
            assert!(c.default_consensus_url().starts_with("https://"));
        }
        let urls: std::collections::HashSet<_> = Chain::ALL
            .iter()
            .map(|c| c.default_consensus_url())
            .collect();
        assert_eq!(urls.len(), 3);
    }

    #[test]
    fn default_blockscout_urls_per_chain() {
        assert_eq!(
            Chain::Mainnet.default_blockscout_url(),
            "https://eth.blockscout.com"
        );
        assert_eq!(
            Chain::Base.default_blockscout_url(),
            "https://base.blockscout.com"
        );
        assert_eq!(
            Chain::Optimism.default_blockscout_url(),
            "https://optimism.blockscout.com"
        );
    }

    #[test]
    fn supports_simulation_all_chains() {
        for c in Chain::ALL {
            assert!(c.supports_simulation());
        }
    }

    #[test]
    fn display_matches_label() {
        for c in Chain::ALL {
            assert_eq!(format!("{c}"), c.label());
        }
    }

    #[test]
    fn default_chain_is_mainnet() {
        assert_eq!(Chain::default(), Chain::Mainnet);
    }

    #[test]
    fn perchain_get_set_round_trip() {
        let mut p: PerChain<u32> = PerChain::default();
        for (i, c) in Chain::ALL.iter().enumerate() {
            p.set(*c, i as u32);
        }
        for (i, c) in Chain::ALL.iter().enumerate() {
            assert_eq!(*p.get(*c), i as u32);
        }
    }

    #[test]
    fn network_id_chain_id_matches_source() {
        for c in Chain::ALL {
            assert_eq!(NetworkId::Builtin(c).chain_id(), c.chain_id());
        }
        assert_eq!(NetworkId::Custom(11155111).chain_id(), 11155111);
    }

    #[test]
    fn network_id_builtin_and_is_custom() {
        let b: NetworkId = Chain::Base.into();
        assert_eq!(b.builtin(), Some(Chain::Base));
        assert!(!b.is_custom());

        let c = NetworkId::Custom(31337);
        assert_eq!(c.builtin(), None);
        assert!(c.is_custom());
    }

    #[test]
    fn network_id_custom_never_simulates() {
        // Built-ins follow their own rule; custom networks always skip sim.
        assert!(!NetworkId::Custom(11155111).supports_simulation());
        for c in Chain::ALL {
            assert_eq!(
                NetworkId::Builtin(c).supports_simulation(),
                c.supports_simulation()
            );
        }
    }

    #[test]
    fn network_id_default_is_mainnet() {
        assert_eq!(NetworkId::default(), NetworkId::Builtin(Chain::Mainnet));
    }
}
