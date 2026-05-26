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

    /// Reverse of [`Chain::chain_id`]: map an EIP-155 chain id back to a
    /// `Chain`, returning `None` for chains Kao doesn't support. Used by the
    /// WalletConnect dispatcher to translate CAIP-2 (`eip155:N`) into the
    /// internal enum before quoting/signing dApp transactions.
    pub fn from_chain_id(id: u64) -> Option<Chain> {
        match id {
            1 => Some(Chain::Mainnet),
            8453 => Some(Chain::Base),
            10 => Some(Chain::Optimism),
            _ => None,
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
            Chain::Mainnet => "https://ethereum-beacon-api.publicnode.com",
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
    fn display_name_distinct() {
        assert_eq!(Chain::Mainnet.display_name(), "Ethereum Mainnet");
        assert_eq!(Chain::Base.display_name(), "Base");
        assert_eq!(Chain::Optimism.display_name(), "OP Mainnet");
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
}
