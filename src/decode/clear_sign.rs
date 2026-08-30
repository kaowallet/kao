//! ERC-7730 descriptor-based clear signing. Tries curated JSON
//! descriptors first (via `clear_signing::BundledRegistrySource`);
//! falls back to the existing heuristic pipeline when no descriptor
//! matches.
//!
//! The `KaoDataProvider` bridges Kao's Helios-verified RPC layer into
//! the `clear_signing::DataProvider` trait, so token metadata and ENS
//! reverse lookups go through the same verified path the heuristic
//! pipeline already uses.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use alloy::primitives::{Address, Bytes, U256};
use tracing::{debug, info, trace, warn};

use clear_signing::{
    BundledRegistrySource, DataProvider, DisplayModel, FormatDiagnostic, FormatOutcome,
    ResolvedDescriptorResolution, TokenMeta, TransactionContext, format_calldata,
    resolve_descriptors_for_tx,
};

use crate::chain::Chain;
use crate::decode::proxy;
use crate::decode::render::{
    DecodedCall, ResolutionState, Warning, decode_args_inner, decode_call, read_token_meta,
    unaccounted_calldata,
};
use crate::net::BalanceFetcher;

// ---------------------------------------------------------------------------
// Data provider

/// Bridges Kao's Helios-verified network layer into the `clear_signing`
/// crate's `DataProvider` trait. Token metadata goes through verified
/// `eth_call`; ENS goes through forward-verified reverse resolution.
/// Local names (contacts + own accounts) are resolved from a pre-built
/// snapshot so no locking happens on the async path.
pub struct KaoDataProvider<'a> {
    net: &'a dyn BalanceFetcher,
    chain: Chain,
    all_verified: Arc<AtomicBool>,
    /// Snapshot of contacts + own account names, keyed by address.
    /// Built once at task-spawn time so the async decode doesn't need
    /// the `RwLock<ContactsBook>`.
    local_names: HashMap<Address, String>,
}

impl<'a> KaoDataProvider<'a> {
    pub fn new(
        net: &'a dyn BalanceFetcher,
        chain: Chain,
        local_names: HashMap<Address, String>,
    ) -> Self {
        Self {
            net,
            chain,
            all_verified: Arc::new(AtomicBool::new(true)),
            local_names,
        }
    }

    pub fn all_verified(&self) -> bool {
        self.all_verified.load(Ordering::Relaxed)
    }
}

impl DataProvider for KaoDataProvider<'_> {
    fn resolve_token(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Pin<Box<dyn Future<Output = Option<TokenMeta>> + Send + '_>> {
        let address = address.to_string();
        Box::pin(async move {
            let Some(chain) = Chain::from_chain_id(chain_id) else {
                debug!(
                    chain_id,
                    address, "clear-sign: resolve_token: unsupported lookup chain"
                );
                return None;
            };
            let addr: Address = match address.parse() {
                Ok(a) => a,
                Err(_) => {
                    debug!(address, "clear-sign: resolve_token: bad address");
                    return None;
                }
            };
            match read_token_meta(self.net, chain, addr).await {
                Some((info, verified)) => {
                    if !verified {
                        self.all_verified.store(false, Ordering::Relaxed);
                    }
                    debug!(
                        symbol = %info.symbol,
                        decimals = info.decimals,
                        verified,
                        lookup_chain = ?chain,
                        %addr,
                        "clear-sign: resolved token metadata"
                    );
                    Some(TokenMeta {
                        symbol: info.symbol.clone(),
                        decimals: info.decimals,
                        name: info.symbol,
                    })
                }
                None => {
                    trace!(%addr, "clear-sign: no token metadata for address");
                    None
                }
            }
        })
    }

    fn resolve_local_name(
        &self,
        address: &str,
        _chain_id: u64,
        _types: Option<&[String]>,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        let hit = address
            .parse::<Address>()
            .ok()
            .and_then(|addr| self.local_names.get(&addr).cloned());
        match &hit {
            Some(name) => debug!(address, %name, "clear-sign: resolved local name"),
            None => debug!(
                address,
                known = self.local_names.len(),
                "clear-sign: no local name"
            ),
        }
        Box::pin(async move { hit })
    }

    fn resolve_ens_name(
        &self,
        address: &str,
        _chain_id: u64,
        _types: Option<&[String]>,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        // Reverse ENS only on Mainnet — reverse records live there.
        if !matches!(self.chain, Chain::Mainnet) {
            trace!(address, chain = ?self.chain, "clear-sign: skipping ENS (non-mainnet)");
            return Box::pin(async { None });
        }
        let address = address.to_string();
        Box::pin(async move {
            let addr: Address = match address.parse() {
                Ok(a) => a,
                Err(_) => {
                    debug!(address, "clear-sign: resolve_ens_name: bad address");
                    return None;
                }
            };
            // Verified (Helios, mainnet-only) reverse lookup across ENS / GNS /
            // WNS — an unverified read fails closed inside `lookup_address`, so
            // a hostile RPC can't fabricate a name on the clear-signing review
            // surface.
            match crate::names::lookup_address(self.net, addr).await {
                Ok(Some(name)) => {
                    debug!(%addr, %name, "clear-sign: resolved ENS name");
                    Some(name)
                }
                Ok(None) => {
                    trace!(%addr, "clear-sign: no ENS reverse record");
                    None
                }
                Err(e) => {
                    debug!(%addr, error = %e, "clear-sign: ENS lookup failed");
                    None
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Decode result

/// Union of ERC-7730 clear-signing and heuristic decode results.
/// The function panel dispatches on this to pick the right renderer.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum DecodeResult {
    /// ERC-7730 descriptor matched. Intent + labeled entries.
    ClearSigned {
        model: DisplayModel,
        diagnostics: Vec<FormatDiagnostic>,
        proxy_hops: Vec<Address>,
        all_verified: bool,
        /// Mechanical cross-checks on the raw bytes, independent of anything
        /// the descriptor claims (see [`bytes_warnings`]).
        ///
        /// A descriptor renders the fields it was authored to render; it does
        /// not attest that the calldata contains nothing else. This is the only
        /// thing on the clear-signed path that reads the bytes rather than the
        /// authored view of them, which matters most here precisely because
        /// this is the variant the review presents with the most confidence —
        /// destination, value and the whole function panel fold away behind
        /// *Show details* when a descriptor matched.
        warnings: Vec<Warning>,
    },
    /// Descriptor returned Fallback (partial match). Show DisplayModel
    /// but carry heuristic decode for cross-reference.
    Fallback {
        model: DisplayModel,
        reason: clear_signing::FallbackReason,
        diagnostics: Vec<FormatDiagnostic>,
        all_verified: bool,
        heuristic: DecodedCall,
    },
    /// No descriptor or format failure. Existing heuristic pipeline.
    Heuristic(DecodedCall),
    /// Native ETH transfer -- no calldata.
    Empty,
}

/// The one line that says what a transaction *does*, lifted out of whichever
/// decode produced it: the ERC-7730 intent when a descriptor matched, the
/// resolved function name otherwise.
///
/// This is the top of the review's information hierarchy — *what it does* →
/// *who it touches* → *the exact bytes* — so it is rendered by the caller
/// above the destination rows, not buried inside the calldata panel. Every
/// signing surface reads it from here so the same call can't headline
/// differently in two places.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headline {
    pub text: String,
    /// Where the name came from, when that qualifies it — "decoded from
    /// bytecode · no name" for a types-only resolve, "unverified call" when
    /// nothing resolved the selector at all.
    pub note: Option<String>,
    /// The call lands on a proxy and was decoded through its implementation.
    pub via_proxy: bool,
    /// Why the headline can't be taken at face value, if it can't: an on-chain
    /// read fell back to unverified RPC, or the selector matched several
    /// signatures so the name is a guess. Callers mute the line and render this
    /// alongside it — never behind a toggle, since it qualifies the one thing
    /// that is always on screen.
    pub caution: Option<String>,
    /// A descriptor matched, so the headline is an authored intent rather than
    /// a decoded function name. Reviews collapse their mechanical detail behind
    /// a toggle in this case — the intent already says what the call does.
    pub clear_signed: bool,
}

/// Shown when interpolated names/amounts came from an RPC Helios couldn't
/// verify — the values in the headline may be attacker-chosen.
const UNVERIFIED_READS: &str =
    "⚠ Some on-chain reads fell back to unverified RPC — names and amounts may be spoofed.";

impl DecodeResult {
    /// The headline for this decode, or `None` for a bare value transfer (no
    /// calldata) or a decode that resolved nothing nameable.
    pub fn headline(&self) -> Option<Headline> {
        match self {
            Self::ClearSigned {
                model,
                proxy_hops,
                all_verified,
                ..
            } => Some(Headline {
                text: model
                    .interpolated_intent
                    .as_deref()
                    .unwrap_or(&model.intent)
                    .to_string(),
                note: None,
                via_proxy: !proxy_hops.is_empty(),
                caution: (!all_verified).then(|| UNVERIFIED_READS.to_string()),
                clear_signed: true,
            }),
            Self::Fallback {
                model,
                all_verified,
                heuristic,
                ..
            } => Some(Headline {
                text: model
                    .interpolated_intent
                    .as_deref()
                    .unwrap_or(&model.intent)
                    .to_string(),
                note: None,
                via_proxy: !heuristic.proxy_hops.is_empty(),
                // A partial descriptor match is only as trustworthy as the
                // heuristic it was cross-referenced against.
                caution: (!(*all_verified && heuristic.all_verified))
                    .then(|| UNVERIFIED_READS.to_string()),
                clear_signed: true,
            }),
            Self::Heuristic(d) => {
                if matches!(d.state, ResolutionState::Empty) {
                    return None;
                }
                let text = match &d.function_name {
                    Some(name) => format!("{name}(…)"),
                    // Nothing resolved the selector — the raw 4 bytes are the
                    // most honest headline available.
                    None => format!(
                        "0x{:02x}{:02x}{:02x}{:02x}",
                        d.selector[0], d.selector[1], d.selector[2], d.selector[3]
                    ),
                };
                // Provenance the old panel header carried as a subtitle; it
                // qualifies the name, so it travels with it.
                let note = match d.state {
                    ResolutionState::TypesOnly => Some("decoded from bytecode · no name".into()),
                    ResolutionState::Unknown => Some("unverified call".into()),
                    // Ambiguous is spelled out by its own warning strip in the
                    // panel below — a duplicate note would split attention.
                    _ => None,
                };
                let caution = if !d.all_verified {
                    Some(UNVERIFIED_READS.to_string())
                } else if matches!(d.state, ResolutionState::Ambiguous) {
                    Some(
                        "⚠ Several functions share this selector — the name below is a guess."
                            .to_string(),
                    )
                } else {
                    None
                };
                Some(Headline {
                    text,
                    note,
                    via_proxy: !d.proxy_hops.is_empty(),
                    caution,
                    // No descriptor: the user gets the full decode, unfolded.
                    clear_signed: false,
                })
            }
            Self::Empty => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Orchestrator

/// Top-level decode entry point. Tries ERC-7730 descriptors first, then
/// falls back to the heuristic pipeline.
pub async fn decode_transaction(
    net: &dyn BalanceFetcher,
    chain: Chain,
    from: Address,
    to: Address,
    calldata: Bytes,
    value: U256,
    local_names: HashMap<Address, String>,
) -> DecodeResult {
    if calldata.is_empty() {
        debug!(%to, "clear-sign: empty calldata, native transfer");
        return DecodeResult::Empty;
    }

    let selector = if calldata.len() >= 4 {
        format!(
            "0x{:02x}{:02x}{:02x}{:02x}",
            calldata[0], calldata[1], calldata[2], calldata[3]
        )
    } else {
        format!("0x{}", alloy::hex::encode(&calldata))
    };

    info!(
        %to,
        %from,
        %selector,
        calldata_len = calldata.len(),
        chain = ?chain,
        local_names = local_names.len(),
        "clear-sign: decoding transaction"
    );

    // Walk the proxy chain so we can pass the implementation address to
    // the descriptor resolver. The heuristic path re-walks this (cheap,
    // cached in Helios); keeping it self-contained simplifies the
    // fallback.
    let resolved = proxy::resolve_implementation(net, chain, to).await;
    let impl_addr = resolved.implementation;
    let proxy_hops = resolved.hops.clone();
    let all_verified = resolved.all_verified;

    if !proxy_hops.is_empty() {
        debug!(
            %to,
            %impl_addr,
            hops = proxy_hops.len(),
            all_verified,
            "clear-sign: proxy resolved"
        );
    }

    // Build the descriptor-resolver context.
    let to_str = format!("{to:#x}");
    let from_str = format!("{from:#x}");
    let impl_str = format!("{impl_addr:#x}");
    let value_bytes = value.to_be_bytes::<32>();

    let tx_ctx = TransactionContext {
        chain_id: chain.chain_id(),
        to: &to_str,
        calldata: &calldata,
        value: if value.is_zero() {
            None
        } else {
            Some(&value_bytes[..])
        },
        from: Some(&from_str),
        implementation_address: if impl_addr != to {
            Some(&impl_str)
        } else {
            None
        },
    };

    let data_provider = KaoDataProvider::new(net, chain, local_names);

    // Try the bundled registry.
    match BundledRegistrySource::new() {
        Ok(source) => {
            debug!("clear-sign: bundled registry loaded");
            match resolve_descriptors_for_tx(&tx_ctx, &source, Some(&data_provider)).await {
                Ok(ResolvedDescriptorResolution::Found(descriptors)) => {
                    info!(
                        count = descriptors.len(),
                        %selector,
                        "clear-sign: descriptor(s) found"
                    );
                    match format_calldata(&descriptors, &tx_ctx, &data_provider).await {
                        Ok(FormatOutcome::ClearSigned { model, diagnostics }) => {
                            info!(
                                intent = %model.intent,
                                entries = model.entries.len(),
                                diagnostics = diagnostics.len(),
                                "clear-sign: clear-signed result"
                            );
                            // Read the bytes, not the authored view of them.
                            // Pure and local — no second network round-trip on
                            // what is the common, good path.
                            let warnings = bytes_warnings(&descriptors, &calldata);
                            return DecodeResult::ClearSigned {
                                model,
                                diagnostics,
                                proxy_hops,
                                all_verified: all_verified && data_provider.all_verified(),
                                warnings,
                            };
                        }
                        Ok(FormatOutcome::Fallback {
                            model,
                            reason,
                            diagnostics,
                        }) => {
                            info!(
                                intent = %model.intent,
                                reason = ?reason,
                                diagnostics = diagnostics.len(),
                                "clear-sign: fallback result, running heuristic too"
                            );
                            let heuristic = decode_call(net, chain, to, calldata).await;
                            return DecodeResult::Fallback {
                                model,
                                reason,
                                diagnostics,
                                all_verified: all_verified && data_provider.all_verified(),
                                heuristic,
                            };
                        }
                        Err(e) => {
                            warn!(
                                error = ?e,
                                %selector,
                                "clear-sign: format_calldata failed, falling back to heuristic"
                            );
                        }
                    }
                }
                Ok(ResolvedDescriptorResolution::NotFound) => {
                    debug!(%selector, %to, "clear-sign: no descriptor found");
                }
                Err(e) => {
                    warn!(
                        error = ?e,
                        %selector,
                        "clear-sign: descriptor resolution error"
                    );
                }
            }
        }
        Err(e) => {
            warn!(error = ?e, "clear-sign: failed to load bundled registry");
        }
    }

    // Heuristic fallback.
    debug!(%selector, "clear-sign: using heuristic pipeline");
    let decoded = decode_call(net, chain, to, calldata).await;
    DecodeResult::Heuristic(decoded)
}

/// The ERC-7730 `display.formats` key that describes `selector`, if the
/// resolved descriptors carry one.
///
/// Keys are function signatures (`"transfer(address,uint256)"`); the spec also
/// permits a bare `"0x…"` selector, which carries no argument types and so is
/// no use here. Matching on the selector rather than taking the first format is
/// what makes this the format that was actually rendered: a descriptor may
/// describe many functions, and the transaction names exactly one.
fn matched_signature(
    descriptors: &[clear_signing::ResolvedDescriptor],
    selector: [u8; 4],
) -> Option<&str> {
    descriptors
        .iter()
        .flat_map(|d| d.descriptor.display.formats.keys())
        .map(String::as_str)
        .find(|key| {
            !key.starts_with("0x") && alloy::primitives::keccak256(key.as_bytes())[..4] == selector
        })
}

/// Mechanical checks on the raw calldata, run alongside a descriptor rather
/// than in place of it.
///
/// Only one check today, and it is the one a descriptor structurally cannot
/// make: **does the calldata carry bytes the rendered arguments don't
/// explain?** Both decoders in play are non-consuming — alloy's reads the types
/// it was asked for, and `clear_signing`'s walks `head_size()` per parameter
/// without ever comparing the total against `data.len()` — so a call can render
/// a complete, authored, entirely truthful set of fields and still carry a tail
/// that reaches the contract. An ERC-2771 forwarder takes the spoofed sender
/// from exactly that tail.
///
/// The composer refuses such a call outright (`txbuilder::encode::decode_args`)
/// because it is producing the bytes that get signed. Here the bytes already
/// exist and the user is being asked to vet them, so it is surfaced as a
/// warning beside a decode still worth reading — the same trade the heuristic
/// path already makes.
///
/// Returns nothing when the signature can't be recovered or its types don't
/// parse: an unprovable claim is not a finding, and a false alarm on the
/// wallet's most-trusted screen is worse than silence.
fn bytes_warnings(
    descriptors: &[clear_signing::ResolvedDescriptor],
    calldata: &[u8],
) -> Vec<Warning> {
    // Derived here rather than taken as an argument so the slicing below can
    // never be reached with calldata too short to hold a selector.
    let Some(selector) = calldata.get(..4).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
        return Vec::new();
    };
    let Some(sig) = matched_signature(descriptors, selector) else {
        return Vec::new();
    };
    let Some(arg_types) = crate::decode::matcher::parse_signature_args(sig) else {
        return Vec::new();
    };
    let body = &calldata[4..];
    let values = decode_args_inner(&arg_types, body);
    match unaccounted_calldata(&values, body) {
        Some((decoded, total)) => {
            warn!(
                %sig,
                decoded,
                total,
                "clear-sign: descriptor rendered a call with unaccounted calldata"
            );
            vec![Warning::UnaccountedCalldata { decoded, total }]
        }
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{BalanceFetcher, LatestBlock, VerificationStatus, VerifiedRead};
    use alloy::network::Ethereum;
    use alloy::providers::RootProvider;
    use async_trait::async_trait;
    use clear_signing::DataProvider;
    use std::sync::Mutex;

    fn abi_encode_string(s: &str) -> Bytes {
        let mut buf = Vec::with_capacity(64 + s.len().next_multiple_of(32));
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        buf.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[24..32].copy_from_slice(&(s.len() as u64).to_be_bytes());
        buf.extend_from_slice(&len);
        buf.extend_from_slice(s.as_bytes());
        let pad = (32 - (s.len() % 32)) % 32;
        buf.extend(std::iter::repeat_n(0u8, pad));
        Bytes::from(buf)
    }

    fn abi_encode_uint8(v: u8) -> Bytes {
        let mut buf = [0u8; 32];
        buf[31] = v;
        Bytes::from(buf.to_vec())
    }

    #[derive(Debug)]
    struct TokenMetaMock {
        calls: Mutex<Vec<Chain>>,
        verified: bool,
    }

    impl TokenMetaMock {
        fn new(verified: bool) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                verified,
            }
        }
        fn called_chains(&self) -> Vec<Chain> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl BalanceFetcher for TokenMetaMock {
        async fn balance(&self, _: Address, _: Chain) -> Result<String, String> {
            Ok("0".into())
        }
        async fn invalidate(&self) {}
        fn last_status(&self, _: Chain) -> VerificationStatus {
            VerificationStatus::Verified
        }
        async fn provider(&self, _: Chain) -> Option<RootProvider<Ethereum>> {
            None
        }
        async fn get_code(&self, _: Address, _: Chain) -> Result<VerifiedRead<Bytes>, String> {
            Ok(VerifiedRead {
                value: Bytes::new(),
                verified: true,
            })
        }
        async fn get_storage_at(
            &self,
            _: Address,
            _: U256,
            _: Chain,
        ) -> Result<VerifiedRead<alloy::primitives::B256>, String> {
            Ok(VerifiedRead {
                value: alloy::primitives::B256::ZERO,
                verified: true,
            })
        }
        async fn call(
            &self,
            _: Address,
            data: Bytes,
            chain: Chain,
        ) -> Result<VerifiedRead<Bytes>, String> {
            self.calls.lock().unwrap().push(chain);
            let value = match data.as_ref() {
                [0x95, 0xd8, 0x9b, 0x41] => abi_encode_string("TOK"),
                [0x31, 0x3c, 0xe5, 0x67] => abi_encode_uint8(18),
                _ => Bytes::new(),
            };
            Ok(VerifiedRead {
                value,
                verified: self.verified,
            })
        }
        async fn get_balance_raw(
            &self,
            _: Address,
            _: Chain,
        ) -> Result<VerifiedRead<U256>, String> {
            Ok(VerifiedRead {
                value: U256::ZERO,
                verified: true,
            })
        }
        async fn get_transaction_count(
            &self,
            _: Address,
            _: Chain,
        ) -> Result<VerifiedRead<u64>, String> {
            Ok(VerifiedRead {
                value: 0,
                verified: true,
            })
        }
        async fn latest_block(&self, _: Chain) -> Result<VerifiedRead<LatestBlock>, String> {
            Ok(VerifiedRead {
                value: LatestBlock {
                    number: 0,
                    hash: alloy::primitives::B256::ZERO,
                    timestamp: 0,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: 0,
                    prevrandao: alloy::primitives::B256::ZERO,
                    beneficiary: Address::ZERO,
                    excess_blob_gas: None,
                },
                verified: true,
            })
        }
        async fn get_code_raw(
            &self,
            addr: Address,
            chain: Chain,
        ) -> Result<VerifiedRead<Bytes>, String> {
            self.get_code(addr, chain).await
        }
        async fn get_storage_at_raw(
            &self,
            addr: Address,
            slot: U256,
            chain: Chain,
        ) -> Result<VerifiedRead<alloy::primitives::B256>, String> {
            self.get_storage_at(addr, slot, chain).await
        }
        async fn call_raw(
            &self,
            to: Address,
            data: Bytes,
            chain: Chain,
        ) -> Result<VerifiedRead<Bytes>, String> {
            self.call(to, data, chain).await
        }
    }

    #[tokio::test]
    async fn resolve_token_honors_descriptor_selected_chain_id() {
        let net = TokenMetaMock::new(true);
        let provider = KaoDataProvider::new(&net, Chain::Mainnet, HashMap::new());
        let token = Address::repeat_byte(0x22).to_checksum(None);

        let meta = provider
            .resolve_token(Chain::Base.chain_id(), &token)
            .await
            .expect("token metadata");

        assert_eq!(meta.symbol, "TOK");
        assert_eq!(meta.decimals, 18);
        assert_eq!(net.called_chains(), vec![Chain::Base, Chain::Base]);
        assert!(provider.all_verified());
    }

    #[tokio::test]
    async fn resolve_token_marks_unverified_metadata() {
        let net = TokenMetaMock::new(false);
        let provider = KaoDataProvider::new(&net, Chain::Mainnet, HashMap::new());
        let token = Address::repeat_byte(0x33).to_checksum(None);

        let meta = provider
            .resolve_token(Chain::Mainnet.chain_id(), &token)
            .await
            .expect("token metadata");

        assert_eq!(meta.symbol, "TOK");
        assert!(!provider.all_verified());
    }

    #[tokio::test]
    async fn resolve_token_rejects_unsupported_lookup_chain() {
        let net = TokenMetaMock::new(true);
        let provider = KaoDataProvider::new(&net, Chain::Mainnet, HashMap::new());
        let token = Address::repeat_byte(0x44).to_checksum(None);

        assert!(provider.resolve_token(999_999, &token).await.is_none());
        assert!(net.called_chains().is_empty());
        assert!(provider.all_verified());
    }

    // ── headline ─────────────────────────────────────────────────────
    //
    // The single line every signing surface leads with. It has to say the
    // same thing everywhere (the Send pill and the sign-review card both read
    // it from here) and it must never claim more confidence than the decode
    // earned.

    fn model(intent: &str, interpolated: Option<&str>) -> DisplayModel {
        DisplayModel {
            intent: intent.into(),
            interpolated_intent: interpolated.map(Into::into),
            entries: Vec::new(),
            owner: None,
            contract_name: Some("USDC".into()),
        }
    }

    fn call(state: ResolutionState, name: Option<&str>) -> DecodedCall {
        DecodedCall {
            to: Address::repeat_byte(0x11),
            selector: [0x09, 0x5e, 0xa7, 0xb3],
            raw_calldata: Bytes::new(),
            function_name: name.map(Into::into),
            args: Vec::new(),
            state,
            warnings: Vec::new(),
            proxy_hops: Vec::new(),
            all_verified: true,
            target_token: None,
            target_token_verified: true,
        }
    }

    #[test]
    fn headline_prefers_the_interpolated_intent() {
        // The interpolated form carries the resolved amounts/names — it's what
        // the descriptor meant to say.
        let h = DecodeResult::ClearSigned {
            model: model("Approve {token}", Some("Approve 5,000 USDC for Aave")),
            diagnostics: Vec::new(),
            proxy_hops: Vec::new(),
            all_verified: true,
            warnings: Vec::new(),
        }
        .headline()
        .unwrap();
        assert_eq!(h.text, "Approve 5,000 USDC for Aave");
        assert_eq!(h.caution, None);
        assert!(h.clear_signed, "a descriptor matched");
        assert!(!h.via_proxy);
    }

    #[test]
    fn headline_falls_back_to_the_raw_intent_and_flags_proxies() {
        let h = DecodeResult::ClearSigned {
            model: model("Approve token", None),
            diagnostics: Vec::new(),
            proxy_hops: vec![Address::repeat_byte(0x22)],
            all_verified: true,
            warnings: Vec::new(),
        }
        .headline()
        .unwrap();
        assert_eq!(h.text, "Approve token");
        assert!(h.via_proxy);
    }

    #[test]
    fn headline_is_provisional_when_a_read_fell_back_to_unverified_rpc() {
        // Interpolated names/amounts may be spoofed — the caller mutes the
        // line and pairs it with the caution strip.
        let h = DecodeResult::ClearSigned {
            model: model("Approve", Some("Approve 5,000 EVIL")),
            diagnostics: Vec::new(),
            proxy_hops: Vec::new(),
            all_verified: false,
            warnings: Vec::new(),
        }
        .headline()
        .unwrap();
        assert!(
            h.caution.is_some_and(|c| c.contains("unverified RPC")),
            "an unverified read must be called out beside the headline",
        );
    }

    #[test]
    fn fallback_headline_is_only_as_trusted_as_its_heuristic() {
        // The descriptor's own reads verified, but the heuristic it was
        // cross-referenced against didn't — the pair is provisional.
        let mut heuristic = call(ResolutionState::Resolved, Some("approve"));
        heuristic.all_verified = false;
        let h = DecodeResult::Fallback {
            model: model("Approve", None),
            reason: clear_signing::FallbackReason::FormatNotFound,
            diagnostics: Vec::new(),
            all_verified: true,
            heuristic,
        }
        .headline()
        .unwrap();
        assert!(h.caution.is_some());
        assert!(h.clear_signed);
    }

    #[test]
    fn heuristic_headline_names_the_function_or_shows_the_selector() {
        let named = DecodeResult::Heuristic(call(ResolutionState::Resolved, Some("approve")))
            .headline()
            .unwrap();
        assert_eq!(named.text, "approve(…)");
        assert_eq!(named.note, None);
        assert_eq!(named.caution, None);
        assert!(
            !named.clear_signed,
            "no descriptor — the review shows the full decode, unfolded",
        );

        // Nothing resolved the selector: the raw 4 bytes are the honest
        // headline, and it says so.
        let unknown = DecodeResult::Heuristic(call(ResolutionState::Unknown, None))
            .headline()
            .unwrap();
        assert_eq!(unknown.text, "0x095ea7b3");
        assert_eq!(unknown.note.as_deref(), Some("unverified call"));
    }

    #[test]
    fn heuristic_headline_marks_types_only_and_ambiguous() {
        let types_only = DecodeResult::Heuristic(call(ResolutionState::TypesOnly, None))
            .headline()
            .unwrap();
        assert_eq!(
            types_only.note.as_deref(),
            Some("decoded from bytecode · no name")
        );

        // One of several colliding signatures — the name is a guess, so the
        // headline must not render at full confidence.
        let ambiguous = DecodeResult::Heuristic(call(ResolutionState::Ambiguous, Some("transfer")))
            .headline()
            .unwrap();
        assert!(
            ambiguous
                .caution
                .is_some_and(|c| c.contains("share this selector")),
        );
        assert_eq!(ambiguous.text, "transfer(…)");
    }

    #[test]
    fn value_transfers_have_no_headline() {
        assert!(DecodeResult::Empty.headline().is_none());
        assert!(
            DecodeResult::Heuristic(call(ResolutionState::Empty, None))
                .headline()
                .is_none()
        );
    }

    // ── Mechanical cross-check on a clear-signed call ───────────────────────

    /// A descriptor whose `display.formats` names exactly `sigs`. Only the
    /// format keys are read by the check, but it is built through
    /// `Descriptor::from_json` rather than a struct literal so the fixture
    /// stays honest about the shape the registry actually ships.
    fn descriptors_for(sigs: &[&str]) -> Vec<clear_signing::ResolvedDescriptor> {
        let formats: String = sigs
            .iter()
            .map(|s| format!(r#""{s}": {{ "fields": [] }}"#))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(
            r#"{{
                "context": {{ "contract": {{ "deployments": [] }} }},
                "metadata": {{}},
                "display": {{ "formats": {{ {formats} }} }}
            }}"#
        );
        vec![clear_signing::ResolvedDescriptor {
            descriptor: clear_signing::Descriptor::from_json(&json)
                .expect("fixture descriptor parses"),
            chain_id: 1,
            address: format!("{:#x}", Address::repeat_byte(0x11)),
        }]
    }

    /// `transfer(address,uint256)` calldata, plus `tail` extra bytes that no
    /// argument accounts for.
    fn transfer_with_tail(tail: &[u8]) -> Bytes {
        let mut d = alloy::primitives::keccak256(b"transfer(address,uint256)")[..4].to_vec();
        d.extend_from_slice(
            alloy::primitives::B256::left_padding_from(Address::repeat_byte(0xBB).as_slice())
                .as_slice(),
        );
        d.extend_from_slice(&U256::from(1_000u64).to_be_bytes::<32>());
        d.extend_from_slice(tail);
        Bytes::from(d)
    }

    /// The attack the check exists for. A descriptor renders the two arguments
    /// it was authored to render and says nothing about a trailing word — and
    /// on this path the review folds destination, value and the whole function
    /// panel behind *Show details* precisely because a descriptor matched. An
    /// ERC-2771 forwarder reads the spoofed sender from exactly that tail.
    #[test]
    fn a_clear_signed_call_still_reports_calldata_its_arguments_dont_explain() {
        let suffix =
            alloy::primitives::B256::left_padding_from(Address::repeat_byte(0xEE).as_slice());
        let calldata = transfer_with_tail(suffix.as_slice());
        let w = bytes_warnings(&descriptors_for(&["transfer(address,uint256)"]), &calldata);
        match w.as_slice() {
            [Warning::UnaccountedCalldata { decoded, total }] => {
                assert_eq!(*decoded, 64, "two words are explained");
                assert_eq!(*total, 96, "three are present");
            }
            other => panic!("expected an unaccounted-calldata warning, got {other:?}"),
        }
    }

    /// The other half: an exactly-encoded call must stay silent. A false alarm
    /// on the wallet's most-trusted screen costs more than it buys.
    #[test]
    fn an_exactly_encoded_clear_signed_call_warns_about_nothing() {
        let calldata = transfer_with_tail(&[]);
        assert!(
            bytes_warnings(&descriptors_for(&["transfer(address,uint256)"]), &calldata).is_empty()
        );
    }

    /// The format is chosen by selector, not by position — a descriptor
    /// describing many functions must be measured against the one the
    /// transaction actually calls.
    #[test]
    fn the_check_measures_the_format_the_selector_names() {
        let calldata = transfer_with_tail(&[0u8; 32]);
        let d = descriptors_for(&[
            "approve(address,uint256)",
            "transfer(address,uint256)",
            "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        ]);
        assert!(
            matches!(
                bytes_warnings(&d, &calldata).as_slice(),
                [Warning::UnaccountedCalldata { .. }]
            ),
            "the transfer format is the one that had to be measured"
        );
    }

    /// No recoverable signature ⇒ no claim. A selector-keyed format carries no
    /// argument types, and a descriptor that doesn't describe this selector
    /// says nothing about it either. Silence, not a guess.
    #[test]
    fn an_unrecoverable_signature_makes_no_claim() {
        let calldata = transfer_with_tail(&[0u8; 32]);
        for d in [
            descriptors_for(&["0xa9059cbb"]),
            descriptors_for(&["approve(address,uint256)"]),
            descriptors_for(&[]),
        ] {
            assert!(
                bytes_warnings(&d, &calldata).is_empty(),
                "an unprovable claim is not a finding"
            );
        }
        // Too short to even hold a selector — must not panic on the slice.
        assert!(
            bytes_warnings(
                &descriptors_for(&["transfer(address,uint256)"]),
                &[0x01, 0x02]
            )
            .is_empty()
        );
    }
}
