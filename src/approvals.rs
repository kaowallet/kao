//! Approvals — find the allowances an account has left standing, and build
//! the calls that revoke them.
//!
//! Three shapes are covered, because they are the three a drainer uses:
//!
//! - **ERC-20 allowances** — `token.approve(spender, amount)`, read back with
//!   `allowance(owner, spender)`.
//! - **NFT operator approvals** — `collection.setApprovalForAll(operator,
//!   true)` over ERC-721 / ERC-1155, read back with `isApprovedForAll`.
//! - **Permit2 allowances** — the `(owner, token, spender)` mapping inside
//!   Permit2 itself, which a token-side `allowance()` read can't see.
//!
//! Single-token ERC-721 approvals (`approve(to, tokenId)`) are left out: they
//! are cleared by the next transfer of that item and reach one token, not a
//! collection.
//!
//! Discovery and verification are split on purpose. Candidates come from
//! sources the wallet does **not** trust — the RPC's `eth_getLogs` answer, and
//! the held-token × well-known-spender cross product — and every one is then
//! re-read through Helios's verified `eth_call` before it becomes a row. An RPC
//! can therefore *omit* an approval from the log scan (the seeds exist to
//! narrow that gap), but it can't invent one or misstate an amount without the
//! row carrying the unverified flag.

use std::collections::{BTreeSet, HashMap};

use alloy::primitives::{Address, Bytes, U256, address};
use alloy::rpc::types::{Filter, Log};
use alloy::sol_types::{SolCall, SolEvent};
use futures::StreamExt;

use crate::chain::Chain;
use crate::indexer::onchain::{
    address_from_topic, address_to_topic, decode_decimals, decode_symbol, get_logs_chunked,
};
use crate::net::BalanceFetcher;
use crate::portfolio::{Call3, MULTICALL3, aggregate3Call};
use crate::txbuilder::{DecodedArg, QueuedCall};
use crate::wallet::short_address;

mod erc {
    alloy::sol! {
        event Approval(address indexed owner, address indexed spender, uint256 value);
        event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
        function allowance(address owner, address spender) external view returns (uint256);
        function isApprovedForAll(address owner, address operator) external view returns (bool);
        function approve(address spender, uint256 amount) external returns (bool);
        function setApprovalForAll(address operator, bool approved) external;
        function symbol() external view returns (string);
        function decimals() external view returns (uint8);
    }
}

mod permit2 {
    alloy::sol! {
        event Approval(
            address indexed owner,
            address indexed token,
            address indexed spender,
            uint160 amount,
            uint48 expiration
        );
        event Permit(
            address indexed owner,
            address indexed token,
            address indexed spender,
            uint160 amount,
            uint48 expiration,
            uint48 nonce
        );
        function allowance(address user, address token, address spender)
            external
            view
            returns (uint160 amount, uint48 expiration, uint48 nonce);
        struct TokenSpenderPair {
            address token;
            address spender;
        }
        function lockdown(TokenSpenderPair[] approvals) external;
    }
}

/// Uniswap's canonical Permit2 deployment — the same address on every chain.
pub const PERMIT2: Address = address!("0x000000000022D473030F116dDEE9F6B43aC78BA3");

/// Blocks per `eth_getLogs` window. The same span the on-chain history
/// fallback uses, for the same reason: `get_logs_chunked` can split it down to
/// ~780 blocks, which every public RPC we know of accepts.
pub const WINDOW_BLOCKS: u64 = 50_000;

/// Most candidates one verification pass reads. A log scan over a spammed
/// address can surface thousands of junk `Approval` events; past this the
/// pass reports itself truncated rather than issuing an unbounded read storm.
pub const MAX_CANDIDATES: usize = 1_000;

/// Sub-reads per verified Multicall3 `eth_call`. Helios proves every account
/// and slot the call touches, so this bounds the proof set per round trip.
const READS_PER_CALL: usize = 60;

/// Spender `eth_getCode` reads in flight at once — each is its own Helios
/// proof, and public RPCs throttle past a handful.
const CODE_READS_IN_FLIGHT: usize = 6;

/// At or above this an allowance is shown as **Unlimited**. `2^96 - 1` is the
/// cap of the uint96 tokens (UNI, COMP) whose "infinite" approval saturates
/// there instead of at `2^256 - 1`, and no real balance of any token reaches
/// it — 79 billion whole units even at 18 decimals.
fn unlimited_threshold() -> U256 {
    (U256::from(1u8) << 96) - U256::from(1u8)
}

// ── Lookback ────────────────────────────────────────────────────────────────

/// How far back the log scan reaches. The seeds are checked whatever this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lookback {
    #[default]
    Month,
    Year,
    AllTime,
}

impl Lookback {
    pub const ALL: [Lookback; 3] = [Lookback::Month, Lookback::Year, Lookback::AllTime];

    pub fn label(self) -> &'static str {
        match self {
            Lookback::Month => "30 days",
            Lookback::Year => "1 year",
            Lookback::AllTime => "All time",
        }
    }

    /// The lowest block the scan reaches from `head`.
    pub fn floor(self, chain: Chain, head: u64) -> u64 {
        let days = match self {
            Lookback::Month => 30,
            Lookback::Year => 365,
            Lookback::AllTime => return 0,
        };
        head.saturating_sub(days * 86_400 / block_time_secs(chain))
    }
}

fn block_time_secs(chain: Chain) -> u64 {
    match chain {
        Chain::Mainnet => 12,
        Chain::Base | Chain::Optimism => 2,
    }
}

/// The next `[from, to]` window walking down from `cursor` towards `floor`.
pub fn window(cursor: u64, floor: u64) -> (u64, u64) {
    let from = cursor.saturating_sub(WINDOW_BLOCKS - 1).max(floor);
    (from, cursor)
}

/// Where the scan continues after the window starting at `from`, or `None`
/// once it has reached `floor`.
#[cfg(test)]
pub fn next_cursor(from: u64, floor: u64) -> Option<u64> {
    (from > floor).then(|| from - 1)
}

/// The next `[from, to]` window walking up from `from` towards `head` — how a
/// rescan reads the blocks that landed since the last one.
pub fn window_up(from: u64, head: u64) -> (u64, u64) {
    (from, from.saturating_add(WINDOW_BLOCKS - 1).min(head))
}

// ── Candidates ──────────────────────────────────────────────────────────────

/// A `(asset, spender)` pair that may hold an approval. Nothing about it is
/// trusted until [`verify`] has read it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Candidate {
    Erc20 {
        token: Address,
        spender: Address,
    },
    Operator {
        collection: Address,
        operator: Address,
    },
    Permit2 {
        token: Address,
        spender: Address,
    },
}

/// The log filter for every approval event `owner` could have emitted: the
/// four event signatures, with `owner` as the first indexed topic in each.
pub fn log_filter(owner: Address) -> Filter {
    Filter::new()
        .event_signature(vec![
            erc::Approval::SIGNATURE_HASH,
            erc::ApprovalForAll::SIGNATURE_HASH,
            permit2::Approval::SIGNATURE_HASH,
            permit2::Permit::SIGNATURE_HASH,
        ])
        .topic1(address_to_topic(owner))
}

/// Candidates named by `logs`. Only the event's *shape* is read — the amount a
/// log carries is history, not state, and a revoke is itself an `Approval`
/// event — so each hit is just a pair to read back.
///
/// Permit2's events are taken only from Permit2's own address. Any contract can
/// emit a log with that signature, and one that did would otherwise aim a
/// Permit2 read at a pair it made up.
pub fn candidates_from_logs(logs: &[Log]) -> Vec<Candidate> {
    let mut out = BTreeSet::new();
    for log in logs {
        let topics = log.topics();
        let Some(sig) = topics.first() else { continue };
        let emitter = log.address();
        let c = if *sig == erc::Approval::SIGNATURE_HASH && topics.len() == 3 {
            Candidate::Erc20 {
                token: emitter,
                spender: address_from_topic(&topics[2]),
            }
        } else if *sig == erc::ApprovalForAll::SIGNATURE_HASH && topics.len() == 3 {
            Candidate::Operator {
                collection: emitter,
                operator: address_from_topic(&topics[2]),
            }
        } else if (*sig == permit2::Approval::SIGNATURE_HASH
            || *sig == permit2::Permit::SIGNATURE_HASH)
            && topics.len() == 4
            && emitter == PERMIT2
        {
            Candidate::Permit2 {
                token: address_from_topic(&topics[2]),
                spender: address_from_topic(&topics[3]),
            }
        } else {
            continue;
        };
        out.insert(c);
    }
    out.into_iter().collect()
}

/// A spender this wallet can name, and the chains the name holds on.
struct KnownSpender {
    chains: &'static [Chain],
    /// EIP-55 form, so a mistyped digit fails the checksum test rather than
    /// quietly naming the wrong contract.
    address: &'static str,
    label: &'static str,
    /// Checked against every held token even when no log names the pair.
    seed_erc20: bool,
    /// Checked as a Permit2 spender of every held token.
    seed_permit2: bool,
}

const EVERY_CHAIN: &[Chain] = &[Chain::Mainnet, Chain::Base, Chain::Optimism];
const MAINNET: &[Chain] = &[Chain::Mainnet];

const KNOWN_SPENDERS: &[KnownSpender] = &[
    KnownSpender {
        chains: EVERY_CHAIN,
        address: "0x000000000022D473030F116dDEE9F6B43aC78BA3",
        label: "Permit2",
        seed_erc20: true,
        seed_permit2: false,
    },
    KnownSpender {
        chains: EVERY_CHAIN,
        address: "0xC92E8bdf79f0507f65a392b0ab4667716BFE0110",
        label: "CoW Protocol Vault Relayer",
        seed_erc20: true,
        seed_permit2: false,
    },
    KnownSpender {
        chains: EVERY_CHAIN,
        address: "0x1111111254EEB25477B68fb85Ed929f73A960582",
        label: "1inch v5 Router",
        seed_erc20: true,
        seed_permit2: false,
    },
    KnownSpender {
        chains: EVERY_CHAIN,
        address: "0x111111125421cA6dc452d289314280a0f8842A65",
        label: "1inch v6 Router",
        seed_erc20: true,
        seed_permit2: false,
    },
    KnownSpender {
        chains: EVERY_CHAIN,
        address: "0x1E0049783F008A0085193E00003D00cd54003c71",
        label: "OpenSea Conduit",
        seed_erc20: false,
        seed_permit2: false,
    },
    KnownSpender {
        chains: MAINNET,
        address: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
        label: "Uniswap V2 Router",
        seed_erc20: true,
        seed_permit2: false,
    },
    KnownSpender {
        chains: &[Chain::Mainnet, Chain::Optimism],
        address: "0xE592427A0AEce92De3Edee1F18E0157C05861564",
        label: "Uniswap V3 Router",
        seed_erc20: true,
        seed_permit2: false,
    },
    KnownSpender {
        chains: &[Chain::Mainnet, Chain::Optimism],
        address: "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",
        label: "Uniswap V3 Router 2",
        seed_erc20: true,
        seed_permit2: false,
    },
    KnownSpender {
        chains: &[Chain::Base],
        address: "0x2626664c2603336E57B271c5C0b26F421741e481",
        label: "Uniswap V3 Router 2",
        seed_erc20: true,
        seed_permit2: false,
    },
    KnownSpender {
        chains: MAINNET,
        address: "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
        label: "Uniswap Universal Router",
        seed_erc20: false,
        seed_permit2: true,
    },
    KnownSpender {
        chains: MAINNET,
        address: "0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af",
        label: "Uniswap v4 Universal Router",
        seed_erc20: false,
        seed_permit2: true,
    },
    KnownSpender {
        chains: MAINNET,
        address: "0xDef1C0ded9bec7F1a1670819833240f027b25EfF",
        label: "0x Exchange Proxy",
        seed_erc20: true,
        seed_permit2: false,
    },
    KnownSpender {
        chains: MAINNET,
        address: "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        label: "Aave v3 Pool",
        seed_erc20: true,
        seed_permit2: false,
    },
];

fn known_spenders(chain: Chain) -> impl Iterator<Item = (&'static KnownSpender, Address)> {
    KNOWN_SPENDERS
        .iter()
        .filter(move |k| k.chains.contains(&chain))
        .filter_map(|k| Some((k, Address::parse_checksummed(k.address, None).ok()?)))
}

/// The name this wallet has for `spender` on `chain`, if any.
pub fn spender_label(chain: Chain, spender: Address) -> Option<&'static str> {
    known_spenders(chain)
        .find(|(_, a)| *a == spender)
        .map(|(k, _)| k.label)
}

/// Pairs worth reading whatever the log scan returned: every token the
/// account holds, against the spenders it is most likely to have approved.
/// They cover the one thing verification can't — an RPC that leaves a log out.
pub fn seed_candidates(chain: Chain, held_tokens: &[Address]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for (k, spender) in known_spenders(chain) {
        for &token in held_tokens {
            if k.seed_erc20 {
                out.push(Candidate::Erc20 { token, spender });
            }
            if k.seed_permit2 {
                out.push(Candidate::Permit2 { token, spender });
            }
        }
    }
    out
}

// ── Network ─────────────────────────────────────────────────────────────────

/// The chain head the log scan walks down from.
pub async fn head(network: &dyn BalanceFetcher, chain: Chain) -> Result<u64, String> {
    use alloy::providers::Provider;
    let provider = network
        .provider(chain)
        .await
        .ok_or_else(|| format!("no RPC is configured for {}", chain.display_name()))?;
    provider
        .get_block_number()
        .await
        .map_err(|e| format!("couldn't read the {} head: {e}", chain.display_name()))
}

/// Candidates from one `[from, to]` window of `owner`'s approval events.
pub async fn scan_window(
    network: &dyn BalanceFetcher,
    chain: Chain,
    owner: Address,
    from: u64,
    to: u64,
) -> Result<Vec<Candidate>, String> {
    let provider = network
        .provider(chain)
        .await
        .ok_or_else(|| format!("no RPC is configured for {}", chain.display_name()))?;
    let logs = get_logs_chunked(&provider, &log_filter(owner), from, to, 0, "approvals").await?;
    Ok(candidates_from_logs(&logs))
}

/// What a verification pass found.
#[derive(Debug, Clone, Default)]
pub struct Verified {
    /// Every candidate still holding something, riskiest first.
    pub approvals: Vec<Approval>,
    /// Distinct candidates read.
    pub checked: usize,
    /// Candidates dropped for being over [`MAX_CANDIDATES`].
    pub skipped: usize,
}

/// Read every candidate back through Helios and keep the ones still live.
///
/// `now` is the unix time a Permit2 allowance's expiration is judged against.
pub async fn verify(
    network: &dyn BalanceFetcher,
    chain: Chain,
    owner: Address,
    candidates: Vec<Candidate>,
    now: u64,
) -> Result<Verified, String> {
    let unique: BTreeSet<Candidate> = candidates.into_iter().collect();
    let skipped = unique.len().saturating_sub(MAX_CANDIDATES);
    let candidates: Vec<Candidate> = unique.into_iter().take(MAX_CANDIDATES).collect();

    let plan = ReadPlan::new(owner, &candidates);
    let results = verified_multicall(network, chain, plan.calls()).await?;
    let live = plan.live(&results, now);

    let mut spenders: Vec<Address> = live.iter().map(|l| l.candidate.spender()).collect();
    spenders.sort();
    spenders.dedup();
    let codes: HashMap<Address, (bool, bool)> = futures::stream::iter(spenders)
        .map(|s| async move { (s, network.get_code(s, chain).await) })
        .buffered(CODE_READS_IN_FLIGHT)
        .filter_map(|(s, r)| async move {
            let r = r.ok()?;
            Some((s, (!r.value.is_empty(), r.verified)))
        })
        .collect()
        .await;

    let approvals = plan.assemble(chain, &results, live, &codes);
    Ok(Verified {
        approvals,
        checked: candidates.len(),
        skipped,
    })
}

/// One sub-read's answer: the return data when the call succeeded, and
/// whether the batch it rode in was light-client verified.
type ReadResult = (Option<Bytes>, bool);

async fn verified_multicall(
    network: &dyn BalanceFetcher,
    chain: Chain,
    calls: Vec<(Address, Bytes)>,
) -> Result<Vec<ReadResult>, String> {
    let mut out = Vec::with_capacity(calls.len());
    for chunk in calls.chunks(READS_PER_CALL) {
        let data = aggregate3Call {
            calls: chunk
                .iter()
                .map(|(target, data)| Call3 {
                    target: *target,
                    allowFailure: true,
                    callData: data.clone(),
                })
                .collect(),
        }
        .abi_encode();
        let read = network.call(MULTICALL3, data.into(), chain).await?;
        let decoded = aggregate3Call::abi_decode_returns(&read.value)
            .map_err(|e| format!("approval reads didn't decode: {e}"))?;
        // Rows are matched to reads by position; a short answer would pin
        // every later allowance on the wrong pair.
        if decoded.len() != chunk.len() {
            return Err(format!(
                "approval reads came back with {} answers for {} questions",
                decoded.len(),
                chunk.len()
            ));
        }
        out.extend(
            decoded
                .into_iter()
                .map(|r| (r.success.then_some(r.returnData), read.verified)),
        );
    }
    Ok(out)
}

impl Candidate {
    fn asset(self) -> Address {
        match self {
            Candidate::Erc20 { token, .. } | Candidate::Permit2 { token, .. } => token,
            Candidate::Operator { collection, .. } => collection,
        }
    }

    fn spender(self) -> Address {
        match self {
            Candidate::Erc20 { spender, .. } | Candidate::Permit2 { spender, .. } => spender,
            Candidate::Operator { operator, .. } => operator,
        }
    }

    fn kind(self) -> Kind {
        match self {
            Candidate::Erc20 { .. } => Kind::Erc20,
            Candidate::Operator { .. } => Kind::Operator,
            Candidate::Permit2 { .. } => Kind::Permit2,
        }
    }

    fn state_read(self, owner: Address) -> (Address, Bytes) {
        match self {
            Candidate::Erc20 { token, spender } => (
                token,
                erc::allowanceCall { owner, spender }.abi_encode().into(),
            ),
            Candidate::Operator {
                collection,
                operator,
            } => (
                collection,
                erc::isApprovedForAllCall { owner, operator }
                    .abi_encode()
                    .into(),
            ),
            Candidate::Permit2 { token, spender } => (
                PERMIT2,
                permit2::allowanceCall {
                    user: owner,
                    token,
                    spender,
                }
                .abi_encode()
                .into(),
            ),
        }
    }
}

/// A candidate whose read came back live.
struct Live {
    candidate: Candidate,
    amount: Option<U256>,
    expires: Option<u64>,
    verified: bool,
}

/// The reads one verification pass issues, in order: a state read per
/// candidate, then `symbol()` per asset, then `decimals()` per token asset.
struct ReadPlan {
    owner: Address,
    candidates: Vec<Candidate>,
    assets: Vec<Address>,
    /// Assets that need `decimals()` (not NFT collections), in read order.
    decimal_assets: Vec<Address>,
}

impl ReadPlan {
    fn new(owner: Address, candidates: &[Candidate]) -> Self {
        let mut assets: Vec<Address> = candidates.iter().map(|c| c.asset()).collect();
        assets.sort();
        assets.dedup();
        let mut decimal_assets: Vec<Address> = candidates
            .iter()
            .filter(|c| !matches!(c, Candidate::Operator { .. }))
            .map(|c| c.asset())
            .collect();
        decimal_assets.sort();
        decimal_assets.dedup();
        Self {
            owner,
            candidates: candidates.to_vec(),
            assets,
            decimal_assets,
        }
    }

    fn calls(&self) -> Vec<(Address, Bytes)> {
        let symbol: Bytes = erc::symbolCall {}.abi_encode().into();
        let decimals: Bytes = erc::decimalsCall {}.abi_encode().into();
        self.candidates
            .iter()
            .map(|c| c.state_read(self.owner))
            .chain(self.assets.iter().map(|a| (*a, symbol.clone())))
            .chain(self.decimal_assets.iter().map(|a| (*a, decimals.clone())))
            .collect()
    }

    /// The candidates whose read says they still grant something.
    ///
    /// A failed or malformed read is dropped, not guessed at: a contract that
    /// doesn't answer `allowance()` holds no allowance this wallet can revoke.
    fn live(&self, results: &[ReadResult], now: u64) -> Vec<Live> {
        let mut out = Vec::new();
        for (c, (data, verified)) in self.candidates.iter().zip(results) {
            let Some(data) = data else { continue };
            let (amount, expires) = match c {
                Candidate::Erc20 { .. } => {
                    let Ok(a) = erc::allowanceCall::abi_decode_returns(data) else {
                        continue;
                    };
                    if a.is_zero() {
                        continue;
                    }
                    (Some(a), None)
                }
                Candidate::Operator { .. } => {
                    match erc::isApprovedForAllCall::abi_decode_returns(data) {
                        Ok(true) => (None, None),
                        _ => continue,
                    }
                }
                Candidate::Permit2 { .. } => {
                    let Ok(r) = permit2::allowanceCall::abi_decode_returns(data) else {
                        continue;
                    };
                    let amount = U256::from(r.amount);
                    let expiration = r.expiration.to::<u64>();
                    // Permit2 refuses a pull once `block.timestamp > expiration`,
                    // so an expired grant is inert whatever its amount says.
                    if amount.is_zero() || expiration < now {
                        continue;
                    }
                    (Some(amount), Some(expiration))
                }
            };
            out.push(Live {
                candidate: *c,
                amount,
                expires,
                verified: *verified,
            });
        }
        out
    }

    fn assemble(
        &self,
        chain: Chain,
        results: &[ReadResult],
        live: Vec<Live>,
        codes: &HashMap<Address, (bool, bool)>,
    ) -> Vec<Approval> {
        let n = self.candidates.len();
        let symbol_of: HashMap<Address, &ReadResult> = self
            .assets
            .iter()
            .copied()
            .zip(&results[n..n + self.assets.len()])
            .collect();
        let decimals_of: HashMap<Address, &ReadResult> = self
            .decimal_assets
            .iter()
            .copied()
            .zip(&results[n + self.assets.len()..])
            .collect();
        let curated: HashMap<Address, (String, u8)> = crate::portfolio::curated_tokens(chain)
            .into_iter()
            .map(|(sym, addr, dec)| (addr, (sym, dec)))
            .collect();

        let mut out: Vec<Approval> = live
            .into_iter()
            .map(|l| {
                let asset = l.candidate.asset();
                let spender = l.candidate.spender();
                let is_nft = matches!(l.candidate, Candidate::Operator { .. });
                // A curated token's symbol and decimals are the wallet's own; a
                // contract's answer is whatever its deployer chose, and only
                // stands in when there is nothing better.
                let (symbol, decimals, known_asset) = match curated.get(&asset) {
                    Some((sym, dec)) if !is_nft => (sym.clone(), Some(*dec), true),
                    _ => {
                        let sym = symbol_of
                            .get(&asset)
                            .and_then(|(d, _)| d.as_ref())
                            .map(decode_symbol)
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| short_address(asset));
                        let dec = decimals_of
                            .get(&asset)
                            .and_then(|(d, _)| d.as_ref())
                            .and_then(decode_decimals);
                        (sym, dec, false)
                    }
                };
                let (spender_has_code, code_verified) = match codes.get(&spender) {
                    Some((has, v)) => (Some(*has), *v),
                    None => (None, true),
                };
                Approval {
                    kind: l.candidate.kind(),
                    asset,
                    symbol,
                    known_asset,
                    decimals,
                    spender,
                    spender_label: spender_label(chain, spender),
                    amount: l.amount,
                    expires: l.expires,
                    spender_has_code,
                    verified: l.verified && code_verified,
                }
            })
            .collect();
        out.sort_by(|a, b| {
            b.severity()
                .cmp(&a.severity())
                .then_with(|| a.symbol.cmp(&b.symbol))
                .then_with(|| a.spender.cmp(&b.spender))
        });
        out
    }
}

// ── Rows ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Erc20,
    Operator,
    Permit2,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Erc20 => "Token",
            Kind::Operator => "NFT",
            Kind::Permit2 => "Permit2",
        }
    }
}

/// Why a row deserves a second look.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// The spender can take every unit the account ever holds.
    Unlimited,
    /// The operator can move every item in the collection.
    EveryItem,
    /// The spender has no code — a plain account, the shape a phishing
    /// approval usually takes. No router needs one.
    NotAContract,
    /// The token isn't on the wallet's curated list, so its symbol is
    /// whatever its contract says.
    UnknownToken,
    /// A read fell back to the raw RPC, so the row is the RPC's word.
    Unverified,
}

impl Risk {
    pub fn label(self) -> &'static str {
        match self {
            Risk::Unlimited => "Unlimited",
            Risk::EveryItem => "Whole collection",
            Risk::NotAContract => "Spender isn't a contract",
            Risk::UnknownToken => "Unlisted token",
            Risk::Unverified => "Unverified read",
        }
    }

    /// Whether this is worth a warning colour, rather than a neutral note.
    pub fn is_serious(self) -> bool {
        matches!(self, Risk::Unlimited | Risk::EveryItem | Risk::NotAContract)
    }
}

/// One live approval, read back through the light client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub kind: Kind,
    /// The token, or the NFT collection.
    pub asset: Address,
    pub symbol: String,
    pub known_asset: bool,
    /// `None` for an NFT collection, or a token that didn't answer `decimals()`.
    pub decimals: Option<u8>,
    pub spender: Address,
    pub spender_label: Option<&'static str>,
    /// `None` for an operator approval, which has no amount.
    pub amount: Option<U256>,
    /// Permit2 only: when the allowance stops working (unix seconds).
    pub expires: Option<u64>,
    /// `None` when the code read failed.
    pub spender_has_code: Option<bool>,
    pub verified: bool,
}

impl Approval {
    /// The pair this row reads, used as its identity in the UI.
    pub fn key(&self) -> Candidate {
        match self.kind {
            Kind::Erc20 => Candidate::Erc20 {
                token: self.asset,
                spender: self.spender,
            },
            Kind::Operator => Candidate::Operator {
                collection: self.asset,
                operator: self.spender,
            },
            Kind::Permit2 => Candidate::Permit2 {
                token: self.asset,
                spender: self.spender,
            },
        }
    }

    pub fn is_unlimited(&self) -> bool {
        self.amount.is_some_and(|a| a >= unlimited_threshold())
    }

    /// "Unlimited USDC", "250 USDC", "Every BAYC".
    pub fn amount_label(&self) -> String {
        match self.amount {
            None => format!("Every {}", self.symbol),
            Some(_) if self.is_unlimited() => format!("Unlimited {}", self.symbol),
            Some(a) => match self.decimals {
                Some(d) => {
                    let (s, _) = crate::portfolio::format_token_balance(a, d);
                    format!("{s} {}", self.symbol)
                }
                None => format!("{a} base units of {}", self.symbol),
            },
        }
    }

    pub fn risks(&self) -> Vec<Risk> {
        let mut out = Vec::new();
        if self.is_unlimited() {
            out.push(Risk::Unlimited);
        }
        if self.kind == Kind::Operator {
            out.push(Risk::EveryItem);
        }
        if self.spender_has_code == Some(false) {
            out.push(Risk::NotAContract);
        }
        if !self.known_asset && self.kind != Kind::Operator {
            out.push(Risk::UnknownToken);
        }
        if !self.verified {
            out.push(Risk::Unverified);
        }
        out
    }

    /// Sort key: rows a drainer could use hardest come first.
    fn severity(&self) -> u8 {
        let r = self.risks();
        let mut s = 0;
        if r.contains(&Risk::NotAContract) {
            s += 4;
        }
        if r.contains(&Risk::Unlimited) || r.contains(&Risk::EveryItem) {
            s += 2;
        }
        if self.spender_label.is_none() {
            s += 1;
        }
        s
    }
}

// ── Revoke ──────────────────────────────────────────────────────────────────

/// The calls that revoke `rows`: `approve(spender, 0)` per token allowance,
/// `setApprovalForAll(operator, false)` per operator, and one Permit2
/// `lockdown` for every Permit2 pair together.
///
/// Ids are placeholders — the Transaction Builder renumbers on adoption.
pub fn revoke_calls(rows: &[&Approval]) -> Vec<QueuedCall> {
    let mut out = Vec::new();
    for a in rows.iter().filter(|a| a.kind == Kind::Erc20) {
        out.push(QueuedCall {
            id: 0,
            to: a.asset,
            value: U256::ZERO,
            data: erc::approveCall {
                spender: a.spender,
                amount: U256::ZERO,
            }
            .abi_encode()
            .into(),
            title: format!("{}.approve", a.symbol),
            detail: format!("{} → 0", spender_name(a)),
            signature: Some("approve(address,uint256)".into()),
            decoded_args: vec![
                arg("spender", "address", a.spender.to_checksum(None)),
                arg("amount", "uint256", "0".into()),
            ],
        });
    }
    for a in rows.iter().filter(|a| a.kind == Kind::Operator) {
        out.push(QueuedCall {
            id: 0,
            to: a.asset,
            value: U256::ZERO,
            data: erc::setApprovalForAllCall {
                operator: a.spender,
                approved: false,
            }
            .abi_encode()
            .into(),
            title: format!("{}.setApprovalForAll", a.symbol),
            detail: format!("{} → off", spender_name(a)),
            signature: Some("setApprovalForAll(address,bool)".into()),
            decoded_args: vec![
                arg("operator", "address", a.spender.to_checksum(None)),
                arg("approved", "bool", "false".into()),
            ],
        });
    }
    let pairs: Vec<&&Approval> = rows.iter().filter(|a| a.kind == Kind::Permit2).collect();
    if !pairs.is_empty() {
        out.push(QueuedCall {
            id: 0,
            to: PERMIT2,
            value: U256::ZERO,
            data: permit2::lockdownCall {
                approvals: pairs
                    .iter()
                    .map(|a| permit2::TokenSpenderPair {
                        token: a.asset,
                        spender: a.spender,
                    })
                    .collect(),
            }
            .abi_encode()
            .into(),
            title: "Permit2.lockdown".into(),
            detail: format!(
                "{} allowance{} → 0",
                pairs.len(),
                if pairs.len() == 1 { "" } else { "s" }
            ),
            signature: Some("lockdown((address,address)[])".into()),
            decoded_args: vec![arg(
                "approvals",
                "(address,address)[]",
                format!(
                    "[{}]",
                    pairs
                        .iter()
                        .map(|a| format!(
                            "({}, {})",
                            a.asset.to_checksum(None),
                            a.spender.to_checksum(None)
                        ))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )],
        });
    }
    out
}

fn spender_name(a: &Approval) -> String {
    a.spender_label
        .map(str::to_string)
        .unwrap_or_else(|| short_address(a.spender))
}

fn arg(name: &str, ty: &str, value: String) -> DecodedArg {
    DecodedArg {
        name: name.into(),
        ty: ty.into(),
        value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{B256, LogData, keccak256};

    const OWNER: Address = address!("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045");
    const USDC: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
    const SPENDER: Address = address!("0x1111111111111111111111111111111111111111");
    const NFT: Address = address!("0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D");

    fn log(emitter: Address, topics: Vec<B256>) -> Log {
        Log {
            inner: alloy::primitives::Log {
                address: emitter,
                data: LogData::new_unchecked(topics, Bytes::new()),
            },
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        }
    }

    fn word(v: U256) -> Bytes {
        Bytes::from(v.to_be_bytes::<32>().to_vec())
    }

    fn row(kind: Kind, amount: Option<U256>) -> Approval {
        Approval {
            kind,
            asset: USDC,
            symbol: "USDC".into(),
            known_asset: true,
            decimals: Some(6),
            spender: SPENDER,
            spender_label: None,
            amount,
            expires: None,
            spender_has_code: Some(true),
            verified: true,
        }
    }

    /// Every event and call this module keys off, pinned to its preimage. A
    /// drifted selector reads nothing, and "nothing" renders as "no approvals".
    #[test]
    fn signatures_are_canonical() {
        for (sig, hash) in [
            (
                "Approval(address,address,uint256)",
                erc::Approval::SIGNATURE_HASH,
            ),
            (
                "ApprovalForAll(address,address,bool)",
                erc::ApprovalForAll::SIGNATURE_HASH,
            ),
            (
                "Approval(address,address,address,uint160,uint48)",
                permit2::Approval::SIGNATURE_HASH,
            ),
            (
                "Permit(address,address,address,uint160,uint48,uint48)",
                permit2::Permit::SIGNATURE_HASH,
            ),
        ] {
            assert_eq!(keccak256(sig), hash, "{sig}");
        }
        for (sig, sel) in [
            (
                "allowance(address,address,address)",
                permit2::allowanceCall::SELECTOR,
            ),
            (
                "lockdown((address,address)[])",
                permit2::lockdownCall::SELECTOR,
            ),
            (
                "setApprovalForAll(address,bool)",
                erc::setApprovalForAllCall::SELECTOR,
            ),
        ] {
            assert_eq!(keccak256(sig)[..4], sel, "{sig}");
        }
        assert_eq!(
            erc::approveCall::SELECTOR,
            crate::txbuilder::flash_approval::APPROVE_SELECTOR
        );
    }

    #[test]
    fn known_spenders_are_checksummed() {
        for k in KNOWN_SPENDERS {
            assert!(
                Address::parse_checksummed(k.address, None).is_ok(),
                "{} ({}) fails its EIP-55 checksum",
                k.label,
                k.address
            );
        }
        assert_eq!(spender_label(Chain::Base, PERMIT2), Some("Permit2"));
        assert_eq!(
            spender_label(Chain::Base, crate::cow::VAULT_RELAYER),
            Some("CoW Protocol Vault Relayer")
        );
    }

    /// Mainnet-only routers must not name an address on an L2, where the same
    /// bytes can be a different contract or nothing at all.
    #[test]
    fn labels_stay_on_their_chains() {
        let v2: Address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap();
        assert_eq!(spender_label(Chain::Mainnet, v2), Some("Uniswap V2 Router"));
        assert_eq!(spender_label(Chain::Base, v2), None);
    }

    #[test]
    fn logs_become_candidates_by_shape() {
        let owner = address_to_topic(OWNER);
        let spender = address_to_topic(SPENDER);
        let logs = vec![
            log(USDC, vec![erc::Approval::SIGNATURE_HASH, owner, spender]),
            // The same log twice dedupes.
            log(USDC, vec![erc::Approval::SIGNATURE_HASH, owner, spender]),
            // ERC-721 single-token approval: tokenId is a fourth topic.
            log(
                NFT,
                vec![erc::Approval::SIGNATURE_HASH, owner, spender, B256::ZERO],
            ),
            log(
                NFT,
                vec![erc::ApprovalForAll::SIGNATURE_HASH, owner, spender],
            ),
            log(
                PERMIT2,
                vec![
                    permit2::Permit::SIGNATURE_HASH,
                    owner,
                    address_to_topic(USDC),
                    spender,
                ],
            ),
        ];
        assert_eq!(
            candidates_from_logs(&logs),
            vec![
                Candidate::Erc20 {
                    token: USDC,
                    spender: SPENDER
                },
                Candidate::Operator {
                    collection: NFT,
                    operator: SPENDER
                },
                Candidate::Permit2 {
                    token: USDC,
                    spender: SPENDER
                },
            ]
        );
    }

    /// Any contract can emit Permit2's event signature. Only Permit2's own
    /// logs describe Permit2's mapping.
    #[test]
    fn permit2_events_from_elsewhere_are_ignored() {
        let logs = vec![log(
            USDC,
            vec![
                permit2::Approval::SIGNATURE_HASH,
                address_to_topic(OWNER),
                address_to_topic(USDC),
                address_to_topic(SPENDER),
            ],
        )];
        assert!(candidates_from_logs(&logs).is_empty());
    }

    #[test]
    fn windows_walk_down_to_the_floor_and_stop() {
        let floor = 100_000;
        let (from, to) = window(200_000, floor);
        assert_eq!((from, to), (150_001, 200_000));
        assert_eq!(next_cursor(from, floor), Some(150_000));
        let (from, to) = window(150_000, floor);
        assert_eq!((from, to), (100_001, 150_000));
        let (from, _) = window(next_cursor(from, floor).unwrap(), floor);
        assert_eq!(from, floor, "the last window is clipped at the floor");
        assert_eq!(next_cursor(from, floor), None);
        // Genesis.
        assert_eq!(window(10, 0), (0, 10));
        assert_eq!(next_cursor(0, 0), None);
    }

    #[test]
    fn upward_windows_stop_at_the_head() {
        assert_eq!(window_up(100, 120), (100, 120));
        assert_eq!(window_up(100, 1_000_000), (100, 100 + WINDOW_BLOCKS - 1));
    }

    #[test]
    fn lookback_floor_scales_with_block_time() {
        let head = 20_000_000;
        assert_eq!(Lookback::Month.floor(Chain::Mainnet, head), head - 216_000);
        assert_eq!(Lookback::Month.floor(Chain::Base, head), head - 1_296_000);
        assert_eq!(Lookback::AllTime.floor(Chain::Mainnet, head), 0);
        assert_eq!(Lookback::Year.floor(Chain::Base, 5), 0, "no underflow");
    }

    #[test]
    fn seeds_cross_held_tokens_with_chain_spenders() {
        let seeds = seed_candidates(Chain::Base, &[USDC]);
        assert!(seeds.contains(&Candidate::Erc20 {
            token: USDC,
            spender: PERMIT2
        }));
        // The Universal Router seeds are Mainnet-only.
        assert!(!seeds.iter().any(|c| matches!(c, Candidate::Permit2 { .. })));
        assert!(
            seed_candidates(Chain::Mainnet, &[USDC])
                .iter()
                .any(|c| matches!(c, Candidate::Permit2 { .. }))
        );
        assert!(seed_candidates(Chain::Mainnet, &[]).is_empty());
    }

    /// The pure half of `verify`: which reads count as live, and what each row
    /// says about itself.
    #[test]
    fn live_reads_keep_only_what_still_grants() {
        let cands = vec![
            Candidate::Erc20 {
                token: USDC,
                spender: SPENDER,
            },
            Candidate::Erc20 {
                token: USDC,
                spender: PERMIT2,
            },
            Candidate::Operator {
                collection: NFT,
                operator: SPENDER,
            },
            Candidate::Permit2 {
                token: USDC,
                spender: SPENDER,
            },
            Candidate::Permit2 {
                token: NFT,
                spender: SPENDER,
            },
        ];
        let plan = ReadPlan::new(OWNER, &cands);
        let now = 1_000;
        let permit2_row = |amount: u64, expiration: u64| {
            let mut v = Vec::new();
            v.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
            v.extend_from_slice(&U256::from(expiration).to_be_bytes::<32>());
            v.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
            Bytes::from(v)
        };
        let mut results: Vec<ReadResult> = vec![
            (Some(word(U256::MAX)), true),
            // Revoked already.
            (Some(word(U256::ZERO)), true),
            (Some(word(U256::from(1u8))), false),
            (Some(permit2_row(5, 2_000)), true),
            // Expired.
            (Some(permit2_row(5, 999)), true),
        ];
        // Metadata reads, all failed — the fallbacks must hold.
        results.extend(std::iter::repeat_n(
            (None, true),
            plan.calls().len() - cands.len(),
        ));
        let live = plan.live(&results, now);
        assert_eq!(live.len(), 3);

        let codes = HashMap::from([(SPENDER, (false, true))]);
        let rows = plan.assemble(Chain::Mainnet, &results, live, &codes);
        assert_eq!(rows.len(), 3);
        // The Permit2 grant is limited and so outranked by both blanket grants
        // to the same plain-account spender.
        assert_eq!(rows[2].kind, Kind::Permit2);
        let erc20 = rows.iter().find(|r| r.kind == Kind::Erc20).unwrap();
        assert!(erc20.is_unlimited());
        assert_eq!(erc20.symbol, "USDC", "curated symbol, not a failed read");
        assert!(erc20.risks().contains(&Risk::NotAContract));
        let nft = rows.iter().find(|r| r.kind == Kind::Operator).unwrap();
        assert!(!nft.verified, "an unverified read stays flagged");
        assert_eq!(nft.symbol, short_address(NFT));
        let p2 = rows.iter().find(|r| r.kind == Kind::Permit2).unwrap();
        assert_eq!(p2.expires, Some(2_000));
        assert_eq!(p2.amount_label(), "0.000005 USDC");
    }

    #[test]
    fn amount_labels() {
        assert_eq!(
            row(Kind::Erc20, Some(U256::MAX)).amount_label(),
            "Unlimited USDC"
        );
        assert_eq!(
            row(Kind::Erc20, Some(unlimited_threshold())).amount_label(),
            "Unlimited USDC",
            "a saturated uint96 approval is unlimited too"
        );
        assert_eq!(
            row(Kind::Erc20, Some(U256::from(250_000_000u64))).amount_label(),
            "250.0000 USDC"
        );
        let mut nft = row(Kind::Operator, None);
        nft.symbol = "BAYC".into();
        assert_eq!(nft.amount_label(), "Every BAYC");
        assert!(nft.risks().contains(&Risk::EveryItem));
    }

    #[test]
    fn revoke_calls_zero_each_shape() {
        let erc20 = row(Kind::Erc20, Some(U256::MAX));
        let mut nft = row(Kind::Operator, None);
        nft.asset = NFT;
        let p2a = row(Kind::Permit2, Some(U256::from(5u8)));
        let mut p2b = p2a.clone();
        p2b.asset = NFT;
        let calls = revoke_calls(&[&p2a, &erc20, &nft, &p2b]);
        assert_eq!(calls.len(), 3, "the two Permit2 pairs share one lockdown");

        assert_eq!(calls[0].to, USDC);
        let a = erc::approveCall::abi_decode(&calls[0].data).unwrap();
        assert_eq!((a.spender, a.amount), (SPENDER, U256::ZERO));

        assert_eq!(calls[1].to, NFT);
        let s = erc::setApprovalForAllCall::abi_decode(&calls[1].data).unwrap();
        assert_eq!((s.operator, s.approved), (SPENDER, false));

        assert_eq!(calls[2].to, PERMIT2);
        let l = permit2::lockdownCall::abi_decode(&calls[2].data).unwrap();
        assert_eq!(l.approvals.len(), 2);
        assert_eq!(l.approvals[0].token, USDC);
        assert_eq!(l.approvals[1].token, NFT);

        for c in &calls {
            assert!(c.value.is_zero());
            assert!(!c.is_raw());
        }
    }

    /// The revoke batch goes through the Builder's review, which describes
    /// allowances with the flash-approval verdict. It must read as revokes,
    /// never as a grant it can't account for.
    #[test]
    fn a_revoke_batch_reads_as_revokes_in_review() {
        let erc20 = row(Kind::Erc20, Some(U256::MAX));
        let mut nft = row(Kind::Operator, None);
        nft.asset = NFT;
        let calls = revoke_calls(&[&erc20, &nft]);
        let v = crate::txbuilder::flash_approval::allowance_verdict(&calls);
        assert!(v.standing.is_empty());
        assert!(
            v.unmodelled.is_empty(),
            "setApprovalForAll(_, false) is not a grant"
        );
        let d = v.disclosure().unwrap();
        assert!(d.starts_with("Revokes 1 token allowance"), "got {d}");
    }

    #[tokio::test]
    async fn verify_reads_through_the_verified_call_path() {
        let mock = crate::net::CallMock::new();
        let cands = vec![Candidate::Erc20 {
            token: USDC,
            spender: SPENDER,
        }];
        let plan = ReadPlan::new(OWNER, &cands);
        let request = aggregate3Call {
            calls: plan
                .calls()
                .into_iter()
                .map(|(target, call_data)| Call3 {
                    target,
                    allowFailure: true,
                    callData: call_data,
                })
                .collect(),
        }
        .abi_encode();
        let answer = aggregate3Call::abi_encode_returns(&vec![
            crate::portfolio::MultiResult {
                success: true,
                returnData: word(U256::from(42u8)),
            },
            crate::portfolio::MultiResult {
                success: false,
                returnData: Bytes::new(),
            },
            crate::portfolio::MultiResult {
                success: false,
                returnData: Bytes::new(),
            },
        ]);
        mock.set_call(MULTICALL3, request.into(), answer.into(), true);
        mock.set_code(SPENDER, Bytes::from_static(&[0x60]), true);

        let v = verify(&mock, Chain::Mainnet, OWNER, cands, 0)
            .await
            .unwrap();
        assert_eq!(v.checked, 1);
        assert_eq!(v.approvals.len(), 1);
        let a = &v.approvals[0];
        assert_eq!(a.amount, Some(U256::from(42u8)));
        assert_eq!(a.spender_has_code, Some(true));
        assert!(a.verified);
        assert!(a.risks().is_empty(), "{:?}", a.risks());
    }
}
