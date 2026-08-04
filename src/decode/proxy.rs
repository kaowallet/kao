//! EIP-1967 / ZeppelinOS proxy walker.
//!
//! Given a contract address that calldata is targeting, follow well-known
//! implementation-pointer storage slots through any layers of proxy
//! indirection until we reach a non-proxy contract. The clear-signing
//! pipeline then runs bytecode introspection (evmole) against THAT
//! contract instead of the proxy stub, which would otherwise have an
//! empty selector set.
//!
//! ### Slots followed
//!
//! - **EIP-1967 implementation** (`bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)`)
//!   — the modern standard; covers Transparent and UUPS proxies.
//! - **ZeppelinOS legacy** (`keccak256("org.zeppelinos.proxy.implementation")`) —
//!   pre-EIP-1967 OpenZeppelin contracts; still in the wild on older
//!   deployments.
//!
//! ### Slots not followed (yet)
//!
//! - **EIP-1967 beacon** (`bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)`):
//!   beacon proxies store a beacon address in the slot, and you
//!   resolve the implementation by calling `implementation()` on the
//!   beacon. That requires an `eth_call`, which Phase 1 deliberately
//!   skipped (alloy v1/v2 type wrangling on the Helios boundary). Not
//!   followed, but [`is_beacon_proxy`] recognises the shape so the UI can
//!   say which limitation it hit rather than showing an empty ABI.
//! - **EIP-1967 admin** — used for upgrade governance, not call routing.
//!
//! ### Not a slot at all
//!
//! - **ERC-1167 minimal proxies** (OpenZeppelin `Clones`) carry the
//!   implementation as 20 literal bytes inside a fixed 45-byte runtime, with no
//!   storage pointer for this walker to find. [`erc1167_target`] reads it
//!   straight out of the code — no RPC call, no trust decision.

use alloy::primitives::{Address, B256, U256};

use crate::chain::Chain;
use crate::net::BalanceFetcher;

/// EIP-1967 implementation slot:
/// `bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)` =
/// `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`.
/// Asserted at test time by recomputing the keccak; baked in here so
/// the const is usable without a runtime initializer.
const EIP_1967_IMPL_SLOT: B256 = B256::new([
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d,
    0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc,
]);

/// `keccak256("org.zeppelinos.proxy.implementation")`.
const ZOS_IMPL_SLOT: B256 = B256::new([
    0x70, 0x50, 0xc9, 0xe0, 0xf4, 0xca, 0x76, 0x9c, 0x69, 0xbd, 0x3a, 0x8e, 0xf7, 0x40, 0xbc, 0x37,
    0x93, 0x4f, 0x8e, 0x2c, 0x03, 0x6e, 0x5a, 0x72, 0x3f, 0xd8, 0xee, 0x04, 0x8e, 0xd3, 0xf8, 0xc3,
]);

const SLOTS: &[B256] = &[EIP_1967_IMPL_SLOT, ZOS_IMPL_SLOT];

/// Stop after this many proxy hops. Real proxies are 1 hop deep; the
/// limit is here to keep a pathological diamond-of-proxies from looping
/// forever, not because deeper chains are expected.
const MAX_DEPTH: usize = 4;

/// Outcome of walking the proxy chain rooted at the original target.
#[derive(Debug, Clone)]
pub struct ProxyResolution {
    /// The address whose bytecode will actually run when the call lands.
    /// Equal to the input when no proxy slots resolve.
    pub implementation: Address,
    /// Each hop the walk took, in order. Empty when no proxy was
    /// detected; present for diagnostic UI ("Proxy → 0x… → 0x…").
    pub hops: Vec<Address>,
    /// Every storage read in the chain came back via Helios's verified
    /// path. False if any read fell back to raw RPC — UI should warn.
    pub all_verified: bool,
}

/// Resolve `addr` to the final implementation by walking known proxy
/// slots. On any storage-read failure for a given slot, that slot is
/// skipped (not treated as fatal) — the next slot in [`SLOTS`] still
/// gets a try, and if no slot resolves at the current depth we settle
/// at `addr`.
pub async fn resolve_implementation(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> ProxyResolution {
    let mut current = addr;
    let mut hops: Vec<Address> = Vec::new();
    let mut all_verified = true;
    for _ in 0..MAX_DEPTH {
        match probe_slots(net, chain, current).await {
            Some((impl_addr, verified)) => {
                if !verified {
                    all_verified = false;
                    // Do not let raw-RPC storage select the implementation
                    // used for clear-signing descriptors or bytecode
                    // introspection. The caller still sees all_verified=false
                    // and can warn, but the untrusted pointer is not followed.
                    break;
                }
                if impl_addr == current {
                    // Self-pointer; treat as terminal to avoid an
                    // infinite loop even within MAX_DEPTH.
                    break;
                }
                hops.push(impl_addr);
                current = impl_addr;
            }
            None => break,
        }
    }
    ProxyResolution {
        implementation: current,
        hops,
        all_verified,
    }
}

/// Read each known proxy slot in turn. Returns the first slot that
/// holds a non-zero address, plus whether THAT read was verified. Slot
/// errors are non-fatal — a borked RPC for one slot doesn't prevent the
/// walker from trying the next.
async fn probe_slots(
    net: &dyn BalanceFetcher,
    chain: Chain,
    addr: Address,
) -> Option<(Address, bool)> {
    for slot in SLOTS {
        let slot_u256 = U256::from_be_bytes(slot.0);
        match net.get_storage_at(addr, slot_u256, chain).await {
            Ok(read) => {
                if let Some(impl_addr) = address_from_slot(read.value) {
                    return Some((impl_addr, read.verified));
                }
            }
            Err(_) => continue,
        }
    }
    None
}

/// ERC-1167 minimal-proxy runtime, split around the 20-byte target it embeds:
/// `363d3d373d3d3d363d73 ‖ <impl> ‖ 5af43d82803e903d91602b57fd5bf3`.
const ERC1167_PREFIX: [u8; 10] = [0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
const ERC1167_SUFFIX: [u8; 15] = [
    0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3,
];

/// The implementation an ERC-1167 minimal proxy delegates to, read straight out
/// of its runtime bytecode.
///
/// A clone carries its target as 20 literal bytes in the middle of a fixed
/// 45-byte body — there is no storage slot, so [`resolve_implementation`] can
/// never find one, and the clone's own dispatcher exposes no selectors at all.
/// That combination is what surfaced OpenZeppelin `Clones` deployments as an
/// undifferentiated "no ABI found". Recovering the target costs no RPC call and
/// no trust: the pointer is in code the caller already fetched.
pub fn erc1167_target(code: &[u8]) -> Option<Address> {
    if code.len() != ERC1167_PREFIX.len() + 20 + ERC1167_SUFFIX.len() {
        return None;
    }
    if !code.starts_with(&ERC1167_PREFIX) || !code.ends_with(&ERC1167_SUFFIX) {
        return None;
    }
    let addr = Address::from_slice(&code[ERC1167_PREFIX.len()..ERC1167_PREFIX.len() + 20]);
    (addr != Address::ZERO).then_some(addr)
}

/// EIP-1967 beacon slot:
/// `bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1)`.
const EIP_1967_BEACON_SLOT: B256 = B256::new([
    0xa3, 0xf0, 0xad, 0x74, 0xe5, 0x42, 0x3a, 0xeb, 0xfd, 0x80, 0xd3, 0xef, 0x43, 0x46, 0x57, 0x83,
    0x35, 0xa9, 0xa7, 0x2a, 0xea, 0xee, 0x59, 0xff, 0x6c, 0xb3, 0x58, 0x2b, 0x35, 0x13, 0x3d, 0x50,
]);

/// Whether `addr` is a beacon proxy — a shape this walker recognises but does
/// not follow.
///
/// Resolving a beacon means calling `implementation()` on the beacon contract,
/// which is an `eth_call` rather than a storage read. Until that lands, saying
/// "this is a beacon proxy and Kao doesn't follow those yet" is worth a read on
/// its own: it is the difference between a limitation the user can act on and
/// an empty method list with no explanation.
pub async fn is_beacon_proxy(net: &dyn BalanceFetcher, chain: Chain, addr: Address) -> bool {
    let slot = U256::from_be_bytes(EIP_1967_BEACON_SLOT.0);
    match net.get_storage_at(addr, slot, chain).await {
        // Only a verified read may make this claim: an unverified one would let
        // a hostile RPC label any address a beacon and suppress its real ABI.
        Ok(read) => read.verified && address_from_slot(read.value).is_some(),
        Err(_) => false,
    }
}

/// A storage word holds an address in its rightmost 20 bytes. Treat
/// any non-zero upper bytes as "this slot doesn't hold an address" —
/// that catches the case where a slot keccak'd by an unrelated mapping
/// happens to alias one of our standard slots, and the data isn't a
/// pointer at all.
fn address_from_slot(slot: B256) -> Option<Address> {
    let bytes = slot.as_slice();
    if bytes[..12].iter().any(|b| *b != 0) {
        return None;
    }
    let addr = Address::from_slice(&bytes[12..]);
    if addr == Address::ZERO {
        None
    } else {
        Some(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::keccak256;

    /// A canonical ERC-1167 runtime pointing at `target`.
    fn clone_runtime(target: Address) -> Vec<u8> {
        let mut code = ERC1167_PREFIX.to_vec();
        code.extend_from_slice(target.as_slice());
        code.extend_from_slice(&ERC1167_SUFFIX);
        code
    }

    #[test]
    fn erc1167_target_reads_the_implementation_out_of_the_clone() {
        let target = Address::repeat_byte(0x42);
        let code = clone_runtime(target);
        assert_eq!(code.len(), 45, "the canonical clone runtime is 45 bytes");
        assert_eq!(erc1167_target(&code), Some(target));
    }

    #[test]
    fn erc1167_target_refuses_anything_that_is_not_exactly_a_clone() {
        let target = Address::repeat_byte(0x42);
        // Right shape, wrong length — a longer body is a different contract
        // that merely opens the same way, and its 20 bytes at that offset are
        // not a pointer.
        let mut long = clone_runtime(target);
        long.push(0x00);
        assert!(erc1167_target(&long).is_none());

        let mut short = clone_runtime(target);
        short.pop();
        assert!(erc1167_target(&short).is_none());

        // Prefix matches, suffix doesn't.
        let mut tampered = clone_runtime(target);
        let n = tampered.len();
        tampered[n - 1] = 0x00;
        assert!(erc1167_target(&tampered).is_none());

        // A clone to the zero address delegates nowhere.
        assert!(erc1167_target(&clone_runtime(Address::ZERO)).is_none());

        // Ordinary contract code.
        assert!(erc1167_target(&crate::decode::bytecode::tiny_transfer_runtime()).is_none());
        assert!(erc1167_target(&[]).is_none());
    }

    #[test]
    fn eip1967_beacon_slot_is_the_standard_one() {
        // keccak256("eip1967.proxy.beacon") - 1, same derivation as the
        // implementation slot above.
        let h = keccak256(b"eip1967.proxy.beacon");
        let want = B256::from(U256::from_be_bytes(h.0) - U256::from(1u8));
        assert_eq!(EIP_1967_BEACON_SLOT, want);
    }

    #[test]
    fn keccak_smoketest() {
        // Canonical Keccak-256 of "abc" — pinned in every keccak test
        // suite. Catches a wrong hash function before we reason about
        // EIP-1967.
        let h = keccak256(b"abc");
        let want = B256::new([
            0x4e, 0x03, 0x65, 0x7a, 0xea, 0x45, 0xa9, 0x4f, 0xc7, 0xd4, 0x7b, 0xa8, 0x26, 0xc8,
            0xd6, 0x67, 0xc0, 0xd1, 0xe6, 0xe3, 0x3a, 0x64, 0xa0, 0x36, 0xec, 0x44, 0xf5, 0x8f,
            0xa1, 0x2d, 0x6c, 0x45,
        ]);
        assert_eq!(h, want, "keccak256 of 'abc' diverges from canonical");
    }

    #[test]
    fn eip_1967_impl_slot_matches_definition() {
        // bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1)
        let h = keccak256(b"eip1967.proxy.implementation");
        eprintln!("keccak('eip1967.proxy.implementation') = {h:#x}");
        let as_u256 = U256::from_be_bytes(h.0);
        let minus_one = as_u256 - U256::from(1u8);
        let expected = B256::from(minus_one.to_be_bytes::<32>());
        assert_eq!(expected, EIP_1967_IMPL_SLOT);
    }

    #[test]
    fn zos_impl_slot_matches_definition() {
        let h = keccak256(b"org.zeppelinos.proxy.implementation");
        assert_eq!(h, ZOS_IMPL_SLOT);
    }

    #[test]
    fn address_from_slot_rejects_dirty_upper_bytes() {
        let mut bytes = [0u8; 32];
        // Address only in the bottom 20 bytes is fine.
        bytes[31] = 1;
        assert_eq!(
            address_from_slot(B256::from(bytes)),
            Some(Address::from_slice(&bytes[12..]))
        );
        // Junk in the upper 12 bytes → not a pointer.
        bytes[0] = 0xff;
        assert_eq!(address_from_slot(B256::from(bytes)), None);
    }

    #[test]
    fn address_from_slot_rejects_zero() {
        assert_eq!(address_from_slot(B256::ZERO), None);
    }

    #[test]
    fn address_from_slot_accepts_top_bit_in_low_20_bytes() {
        // Address with 0xff..ff in the low 20 bytes is still a valid
        // 160-bit address — the upper-12-bytes-zero check shouldn't
        // reject it.
        let mut bytes = [0u8; 32];
        for b in &mut bytes[12..] {
            *b = 0xff;
        }
        assert_eq!(
            address_from_slot(B256::from(bytes)),
            Some(Address::from_slice(&bytes[12..]))
        );
    }

    // ----- resolve_implementation tests with a programmable mock ------

    use crate::net::{BalanceFetcher, VerificationStatus, VerifiedRead};
    use alloy::network::Ethereum;
    use alloy::primitives::Bytes;
    use alloy::providers::RootProvider;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Lookup (addr, slot) → stored word, with a verification flag.
    /// Anything not configured returns B256::ZERO (verified=true), which
    /// `address_from_slot` treats as "no proxy here".
    #[derive(Debug, Default)]
    struct StorageMock {
        slots: Mutex<HashMap<(Address, B256), (B256, bool)>>,
    }

    impl StorageMock {
        fn new() -> Self {
            Self::default()
        }
        fn set(&self, addr: Address, slot: B256, value: B256, verified: bool) {
            self.slots
                .lock()
                .unwrap()
                .insert((addr, slot), (value, verified));
        }
    }

    #[async_trait]
    impl BalanceFetcher for StorageMock {
        async fn balance(&self, _: Address, _: Chain) -> Result<String, String> {
            unreachable!("proxy walker doesn't call balance")
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
            addr: Address,
            slot: U256,
            _: Chain,
        ) -> Result<VerifiedRead<B256>, String> {
            let slot_b256 = B256::from(slot.to_be_bytes::<32>());
            let (value, verified) = self
                .slots
                .lock()
                .unwrap()
                .get(&(addr, slot_b256))
                .copied()
                .unwrap_or((B256::ZERO, true));
            Ok(VerifiedRead { value, verified })
        }
        async fn call(
            &self,
            _: Address,
            _: Bytes,
            _: Chain,
        ) -> Result<VerifiedRead<Bytes>, String> {
            Ok(VerifiedRead {
                value: Bytes::new(),
                verified: true,
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
        async fn latest_block(
            &self,
            _: Chain,
        ) -> Result<VerifiedRead<crate::net::LatestBlock>, String> {
            Ok(VerifiedRead {
                value: crate::net::LatestBlock {
                    number: 0,
                    hash: B256::ZERO,
                    timestamp: 0,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: 0,
                    prevrandao: B256::ZERO,
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
        ) -> Result<VerifiedRead<B256>, String> {
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

    fn slot_with_address(addr: Address) -> B256 {
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(addr.as_slice());
        B256::from(bytes)
    }

    #[tokio::test]
    async fn resolve_non_proxy_returns_input() {
        let mock = StorageMock::new();
        let target = Address::from([0x11; 20]);
        let res = resolve_implementation(&mock, Chain::Mainnet, target).await;
        assert_eq!(res.implementation, target);
        assert!(res.hops.is_empty());
        assert!(res.all_verified);
    }

    #[tokio::test]
    async fn resolve_follows_eip1967_slot() {
        let mock = StorageMock::new();
        let proxy_addr = Address::from([0x11; 20]);
        let impl_addr = Address::from([0x22; 20]);
        mock.set(
            proxy_addr,
            EIP_1967_IMPL_SLOT,
            slot_with_address(impl_addr),
            true,
        );
        let res = resolve_implementation(&mock, Chain::Mainnet, proxy_addr).await;
        assert_eq!(res.implementation, impl_addr);
        assert_eq!(res.hops, vec![impl_addr]);
        assert!(res.all_verified);
    }

    #[tokio::test]
    async fn resolve_follows_zos_slot_when_eip1967_empty() {
        let mock = StorageMock::new();
        let proxy_addr = Address::from([0x11; 20]);
        let impl_addr = Address::from([0x33; 20]);
        // EIP_1967 slot stays zero; ZOS slot points to impl.
        mock.set(
            proxy_addr,
            ZOS_IMPL_SLOT,
            slot_with_address(impl_addr),
            true,
        );
        let res = resolve_implementation(&mock, Chain::Mainnet, proxy_addr).await;
        assert_eq!(res.implementation, impl_addr);
        assert_eq!(res.hops, vec![impl_addr]);
    }

    #[tokio::test]
    async fn resolve_unverified_storage_propagates() {
        let mock = StorageMock::new();
        let proxy_addr = Address::from([0x11; 20]);
        let impl_addr = Address::from([0x22; 20]);
        // Slot read came back from the unverified fallback path.
        mock.set(
            proxy_addr,
            EIP_1967_IMPL_SLOT,
            slot_with_address(impl_addr),
            false,
        );
        let res = resolve_implementation(&mock, Chain::Mainnet, proxy_addr).await;
        assert_eq!(res.implementation, proxy_addr);
        assert!(res.hops.is_empty());
        assert!(!res.all_verified, "unverified slot read must flip the flag");
    }

    #[tokio::test]
    async fn resolve_terminates_on_self_pointer() {
        let mock = StorageMock::new();
        let proxy_addr = Address::from([0x11; 20]);
        // Slot points back at the contract itself — explicit cycle.
        // Walker should break without recording a hop.
        mock.set(
            proxy_addr,
            EIP_1967_IMPL_SLOT,
            slot_with_address(proxy_addr),
            true,
        );
        let res = resolve_implementation(&mock, Chain::Mainnet, proxy_addr).await;
        assert_eq!(res.implementation, proxy_addr);
        assert!(res.hops.is_empty());
    }

    #[tokio::test]
    async fn resolve_respects_max_depth() {
        // Build a chain longer than MAX_DEPTH and verify the walker
        // stops at exactly MAX_DEPTH hops without looping forever.
        let mock = StorageMock::new();
        let chain_addrs: Vec<Address> = (0..(MAX_DEPTH + 3))
            .map(|i| Address::from([i as u8 + 1; 20]))
            .collect();
        for pair in chain_addrs.windows(2) {
            mock.set(
                pair[0],
                EIP_1967_IMPL_SLOT,
                slot_with_address(pair[1]),
                true,
            );
        }
        let res = resolve_implementation(&mock, Chain::Mainnet, chain_addrs[0]).await;
        assert_eq!(res.hops.len(), MAX_DEPTH);
        assert_eq!(res.implementation, chain_addrs[MAX_DEPTH]);
    }

    #[tokio::test]
    async fn resolve_eip1967_takes_precedence_over_zos() {
        // Both slots populated; the walker tries EIP-1967 first and
        // returns its impl without consulting ZOS.
        let mock = StorageMock::new();
        let proxy_addr = Address::from([0x11; 20]);
        let modern_impl = Address::from([0x22; 20]);
        let legacy_impl = Address::from([0x33; 20]);
        mock.set(
            proxy_addr,
            EIP_1967_IMPL_SLOT,
            slot_with_address(modern_impl),
            true,
        );
        mock.set(
            proxy_addr,
            ZOS_IMPL_SLOT,
            slot_with_address(legacy_impl),
            true,
        );
        let res = resolve_implementation(&mock, Chain::Mainnet, proxy_addr).await;
        assert_eq!(res.implementation, modern_impl);
    }
}
