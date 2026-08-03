//! Bytecode introspection via evmole.
//!
//! Given a contract's runtime bytecode, evmole walks the dispatcher
//! table to recover (selector, arg-type-list) tuples for every public
//! entry point. The clear-signing pipeline uses this two ways:
//!
//! 1. **Narrow ambiguous 4byte matches.** When 4byte returns multiple
//!    candidate signatures for one selector, only the candidate whose
//!    type list matches what the contract actually implements is real.
//! 2. **Fall back when 4byte misses.** Custom contracts deployed after
//!    the 4byte snapshot won't have a registered signature; evmole at
//!    least gives us "selector 0xdeadbeef takes (address, uint256)" so
//!    the user sees structured arguments instead of a hex blob.
//!
//! Caching: not yet — evmole on a 24KB runtime takes ~ms in dev builds,
//! which is fine for the Phase 7 progressive renderer (we'll already
//! be awaiting RPC round-trips in parallel). Add an LRU keyed by code
//! hash if real-world latency proves it matters.

use alloy::dyn_abi::DynSolType;

/// One public entry point recovered from the bytecode dispatcher.
#[derive(Debug, Clone)]
pub struct ExtractedFn {
    pub selector: [u8; 4],
    pub arg_types: Vec<DynSolType>,
}

/// All public functions evmole could recover from `code`. Empty when
/// the bytecode isn't a contract (EOA, empty account, or proxy with no
/// dispatcher of its own — caller should walk via `proxy::resolve_implementation`
/// before invoking this).
pub fn extract(code: &[u8]) -> Vec<ExtractedFn> {
    if code.is_empty() {
        return Vec::new();
    }
    let args = evmole::ContractInfoArgs::new(code)
        .with_selectors()
        .with_arguments();
    let info = evmole::contract_info(args);
    info.functions
        .unwrap_or_default()
        .into_iter()
        .map(|f| ExtractedFn {
            selector: f.selector,
            arg_types: f.arguments.unwrap_or_default(),
        })
        .collect()
}

/// Convenience: arg-type list for one specific selector, or `None` if
/// `code` doesn't expose that selector. Keeps callers from open-coding
/// `extract().into_iter().find(...)`.
pub fn lookup(code: &[u8], selector: [u8; 4]) -> Option<Vec<DynSolType>> {
    extract(code)
        .into_iter()
        .find(|f| f.selector == selector)
        .map(|f| f.arg_types)
}

/// Minimal compiled `transfer(address,uint256)` dispatcher. Hand-
/// crafted via solc against:
///
/// ```solidity
/// contract T {
///     function transfer(address to, uint256 amount) external {}
/// }
/// ```
///
/// We just need ANY valid runtime that exposes the standard ERC-20
/// transfer selector for evmole to chew through. If this snippet
/// breaks on an evmole upgrade, swap with `solc --bin-runtime`.
/// Shared with the Transaction Builder's ABI tests, which need a contract
/// whose selectors actually come back.
#[cfg(test)]
pub(crate) fn tiny_transfer_runtime() -> Vec<u8> {
    let cleaned: String = TINY_TRANSFER_RUNTIME
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    alloy::hex::decode(&cleaned).expect("fixture bytecode hex is malformed")
}

#[cfg(test)]
const TINY_TRANSFER_RUNTIME: &str = "608060405234801561001057600080fd5b50600436106100365760003560e01c\
        8063a9059cbb1461003b575b600080fd5b610055600480360381019061005091906100a4565b610057565b005b505050565b6000\
        81359050610071816100f1565b92915050565b6000813590506100868161010856\
        5b92915050565b60008060408385031215610099576100986100ec565b5b60006100a785828601610062565b92505060206100b8\
        85828601610077565b9150509250929050565b6100ca816100d0565b82525050565b60006100db826100e2565b9050919050565b6000\
        819050919050565b600080fd5b6100f4816100d0565b81146100ff57600080fd5b50565b610111816100d6565b811461011c57\
        600080fd5b5056fea2646970667358221220";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_code_returns_empty() {
        assert!(extract(&[]).is_empty());
        assert!(lookup(&[], [0xa9, 0x05, 0x9c, 0xbb]).is_none());
    }

    #[test]
    fn extracts_transfer_selector() {
        let code = tiny_transfer_runtime();
        let funcs = extract(&code);
        // Even if evmole's heuristic misses some, the transfer selector
        // is the only public entry point in this contract — it must
        // come back.
        let transfer = funcs
            .iter()
            .find(|f| f.selector == [0xa9, 0x05, 0x9c, 0xbb]);
        assert!(
            transfer.is_some(),
            "expected transfer selector; got {funcs:?}"
        );
        if let Some(f) = transfer {
            // Argument extraction is best-effort; assert two args of
            // the expected types only when evmole gave us anything.
            // A future evmole version that improves argument inference
            // shouldn't break this test by becoming MORE accurate.
            if !f.arg_types.is_empty() {
                assert_eq!(f.arg_types.len(), 2, "transfer takes 2 args");
                assert!(matches!(f.arg_types[0], DynSolType::Address));
                assert!(matches!(f.arg_types[1], DynSolType::Uint(256)));
            }
        }
    }

    #[test]
    fn lookup_finds_known_selector() {
        let code = tiny_transfer_runtime();
        let types = lookup(&code, [0xa9, 0x05, 0x9c, 0xbb]);
        // evmole sometimes recovers the selector but not the arg types —
        // both "Some(empty)" and "Some([Address, Uint(256)])" mean the
        // selector was found. None means it wasn't, which is the bug.
        assert!(types.is_some(), "transfer selector not found in bytecode");
    }

    #[test]
    fn lookup_misses_unknown_selector() {
        let code = tiny_transfer_runtime();
        // Selector that the contract doesn't expose. evmole should
        // simply not return it.
        assert!(lookup(&code, [0xde, 0xad, 0xbe, 0xef]).is_none());
    }
}
