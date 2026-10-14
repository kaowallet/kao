//! Safe-transaction primitives — build, hash, sign, pack, and execute
//! a Safe 1.3+ multisig transaction.
//!
//! This module is the layer below the UI. It exposes:
//!
//! - `SafeTxInput` — ergonomic builder input (recipient + value + calldata).
//! - `current_safe_nonce` / `build_safe_tx_with_nonce` — read the Safe's
//!   authoritative on-chain nonce, then assemble a fully-populated
//!   `SafeTx` (relay fields zeroed) at that *pinned* nonce. Split on
//!   purpose: the nonce is read once at review time and carried through
//!   to signing, so the user only ever signs the hash they verified.
//! - `safe_tx_hash` — local EIP-712 signing hash.
//! - `verify_safe_tx_hash_on_chain` / `verify_domain_separator_on_chain` —
//!   cross-checks against the Safe's own `getTransactionHash` /
//!   `domainSeparator` views. Defense-in-depth before signing.
//! - `pack_owner_signatures` — Safe's wire format: 65-byte `r ‖ s ‖ v`
//!   per owner, sorted ascending by signer address, concatenated.
//! - `execute_safe_tx` — ABI-encodes `execTransaction`, builds an
//!   EIP-1559 envelope from the executor EOA, signs it via
//!   `KaoSigner::sign_tx`, and broadcasts.
//!
//! Out of scope (this slice): UI, hardware EIP-712 signing,
//! Safe Transaction Service integration, `contractSignatures`
//! (nested-Safe-as-signer), module txs, DelegateCall, gas-refund
//! parameters, and ERC-20/721 calldata building.

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::Encodable2718;
use alloy::network::Ethereum;
use alloy::primitives::{Address, B256, Bytes, Signature, TxHash, TxKind, U256};
use alloy::providers::{Provider, RootProvider};
use alloy::sol_types::{Eip712Domain, SolCall, SolStruct};

use crate::chain::Chain;
use crate::net::BalanceFetcher;
use crate::wallet::KaoSigner;

use super::{
    SafeTx, decode_ret, domainSeparatorCall, execTransactionCall, getTransactionHashCall, nonceCall,
};

/// Safe-spec operation byte.
///
/// `DelegateCall` runs the target's code under the Safe's own identity and
/// storage — a foot-gun in general, since a delegatecall to an attacker
/// contract can rewrite the Safe's owners. It is therefore NEVER offered as
/// a free-form choice in any UI. The single sanctioned use is the
/// Transaction Builder's atomic-batch path, which delegatecalls *only* the
/// canonical, audited `MultiSendCallOnly` library (a fixed known address,
/// verified to have code on-chain before signing) — see
/// [`crate::txbuilder::multisend`]. `MultiSendCallOnly` restricts its own
/// inner operations to plain `Call`, so the Safe's storage is never
/// mutated by the delegatecall itself.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Call = 0,
    DelegateCall = 1,
}

/// Ergonomic input for [`build_safe_tx_with_nonce`] — the
/// caller-expressible half of a SafeTx (target, value, calldata, op).
/// The nonce is always supplied explicitly: callers read it via
/// [`current_safe_nonce`] at review time and pin it through to signing,
/// so the hash the user verified is the only hash that can be signed.
#[derive(Debug, Clone)]
pub struct SafeTxInput {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub operation: Operation,
}

/// Build the Safe 1.3+ EIP-712 domain.
///
/// Per Safe spec since 1.3.0: `EIP712Domain(uint256 chainId, address
/// verifyingContract)` — chainId and verifyingContract only; no name,
/// no version, no salt. Pre-1.3 Safes used a different shape
/// (`EIP712Domain(address verifyingContract)`) and aren't supported —
/// `SafeTrust::Canonical` only certifies 1.3.0+.
pub fn safe_domain(safe: Address, chain: Chain) -> Eip712Domain {
    Eip712Domain {
        name: None,
        version: None,
        chain_id: Some(U256::from(chain.chain_id())),
        verifying_contract: Some(safe),
        salt: None,
    }
}

/// Local EIP-712 signing hash for a SafeTx —
/// `keccak256(0x1901 ‖ domainSeparator ‖ hashStruct(tx))`. This is
/// the same 32 bytes the Safe contract recovers signatures against
/// inside `checkSignatures`.
///
/// Correctness leans entirely on the `SafeTx` struct's field order in
/// `safe::mod`'s `sol!` block matching the Safe 1.3+ canonical
/// typehash. `safe_tx_typehash_matches_spec` pins that.
pub fn safe_tx_hash(tx: &SafeTx, domain: &Eip712Domain) -> B256 {
    tx.eip712_signing_hash(domain)
}

/// Pack owner signatures into the `bytes signatures` argument
/// `execTransaction` expects.
///
/// Wire format: `concat(s_1 ‖ s_2 ‖ … ‖ s_k)` where each `s_i` is
/// 65 bytes `r ‖ s ‖ v` and the signatures are SORTED ASCENDING by
/// recovered signer address. Safe's `checkSignatures` rejects with
/// `GS026` if the recovered addresses aren't monotonically
/// increasing, so unsorted packing is a silent revert at submit.
///
/// `v` byte meanings inside Safe's checkSignatures:
/// - `27` / `28` → EIP-712 signature over the SafeTx hash (our case).
/// - `31` / `32` → eth_sign (EIP-191) signature.
/// - `0` → smart-contract signature (contractSignatures /
///   nested-Safe-as-owner). **Not supported in v1** — any nested-Safe
///   owner hits `UnsupportedOperation` in `KaoSigner::sign_hash`.
///   Follow-up PR.
/// - `1` → pre-validated signature.
///
/// We emit the {27, 28} variant exclusively. alloy's
/// `Signature::as_bytes` writes `r ‖ s ‖ (27 + y_parity)` directly,
/// so we copy its 65 bytes verbatim.
///
/// Errors on a duplicate signer address. Two signatures from the same
/// owner only count once inside `checkSignatures`, so the blob would
/// carry fewer distinct approvals than the threshold requires and
/// revert on-chain (`GS026`) after gas was paid — and silently
/// dropping one here would mask the real problem (the caller selected
/// the same owner twice, e.g. one key imported into two account
/// slots). Fail loudly before anything leaves the wallet.
///
/// The production send/queue paths now pack via [`assemble_signatures`]
/// (raw blobs, so they also carry `eth_sign` fallbacks); this typed
/// variant is retained as the reference the equivalence tests pin
/// `sign_owner`/`sign_eip712` output against.
#[allow(dead_code)]
pub fn pack_owner_signatures(mut sigs: Vec<(Address, Signature)>) -> Result<Bytes, String> {
    // `Address` is a `FixedBytes<20>`; its `Ord` impl is lexicographic
    // byte order, which is also numeric big-endian order — matching
    // what Safe sorts on.
    sigs.sort_by_key(|(addr, _)| *addr);
    ensure_distinct_signers(sigs.iter().map(|(a, _)| *a))?;
    let mut out = Vec::with_capacity(sigs.len() * 65);
    for (_, sig) in sigs {
        out.extend_from_slice(&sig.as_bytes());
    }
    Ok(Bytes::from(out))
}

/// Reject adjacent duplicates in an already-sorted signer sequence.
/// Shared guard for [`pack_owner_signatures`] / [`assemble_signatures`].
fn ensure_distinct_signers(sorted: impl Iterator<Item = Address>) -> Result<(), String> {
    let mut prev: Option<Address> = None;
    for addr in sorted {
        if prev == Some(addr) {
            return Err(format!(
                "duplicate signature from owner {} — each owner counts once toward the threshold",
                crate::wallet::short_address(addr),
            ));
        }
        prev = Some(addr);
    }
    Ok(())
}

/// Read the AUTHORITATIVE Safe nonce on chain. The cached
/// `SafeDescriptor.nonce` snapshot is stale by definition at sign
/// time — any other co-signer's executed tx will have bumped the
/// contract's nonce without going through this client. Always
/// re-read before quoting.
///
/// Returns `u64` because real Safes never approach overflow (one
/// increment per `execTransaction`); the `try_from` cast guards
/// against a pathological return rather than truncating silently.
pub async fn current_safe_nonce(
    net: &dyn BalanceFetcher,
    safe: Address,
    chain: Chain,
) -> Result<u64, String> {
    let calldata = nonceCall {}.abi_encode();
    let ret = net.call_raw(safe, Bytes::from(calldata), chain).await?;
    let n = decode_ret::<nonceCall>(&ret.value)?;
    u64::try_from(n).map_err(|_| format!("safe nonce overflows u64: {n}"))
}

/// Cross-check the local `safe_tx_hash` against the Safe's own
/// `getTransactionHash` view. Defense-in-depth before signing: a
/// divergence means either we built the domain/fields wrong or the
/// contract isn't actually the Safe we believe it is — caller MUST
/// refuse to sign on mismatch.
///
/// Uses `call_raw` (skips helios). The trust posture matches the
/// rest of the read-only Safe inspection: if a malicious RPC lies
/// about the contract's reply, it gains nothing it doesn't already
/// have via broadcast censorship; a quiet agreement between local
/// and remote rules out our own field-order or domain mistakes.
pub async fn verify_safe_tx_hash_on_chain(
    net: &dyn BalanceFetcher,
    tx: &SafeTx,
    safe: Address,
    chain: Chain,
) -> Result<B256, String> {
    let calldata = getTransactionHashCall {
        to: tx.to,
        value: tx.value,
        data: tx.data.clone(),
        operation: tx.operation,
        safeTxGas: tx.safeTxGas,
        baseGas: tx.baseGas,
        gasPrice: tx.gasPrice,
        gasToken: tx.gasToken,
        refundReceiver: tx.refundReceiver,
        _nonce: tx.nonce,
    }
    .abi_encode();
    let ret = net.call_raw(safe, Bytes::from(calldata), chain).await?;
    decode_ret::<getTransactionHashCall>(&ret.value)
}

/// Cross-check the locally-built EIP-712 domain separator against the
/// Safe's own `domainSeparator()` view. Companion to
/// [`verify_safe_tx_hash_on_chain`], same trust posture.
///
/// A mismatch means the contract derives its domain differently than we
/// do — most commonly a pre-1.3 Safe (whose domain omits `chainId`), a
/// proxy pointing at something that isn't the Safe we classified, or a
/// chain-id confusion. All of those are "do not sign" conditions: a
/// signature over our domain would either be rejected by the contract
/// or, worse, be valid somewhere we didn't intend.
pub async fn verify_domain_separator_on_chain(
    net: &dyn BalanceFetcher,
    safe: Address,
    chain: Chain,
) -> Result<(), String> {
    let local = safe_domain(safe, chain).separator();
    let calldata = domainSeparatorCall {}.abi_encode();
    let ret = net.call_raw(safe, Bytes::from(calldata), chain).await?;
    let on_chain = decode_ret::<domainSeparatorCall>(&ret.value)?;
    if local == on_chain {
        Ok(())
    } else {
        Err(format!(
            "safe domain separator mismatch: local {local:#x} vs on-chain {on_chain:#x} — refusing to sign",
        ))
    }
}

/// Run BOTH pre-sign cross-checks against the live contract: the domain
/// separator and the full `getTransactionHash` for `tx`. `local_hash`
/// is the hash the caller is about to put in front of a signer; any
/// divergence aborts before a signature exists.
///
/// The two checks overlap (the tx hash commits to the domain) but fail
/// differently: a domain mismatch pinpoints "wrong domain shape /
/// wrong chain / pre-1.3 Safe", while a tx-hash mismatch with a clean
/// domain points at field encoding. Two reads per signing action is
/// cheap next to a multisig signature that can't be unsigned.
pub async fn verify_safe_tx_before_signing(
    net: &dyn BalanceFetcher,
    tx: &SafeTx,
    safe: Address,
    chain: Chain,
    local_hash: B256,
) -> Result<(), String> {
    verify_domain_separator_on_chain(net, safe, chain).await?;
    let chain_hash = verify_safe_tx_hash_on_chain(net, tx, safe, chain).await?;
    if local_hash != chain_hash {
        return Err(format!(
            "safe hash mismatch: local {local_hash:#x} vs on-chain {chain_hash:#x}",
        ));
    }
    Ok(())
}

/// Gate signing on Safe versions whose EIP-712 domain shape we
/// actually implement. [`safe_domain`] hardcodes the 1.3+ form
/// `EIP712Domain(uint256 chainId, address verifyingContract)`; signing
/// for anything older would silently produce a hash over the wrong
/// domain (pre-1.3 omits `chainId`), and anything newer than the
/// allowlist cap might change the shape again. The on-chain checks in
/// [`verify_safe_tx_before_signing`] would catch both live — this guard
/// turns that late opaque mismatch into an early, explainable refusal.
///
/// Accepts exactly `1.{3,4,5}.N` (digits-only patch), mirroring the
/// `KNOWN_SINGLETONS` range in `safe::mod`. Bump together with that
/// registry and the allowlist cap when Safe ships a new minor.
pub fn ensure_signable_version(version: &str) -> Result<(), String> {
    let mut parts = version.split('.');
    let ok = parts.next() == Some("1")
        && matches!(parts.next(), Some("3" | "4" | "5"))
        && parts
            .next()
            .is_some_and(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && parts.next().is_none();
    if ok {
        Ok(())
    } else {
        Err(format!(
            "Safe version \"{version}\" is outside the signable range (1.3.0 – 1.5.x): \
             its EIP-712 domain may differ from the one Kao signs, so signing is disabled",
        ))
    }
}

/// Assemble a `SafeTx` from `input` at an explicit `nonce`. Pure — no
/// network. All relay-flow fields (`safeTxGas`, `baseGas`, `gasPrice`,
/// `gasToken`, `refundReceiver`) are zero; the contract's
/// `execTransaction` treats them as no-ops when `gasPrice == 0`.
pub fn build_safe_tx_with_nonce(input: SafeTxInput, nonce: u64) -> SafeTx {
    SafeTx {
        to: input.to,
        value: input.value,
        data: input.data,
        operation: input.operation as u8,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: Address::ZERO,
        nonce: U256::from(nonce),
    }
}

/// Build the canonical Safe *rejection* transaction for `nonce`: a
/// zero-value, empty-calldata call to the Safe itself. Executing it
/// consumes `nonce`, voiding whatever else was queued at that nonce.
/// The Transaction Service recognizes a same-nonce self-call as an
/// on-chain rejection and labels it as such.
pub fn build_rejection_tx(safe: Address, nonce: u64) -> SafeTx {
    build_safe_tx_with_nonce(
        SafeTxInput {
            to: safe,
            value: U256::ZERO,
            data: Bytes::new(),
            operation: Operation::Call,
        },
        nonce,
    )
}

/// Concatenate already-encoded per-owner signature blobs into the
/// `bytes signatures` argument `execTransaction` expects, sorted ascending
/// by signer address (Safe's `checkSignatures` requirement; see
/// [`pack_owner_signatures`]).
///
/// Unlike `pack_owner_signatures`, the inputs are *raw bytes*, not
/// `Signature`s — so this can mix EIP-712 (`v∈{27,28}`), `eth_sign`
/// (`v∈{31,32}`), and signatures pulled verbatim from the Transaction
/// Service (the execute-from-queue path). Each blob is whatever the
/// signer produced; for ECDSA owners that's 65 bytes.
///
/// Same duplicate-owner guard as [`pack_owner_signatures`]: a service
/// record (or caller bug) carrying two confirmations from one owner
/// would revert `GS026` on-chain — refuse before broadcasting.
pub fn assemble_signatures(mut sigs: Vec<(Address, Bytes)>) -> Result<Bytes, String> {
    sigs.sort_by_key(|(addr, _)| *addr);
    ensure_distinct_signers(sigs.iter().map(|(a, _)| *a))?;
    let mut out = Vec::with_capacity(sigs.iter().map(|(_, b)| b.len()).sum());
    for (_, b) in sigs {
        out.extend_from_slice(&b);
    }
    Ok(Bytes::from(out))
}

/// How an owner signs a Safe hash (a `SafeTx`'s, or a `SafeMessage`'s): as
/// EIP-712 typed data (`v ∈ {27,28}`), or as an EIP-191 personal message over
/// the 32-byte hash — `eth_sign`, `v ∈ {31,32}`, which Safe's
/// `checkSignatures` accepts as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OwnerSigMode {
    /// EIP-712, falling back to `eth_sign` on any EIP-712 failure — including
    /// right after a device showed the EIP-712 prompt and the user declined it.
    /// How the Safe send, CoW, name-service and Transaction Builder flows sign.
    #[default]
    Auto,
    /// EIP-712, falling back to `eth_sign` only when nothing was shown on a
    /// device ([`crate::wallet::Eip712Failure::Unavailable`]: a Trezor, an old
    /// Ledger app). A device that showed the EIP-712 prompt and refused it ends
    /// the attempt with [`OwnerSigError::eip712_refused`]: a second, different
    /// prompt for the same hash is for the user to ask for, never automatic.
    Eip712,
    /// `eth_sign` only, with no EIP-712 attempt — what the user asks for after
    /// their device refused EIP-712.
    EthSign,
}

/// Why an owner signature wasn't produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerSigError {
    /// What to show the user.
    pub text: String,
    /// The owner's device showed the EIP-712 prompt and refused it (declined, or
    /// Blind signing is off), and — in [`OwnerSigMode::Eip712`] — no `eth_sign`
    /// prompt followed.
    pub eip712_refused: bool,
}

impl OwnerSigError {
    fn failed(text: String) -> Self {
        Self {
            text,
            eip712_refused: false,
        }
    }
}

impl From<OwnerSigError> for String {
    fn from(e: OwnerSigError) -> Self {
        e.text
    }
}

impl std::fmt::Display for OwnerSigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// One owner's 65-byte Safe signature over `hash`, in `mode`: `eip712` asks for
/// the EIP-712 signature (`v ∈ {27,28}`), `eth_sign` for the EIP-191
/// personal-message signature over `hash`, whose `v` is bumped to `{31,32}`.
/// Each is asked at most once, and `eth_sign` never follows an EIP-712 prompt a
/// device refused unless `mode` is [`OwnerSigMode::Auto`].
pub(crate) async fn owner_sig_bytes<E, M>(
    mode: OwnerSigMode,
    eip712: impl FnOnce() -> E,
    eth_sign: impl FnOnce() -> M,
) -> Result<Bytes, OwnerSigError>
where
    E: std::future::Future<Output = Result<Signature, alloy::signers::Error>>,
    M: std::future::Future<Output = Result<Signature, alloy::signers::Error>>,
{
    use crate::wallet::{Eip712Failure, classify_eip712_failure, friendly_signer_error};
    let eth_sign = || async move {
        let sig = eth_sign()
            .await
            .map_err(|e| OwnerSigError::failed(friendly_signer_error(&e)))?;
        let mut bytes = sig.as_bytes().to_vec();
        // 65-byte r‖s‖v; `as_bytes` writes v = 27 + parity. Safe reads
        // v∈{31,32} as "eth_sign over the hash", so +4.
        bytes[64] += 4;
        Ok(Bytes::from(bytes))
    };
    if mode == OwnerSigMode::EthSign {
        return eth_sign().await;
    }
    let eip712_err = match eip712().await {
        Ok(sig) => return Ok(Bytes::from(sig.as_bytes().to_vec())),
        Err(e) => e,
    };
    let class = classify_eip712_failure(&eip712_err);
    if mode == OwnerSigMode::Auto || class == Eip712Failure::Unavailable {
        // EIP-712 failing is the expected trigger for the fallback (Trezor, older
        // Ledger app versions), so its error isn't the actionable one: surface the
        // eth_sign attempt's (already-friendly) error if that also fails, rather
        // than a confusing "both failed" carrying the raw status word twice.
        tracing::debug!(error = %eip712_err, ?mode, "safe owner eip712 sign failed; falling back to eth_sign");
        return eth_sign().await;
    }
    tracing::debug!(error = %eip712_err, ?class, "safe owner eip712 sign failed; no eth_sign fallback");
    Err(OwnerSigError {
        text: friendly_signer_error(&eip712_err),
        eip712_refused: class == Eip712Failure::DeviceRefused,
    })
}

/// Sign a `SafeTx` as an owner — EIP-712, with the `eth_sign` fallback `mode`
/// allows. Returns the `(owner, wire-blob)` pair for [`assemble_signatures`].
/// The single entry point the execute / propose / confirm / reject flows use.
pub async fn sign_owner(
    signer: &KaoSigner,
    tx: &SafeTx,
    domain: &Eip712Domain,
    safe_tx_hash: B256,
    mode: OwnerSigMode,
) -> Result<(Address, Bytes), OwnerSigError> {
    let blob = owner_sig_bytes(
        mode,
        || signer.sign_eip712(tx, domain),
        || signer.sign_eth_message(safe_tx_hash.as_slice()),
    )
    .await?;
    Ok((signer.address(), blob))
}

/// ABI-encode the `execTransaction(...)` calldata for `tx` with the
/// packed `signatures` blob. Pure compute — no provider, no signer.
/// Split out from `execute_safe_tx` so the encoding step is unit-
/// testable independently of the broadcast plumbing.
pub fn encode_exec_transaction(tx: &SafeTx, signatures: Bytes) -> Bytes {
    Bytes::from(
        execTransactionCall {
            to: tx.to,
            value: tx.value,
            data: tx.data.clone(),
            operation: tx.operation,
            safeTxGas: tx.safeTxGas,
            baseGas: tx.baseGas,
            gasPrice: tx.gasPrice,
            gasToken: tx.gasToken,
            refundReceiver: tx.refundReceiver,
            signatures,
        }
        .abi_encode(),
    )
}

/// Build an EIP-1559 envelope from `executor` to the Safe address
/// carrying `execTransaction(...)` calldata, sign, and broadcast.
///
/// `executor` is the EOA paying gas. In v1's solo path this is one
/// of the linked owner accounts, but the Safe contract validates
/// signatures against the owner set rather than `msg.sender`, so any
/// account willing to relay a pre-signed bundle works.
///
/// The envelope's `value` is always zero — `execTransaction` doesn't
/// use `msg.value` for the inner transfer; the Safe sends `tx.value`
/// from its own balance during the internal call.
///
/// Mirrors the build → sign → broadcast pattern in
/// `wallet::tx::sign_and_send` rather than refactoring that fn to
/// take a `(to, value, input)` triple. Convergence is a later PR
/// once the Safe-mode Send UI lands and the shape stabilizes.
pub async fn execute_safe_tx(
    provider: &RootProvider<Ethereum>,
    executor: &KaoSigner,
    safe: Address,
    chain: Chain,
    tx: SafeTx,
    signatures: Bytes,
) -> Result<TxHash, String> {
    execute_safe_tx_guarded(provider, executor, safe, chain, tx, signatures, None)
        .await
        .map(|sent| sent.hash)
        .map_err(ExecSendError::into_text)
}

/// Why [`execute_safe_tx_guarded`] stopped: before the executor's signed
/// transaction left the wallet, or after it was handed to the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecSendError {
    /// Nothing left the wallet — no signatures, a read failed, the executor
    /// declined, or `before_send` refused. Trying again is a fresh attempt.
    NotSent(String),
    /// `eth_sendRawTransaction` was attempted and no hash came back. A reply
    /// lost on its way back (a dropped Tor circuit, a timeout) looks exactly
    /// like this, so the node may well have the transaction. `raw` is the
    /// executor's exact signed envelope, `hash` its hash and `nonce` the
    /// executor nonce it was signed at. Sending `raw` again is idempotent;
    /// executing again is not — it signs a second, distinct transaction at the
    /// executor's next nonce, which reverts once the first is mined.
    Unconfirmed {
        hash: TxHash,
        raw: Bytes,
        nonce: u64,
        msg: String,
    },
}

/// The executor's transaction the node took: its hash, and the account and the nonce it was
/// signed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecSent {
    pub hash: TxHash,
    pub from: Address,
    pub nonce: u64,
}

impl ExecSendError {
    /// The user-facing text — exactly what [`execute_safe_tx`] returns for it.
    pub fn into_text(self) -> String {
        match self {
            Self::NotSent(msg) | Self::Unconfirmed { msg, .. } => msg,
        }
    }
}

/// [`execute_safe_tx`] with a liveness hook: `before_send` runs after
/// `executor.sign_tx` (the executor envelope is signed) and before
/// `send_raw_transaction`; an `Err` discards the envelope and returns that
/// text — nothing is broadcast. WalletConnect passes the request's
/// [`crate::sign::broadcast::BeforeSend`] so a Safe transaction the dapp
/// stopped waiting for is never executed.
///
/// A failure is told apart by whether the executor's transaction was handed
/// to the node ([`ExecSendError`]); the texts are [`execute_safe_tx`]'s.
pub async fn execute_safe_tx_guarded(
    provider: &RootProvider<Ethereum>,
    executor: &KaoSigner,
    safe: Address,
    chain: Chain,
    tx: SafeTx,
    signatures: Bytes,
    before_send: Option<&crate::sign::broadcast::BeforeSend>,
) -> Result<ExecSent, ExecSendError> {
    use ExecSendError::NotSent;
    if signatures.is_empty() {
        // Safe reverts GS020 ("Signatures data too short") on empty
        // input — reject upfront so the user sees a clear error
        // instead of an opaque revert after paying gas.
        return Err(NotSent("safe-tx: no signatures provided".to_string()));
    }

    let calldata = encode_exec_transaction(&tx, signatures);

    let from = executor.address();
    let req = alloy::rpc::types::TransactionRequest::default()
        .from(from)
        .to(safe)
        .input(alloy::rpc::types::TransactionInput::new(calldata.clone()));
    // Alloy transport errors `Display` the full request URL, which for the
    // execution RPC embeds the API key in its path/query (Alchemy, dRPC). These
    // strings flow to warn! logs and the sign-review overlay, so scrub URLs down
    // to the host before they leave here — matching the redaction discipline in
    // `net.rs` and `safe/service.rs`.
    let gas_limit = provider.estimate_gas(req).await.map_err(|e| {
        NotSent(format!(
            "estimate_gas: {}",
            crate::net::redact_urls(&e.to_string())
        ))
    })?;
    let fees = provider.estimate_eip1559_fees().await.map_err(|e| {
        NotSent(format!(
            "estimate_eip1559_fees: {}",
            crate::net::redact_urls(&e.to_string())
        ))
    })?;
    let nonce = provider
        .get_transaction_count(from)
        .pending()
        .await
        .map_err(|e| {
            NotSent(format!(
                "get_transaction_count: {}",
                crate::net::redact_urls(&e.to_string())
            ))
        })?;

    let mut envelope = TxEip1559 {
        chain_id: chain.chain_id(),
        nonce,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: TxKind::Call(safe),
        value: U256::ZERO,
        access_list: Default::default(),
        input: calldata,
    };
    let sig = executor
        .sign_tx(&mut envelope)
        .await
        .map_err(|e| NotSent(crate::wallet::friendly_signer_error(&e)))?;
    if let Some(check) = before_send {
        check().map_err(NotSent)?;
    }
    // The hash is the signed envelope's own, taken before it is encoded: a
    // failure from here on has to name the transaction that may be on its way.
    let signed = envelope.into_signed(sig);
    let hash = *signed.hash();
    let raw = TxEnvelope::from(signed).encoded_2718();
    let pending = provider.send_raw_transaction(&raw).await.map_err(|e| {
        let msg = crate::net::redact_urls(&e.to_string());
        tracing::warn!(
            error = %msg,
            hash = %format!("{hash:#x}"),
            "safe-tx: executor broadcast failed; the node may still have the transaction",
        );
        // Whatever the error says, the request was on the wire: from here the
        // transaction's fate is unknown, never "not sent".
        ExecSendError::Unconfirmed {
            hash,
            raw: Bytes::from(raw.clone()),
            nonce,
            msg: format!("{}: {msg}", crate::sign::broadcast::BROADCAST_FAILED),
        }
    })?;
    Ok(ExecSent {
        hash: *pending.tx_hash(),
        from,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{address, b256, keccak256};
    use alloy::signers::Signer;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::sol_types::{SolCall, SolValue};

    use crate::net::CallMock;

    fn safe_addr() -> Address {
        address!("0x1111111111111111111111111111111111111111")
    }

    fn empty_safe_tx() -> SafeTx {
        SafeTx {
            to: Address::ZERO,
            value: U256::ZERO,
            data: Bytes::new(),
            operation: 0,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasToken: Address::ZERO,
            refundReceiver: Address::ZERO,
            nonce: U256::ZERO,
        }
    }

    #[test]
    fn safe_tx_typehash_matches_spec() {
        // Re-derive the canonical Safe 1.3+ SafeTx typehash from the
        // type-encoding string. If the `sol!` struct fields ever
        // drift out of canonical order, alloy's `eip712_encode_type`
        // diverges and this fails before any silent
        // wrong-hash signing can happen.
        let canonical = b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";
        let expected = keccak256(canonical);
        let encoded = <SafeTx as SolStruct>::eip712_encode_type();
        assert_eq!(encoded.as_bytes(), canonical);
        let derived = empty_safe_tx().eip712_type_hash();
        assert_eq!(derived, expected);
        // Pin the literal so a change to the canonical string is
        // visible at code-review time.
        assert_eq!(
            expected,
            b256!("0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8"),
        );
    }

    #[test]
    fn safe_domain_separator_matches_chain_id_and_safe() {
        // Manual derivation of the Safe 1.3+ domain separator:
        //   keccak256(abi.encode(
        //     keccak256("EIP712Domain(uint256 chainId,address verifyingContract)"),
        //     chainId,
        //     verifyingContract))
        let safe = safe_addr();
        let chain = Chain::Mainnet;
        let domain_typehash = keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)");
        let chain_id = U256::from(chain.chain_id());
        let manual = keccak256((domain_typehash, chain_id, safe).abi_encode());
        let derived = safe_domain(safe, chain).separator();
        assert_eq!(derived, manual);
        // Pin the domain typehash too.
        assert_eq!(
            domain_typehash,
            b256!("0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218"),
        );
    }

    #[test]
    fn safe_tx_hash_differs_for_different_chain_id() {
        let safe = safe_addr();
        let tx = empty_safe_tx();
        let h_mainnet = safe_tx_hash(&tx, &safe_domain(safe, Chain::Mainnet));
        let h_base = safe_tx_hash(&tx, &safe_domain(safe, Chain::Base));
        assert_ne!(
            h_mainnet, h_base,
            "same SafeTx must produce different hashes on different chains (cross-chain replay protection)",
        );
    }

    #[test]
    fn operation_call_byte_is_zero() {
        assert_eq!(Operation::Call as u8, 0);
    }

    async fn sig_for(hash: B256, signer: &PrivateKeySigner) -> (Address, Signature) {
        let sig = signer.sign_hash(&hash).await.unwrap();
        (signer.address(), sig)
    }

    #[tokio::test]
    async fn pack_owner_signatures_handles_single_signer() {
        let s = PrivateKeySigner::random();
        let hash = B256::repeat_byte(0xab);
        let pair = sig_for(hash, &s).await;
        let bytes = pack_owner_signatures(vec![pair]).unwrap();
        assert_eq!(bytes.len(), 65);
        assert!(matches!(bytes[64], 27 | 28));
    }

    #[tokio::test]
    async fn pack_owner_signatures_sorts_by_address_ascending() {
        // Generate two signers and order them by address so we
        // know which one is "lower".
        let (lo, hi) = loop {
            let a = PrivateKeySigner::random();
            let b = PrivateKeySigner::random();
            if a.address() < b.address() {
                break (a, b);
            }
            if a.address() > b.address() {
                break (b, a);
            }
            // ridiculously unlikely tie — re-roll
        };
        let hash = B256::repeat_byte(0xcd);
        let pair_lo = sig_for(hash, &lo).await;
        let pair_hi = sig_for(hash, &hi).await;

        // Feed in HIGH-then-LOW order; expect packing to swap them.
        let bytes = pack_owner_signatures(vec![pair_hi, pair_lo]).unwrap();
        assert_eq!(bytes.len(), 130);
        // First 65 bytes should be the low-address signer's signature.
        assert_eq!(&bytes[..65], &pair_lo.1.as_bytes()[..]);
        assert_eq!(&bytes[65..], &pair_hi.1.as_bytes()[..]);
        // Both v bytes in the EIP-712 domain {27, 28}.
        assert!(matches!(bytes[64], 27 | 28));
        assert!(matches!(bytes[129], 27 | 28));
    }

    #[tokio::test]
    async fn pack_owner_signatures_order_independence() {
        let s_a = PrivateKeySigner::random();
        let s_b = PrivateKeySigner::random();
        let hash = B256::repeat_byte(0xef);
        let pa = sig_for(hash, &s_a).await;
        let pb = sig_for(hash, &s_b).await;
        let ab = pack_owner_signatures(vec![pa, pb]).unwrap();
        let ba = pack_owner_signatures(vec![pb, pa]).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn pack_owner_signatures_empty_returns_empty_bytes() {
        let out = pack_owner_signatures(Vec::new()).unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn pack_owner_signatures_rejects_duplicate_owner() {
        // One key imported into two account slots, both linked and both
        // selected to sign: the same owner appears twice. checkSignatures
        // counts it once, so the blob would be under-threshold and
        // revert GS026 after gas — refuse locally instead.
        let s = PrivateKeySigner::random();
        let hash = B256::repeat_byte(0xab);
        let pair_a = sig_for(hash, &s).await;
        // Different signature bytes (other hash), same recovered owner —
        // dedup keys on the address, not the signature payload.
        let pair_b = sig_for(B256::repeat_byte(0xcd), &s).await;
        let err = pack_owner_signatures(vec![pair_a, pair_b]).unwrap_err();
        assert!(err.contains("duplicate signature from owner"), "{err}");
    }

    #[test]
    fn assemble_signatures_rejects_duplicate_owner() {
        // Execute-from-queue path: a service record carrying two
        // confirmations from one owner must refuse before broadcast.
        let owner = Address::repeat_byte(0x11);
        let other = Address::repeat_byte(0x22);
        let err = assemble_signatures(vec![
            (owner, Bytes::from(vec![0xAAu8; 65])),
            (other, Bytes::from(vec![0xBBu8; 65])),
            (owner, Bytes::from(vec![0xCCu8; 65])),
        ])
        .unwrap_err();
        assert!(err.contains("duplicate signature from owner"), "{err}");
    }

    // ── On-chain reader tests against CallMock ────────────────────

    #[tokio::test]
    async fn current_safe_nonce_reads_via_call_raw() {
        let mock = CallMock::new();
        let safe = safe_addr();
        mock.set_call(
            safe,
            Bytes::from(nonceCall {}.abi_encode()),
            Bytes::from(U256::from(99u64).abi_encode()),
            true,
        );
        let n = current_safe_nonce(&mock, safe, Chain::Mainnet)
            .await
            .unwrap();
        assert_eq!(n, 99);
    }

    #[tokio::test]
    async fn verify_safe_tx_hash_on_chain_round_trips() {
        let mock = CallMock::new();
        let safe = safe_addr();
        let tx = empty_safe_tx();
        let planted = b256!("0xdeadbeef00000000000000000000000000000000000000000000000000000000");
        let calldata = getTransactionHashCall {
            to: tx.to,
            value: tx.value,
            data: tx.data.clone(),
            operation: tx.operation,
            safeTxGas: tx.safeTxGas,
            baseGas: tx.baseGas,
            gasPrice: tx.gasPrice,
            gasToken: tx.gasToken,
            refundReceiver: tx.refundReceiver,
            _nonce: tx.nonce,
        }
        .abi_encode();
        mock.set_call(
            safe,
            Bytes::from(calldata),
            Bytes::from(planted.abi_encode()),
            true,
        );
        let got = verify_safe_tx_hash_on_chain(&mock, &tx, safe, Chain::Mainnet)
            .await
            .unwrap();
        assert_eq!(got, planted);
    }

    #[test]
    fn build_safe_tx_with_nonce_zeros_relay_and_sets_nonce() {
        let input = SafeTxInput {
            to: address!("0x000000000000000000000000000000000000dEaD"),
            value: U256::from(5u64),
            data: Bytes::from_static(&[0x01, 0x02]),
            operation: Operation::Call,
        };
        let tx = build_safe_tx_with_nonce(input, 42);
        assert_eq!(tx.nonce, U256::from(42u64));
        assert_eq!(tx.operation, 0);
        assert_eq!(tx.safeTxGas, U256::ZERO);
        assert_eq!(tx.baseGas, U256::ZERO);
        assert_eq!(tx.gasPrice, U256::ZERO);
        assert_eq!(tx.gasToken, Address::ZERO);
        assert_eq!(tx.refundReceiver, Address::ZERO);
        assert_eq!(tx.value, U256::from(5u64));
    }

    #[test]
    fn build_rejection_tx_is_zero_value_self_call() {
        let safe = safe_addr();
        let tx = build_rejection_tx(safe, 7);
        assert_eq!(tx.to, safe);
        assert_eq!(tx.value, U256::ZERO);
        assert!(tx.data.is_empty());
        assert_eq!(tx.operation, 0);
        assert_eq!(tx.nonce, U256::from(7u64));
    }

    #[test]
    fn assemble_signatures_empty_is_empty() {
        assert!(assemble_signatures(Vec::new()).unwrap().is_empty());
    }

    #[tokio::test]
    async fn assemble_signatures_matches_pack_for_eip712_sigs() {
        // The raw-bytes assembler must produce the exact same blob as the
        // typed `pack_owner_signatures` when fed equivalent EIP-712
        // signatures — they're two entry points to the same wire format
        // (the execute-from-queue path uses the raw one).
        let s1 = PrivateKeySigner::random();
        let s2 = PrivateKeySigner::random();
        let hash = B256::repeat_byte(0x12);
        let sig1 = s1.sign_hash(&hash).await.unwrap();
        let sig2 = s2.sign_hash(&hash).await.unwrap();
        let packed =
            pack_owner_signatures(vec![(s1.address(), sig1), (s2.address(), sig2)]).unwrap();
        let assembled = assemble_signatures(vec![
            (s1.address(), Bytes::from(sig1.as_bytes().to_vec())),
            (s2.address(), Bytes::from(sig2.as_bytes().to_vec())),
        ])
        .unwrap();
        assert_eq!(packed, assembled);

        // Confirmations path: the exec-from-queue flow (and the exec
        // preflight sim) maps `SafeTxDetail.confirmations` to the same
        // `(owner, bytes)` pairs — the blob must be identical to the
        // direct packing above.
        let confirmations = [
            crate::safe::service::ServiceConfirmation {
                owner: s2.address(),
                signature: Bytes::from(sig2.as_bytes().to_vec()),
            },
            crate::safe::service::ServiceConfirmation {
                owner: s1.address(),
                signature: Bytes::from(sig1.as_bytes().to_vec()),
            },
        ];
        let via_confirmations = assemble_signatures(
            confirmations
                .iter()
                .map(|c| (c.owner, c.signature.clone()))
                .collect(),
        )
        .unwrap();
        assert_eq!(packed, via_confirmations);
    }

    #[tokio::test]
    async fn assemble_signatures_sorts_and_concats_raw_bytes() {
        // Two distinct 65-byte blobs tagged by address; lower address
        // must come first regardless of input order.
        let lo = Address::repeat_byte(0x11);
        let hi = Address::repeat_byte(0x22);
        let blob_lo = Bytes::from(vec![0xAAu8; 65]);
        let blob_hi = Bytes::from(vec![0xBBu8; 65]);
        let packed =
            assemble_signatures(vec![(hi, blob_hi.clone()), (lo, blob_lo.clone())]).unwrap();
        assert_eq!(packed.len(), 130);
        assert_eq!(&packed[..65], &blob_lo[..]);
        assert_eq!(&packed[65..], &blob_hi[..]);
    }

    #[tokio::test]
    async fn eip712_owner_sig_recovers_with_v_27_or_28() {
        let signer = PrivateKeySigner::random();
        let ks = crate::wallet::KaoSigner::Local(signer.clone());
        let safe = safe_addr();
        let domain = safe_domain(safe, Chain::Mainnet);
        let tx = empty_safe_tx();
        let hash = safe_tx_hash(&tx, &domain);
        let (owner, bytes) = sign_owner(&ks, &tx, &domain, hash, OwnerSigMode::Eip712)
            .await
            .unwrap();
        assert_eq!(owner, signer.address());
        assert_eq!(bytes.len(), 65);
        assert!(matches!(bytes[64], 27 | 28));
        // Recovers to the owner over the EIP-712 signing hash.
        let local_hash = safe_tx_hash(&tx, &domain);
        let sig = Signature::from_raw(&bytes).unwrap();
        assert_eq!(
            sig.recover_address_from_prehash(&local_hash).unwrap(),
            owner
        );
    }

    #[tokio::test]
    async fn sign_owner_takes_eip712_path_for_software() {
        // A software signer always succeeds at EIP-712, so `Auto` must
        // return exactly what `Eip712` does (the fallback never fires) —
        // v∈{27,28}.
        let signer = PrivateKeySigner::random();
        let ks = crate::wallet::KaoSigner::Local(signer);
        let safe = safe_addr();
        let domain = safe_domain(safe, Chain::Mainnet);
        let tx = empty_safe_tx();
        let hash = safe_tx_hash(&tx, &domain);
        let via_auto = sign_owner(&ks, &tx, &domain, hash, OwnerSigMode::Auto)
            .await
            .unwrap();
        let via_eip712 = sign_owner(&ks, &tx, &domain, hash, OwnerSigMode::Eip712)
            .await
            .unwrap();
        assert_eq!(via_auto, via_eip712);
        assert!(matches!(via_auto.1[64], 27 | 28));
    }

    #[tokio::test]
    async fn eth_sign_owner_sig_has_v_31_or_32_and_recovers() {
        let signer = PrivateKeySigner::random();
        let ks = crate::wallet::KaoSigner::Local(signer.clone());
        let safe = safe_addr();
        let domain = safe_domain(safe, Chain::Mainnet);
        let tx = empty_safe_tx();
        let hash = safe_tx_hash(&tx, &domain);
        let (owner, bytes) = sign_owner(&ks, &tx, &domain, hash, OwnerSigMode::EthSign)
            .await
            .unwrap();
        assert_eq!(bytes.len(), 65);
        assert!(matches!(bytes[64], 31 | 32));
        // Undo the +4 and recover over the EIP-191-prefixed digest.
        let mut raw = bytes.to_vec();
        raw[64] -= 4;
        let sig = Signature::from_raw(&raw).unwrap();
        assert_eq!(
            sig.recover_address_from_msg(hash.as_slice()).unwrap(),
            owner
        );
    }

    /// When an owner's EIP-712 signature fails, which modes go on to an `eth_sign` prompt for
    /// the same hash. `Auto` (every flow built before WalletConnect) always does. `Eip712` does
    /// only when nothing was shown on a device; after a Ledger showed the EIP-712 prompt and
    /// refused it — a decline looks exactly like Blind signing being off — it stops, and says so,
    /// so a second, different prompt is the user's explicit choice. `EthSign` never asks for
    /// EIP-712 at all.
    #[tokio::test]
    async fn owner_sig_falls_back_to_eth_sign_only_where_its_mode_allows() {
        use alloy::signers::ledger::{LedgerError, coins_ledger};
        use coins_ledger::common::APDUResponseCodes as Sw;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let key = PrivateKeySigner::random();
        let hash = B256::repeat_byte(0x42);
        let refused = || {
            alloy::signers::Error::other(LedgerError::LedgerError(
                Sw::ConditionsNotSatisfied.into(),
            ))
        };
        let locked =
            || alloy::signers::Error::other(LedgerError::LedgerError(Sw::UnlockDeviceError.into()));
        let unsupported = || {
            alloy::signers::Error::UnsupportedOperation(
                alloy::signers::UnsupportedSignerOperation::SignHash,
            )
        };
        let run = |mode: OwnerSigMode, err: fn() -> alloy::signers::Error| {
            let key = key.clone();
            async move {
                let (typed_asks, eth_asks) = (AtomicUsize::new(0), AtomicUsize::new(0));
                let got = owner_sig_bytes(
                    mode,
                    || async {
                        typed_asks.fetch_add(1, Ordering::SeqCst);
                        Err(err())
                    },
                    || async {
                        eth_asks.fetch_add(1, Ordering::SeqCst);
                        key.sign_message(hash.as_slice()).await
                    },
                )
                .await;
                (
                    got,
                    typed_asks.load(Ordering::SeqCst),
                    eth_asks.load(Ordering::SeqCst),
                )
            }
        };
        // A refused prompt: Eip712 stops without a second prompt, and says why.
        let (got, typed, eth) = run(OwnerSigMode::Eip712, refused).await;
        let err = got.unwrap_err();
        assert!(err.eip712_refused, "{err:?}");
        assert!(err.text.contains("Blind signing"), "{}", err.text);
        assert_eq!((typed, eth), (1, 0), "no eth_sign prompt after a refusal");
        // A locked device: no fallback either, and nothing to offer.
        let (got, _, eth) = run(OwnerSigMode::Eip712, locked).await;
        assert!(!got.unwrap_err().eip712_refused);
        assert_eq!(eth, 0);
        // Nothing was shown (Trezor, view-only, an old Ledger app): eth_sign, v + 4.
        let (got, _, eth) = run(OwnerSigMode::Eip712, unsupported).await;
        let blob = got.expect("the silent fallback");
        assert_eq!(eth, 1);
        assert!(matches!(blob[64], 31 | 32));
        // Auto keeps the flows that predate WalletConnect exactly as they were.
        let (got, _, eth) = run(OwnerSigMode::Auto, refused).await;
        assert!(got.is_ok());
        assert_eq!(eth, 1);
        // The user's explicit choice: straight to eth_sign.
        let (got, typed, eth) = run(OwnerSigMode::EthSign, refused).await;
        assert!(got.is_ok());
        assert_eq!((typed, eth), (0, 1));
    }

    #[test]
    fn encode_exec_transaction_round_trips() {
        // Round-trip the calldata: encode → ABI-decode → fields match.
        // Catches selector drift, argument permutation, or alloy ABI
        // bugs before they bubble up as opaque on-chain reverts.
        let tx = SafeTx {
            to: address!("0x000000000000000000000000000000000000dEaD"),
            value: U256::from(123u64),
            data: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            operation: 0,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasToken: Address::ZERO,
            refundReceiver: Address::ZERO,
            nonce: U256::from(5u64),
        };
        let sigs = Bytes::from(vec![0x42u8; 65]);
        let calldata = encode_exec_transaction(&tx, sigs.clone());
        // First 4 bytes are the selector.
        assert_eq!(&calldata[..4], &execTransactionCall::SELECTOR);
        // execTransaction does NOT carry SafeTx's `nonce` field —
        // the nonce is consumed when the Safe verifies signatures
        // (it's mixed into the EIP-712 hash). On the wire there
        // are 10 args: to, value, data, operation, safeTxGas,
        // baseGas, gasPrice, gasToken, refundReceiver, signatures.
        let decoded = execTransactionCall::abi_decode(&calldata).unwrap();
        assert_eq!(decoded.to, tx.to);
        assert_eq!(decoded.value, tx.value);
        assert_eq!(decoded.data, tx.data);
        assert_eq!(decoded.operation, tx.operation);
        assert_eq!(decoded.safeTxGas, tx.safeTxGas);
        assert_eq!(decoded.baseGas, tx.baseGas);
        assert_eq!(decoded.gasPrice, tx.gasPrice);
        assert_eq!(decoded.gasToken, tx.gasToken);
        assert_eq!(decoded.refundReceiver, tx.refundReceiver);
        assert_eq!(decoded.signatures, sigs);
    }

    // ── Pre-sign verification ─────────────────────────────────────────

    /// Plant `sep` as the Safe's `domainSeparator()` reply on the mock.
    fn plant_domain_separator(mock: &CallMock, safe: Address, sep: B256) {
        mock.set_call(
            safe,
            Bytes::from(domainSeparatorCall {}.abi_encode()),
            Bytes::from(sep.abi_encode()),
            true,
        );
    }

    /// Plant the Safe's `getTransactionHash(...)` reply for `tx`.
    fn plant_tx_hash(mock: &CallMock, safe: Address, tx: &SafeTx, hash: B256) {
        let calldata = getTransactionHashCall {
            to: tx.to,
            value: tx.value,
            data: tx.data.clone(),
            operation: tx.operation,
            safeTxGas: tx.safeTxGas,
            baseGas: tx.baseGas,
            gasPrice: tx.gasPrice,
            gasToken: tx.gasToken,
            refundReceiver: tx.refundReceiver,
            _nonce: tx.nonce,
        }
        .abi_encode();
        mock.set_call(
            safe,
            Bytes::from(calldata),
            Bytes::from(hash.abi_encode()),
            true,
        );
    }

    #[tokio::test]
    async fn verify_domain_separator_accepts_matching_contract() {
        let mock = CallMock::new();
        let safe = safe_addr();
        let chain = Chain::Mainnet;
        plant_domain_separator(&mock, safe, safe_domain(safe, chain).separator());
        verify_domain_separator_on_chain(&mock, safe, chain)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verify_domain_separator_rejects_mismatch() {
        // A pre-1.3 Safe (verifyingContract-only domain) or a wrong-chain
        // read both surface as a separator that isn't ours.
        let mock = CallMock::new();
        let safe = safe_addr();
        plant_domain_separator(&mock, safe, B256::repeat_byte(0x66));
        let err = verify_domain_separator_on_chain(&mock, safe, Chain::Mainnet)
            .await
            .unwrap_err();
        assert!(err.contains("domain separator mismatch"), "{err}");
    }

    #[tokio::test]
    async fn verify_before_signing_passes_when_both_checks_agree() {
        let mock = CallMock::new();
        let safe = safe_addr();
        let chain = Chain::Mainnet;
        let tx = empty_safe_tx();
        let domain = safe_domain(safe, chain);
        let local = safe_tx_hash(&tx, &domain);
        plant_domain_separator(&mock, safe, domain.separator());
        plant_tx_hash(&mock, safe, &tx, local);
        verify_safe_tx_before_signing(&mock, &tx, safe, chain, local)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verify_before_signing_reports_domain_mismatch_first() {
        // Both checks would fail here, but the domain check must run
        // (and report) first — it pinpoints "wrong domain shape / wrong
        // chain / pre-1.3 Safe", which is more actionable than a bare
        // tx-hash mismatch.
        let mock = CallMock::new();
        let safe = safe_addr();
        let chain = Chain::Mainnet;
        let tx = empty_safe_tx();
        let local = safe_tx_hash(&tx, &safe_domain(safe, chain));
        plant_domain_separator(&mock, safe, B256::repeat_byte(0x66));
        plant_tx_hash(&mock, safe, &tx, B256::repeat_byte(0x99));
        let err = verify_safe_tx_before_signing(&mock, &tx, safe, chain, local)
            .await
            .unwrap_err();
        assert!(err.contains("domain separator mismatch"), "{err}");
        assert!(!err.contains("safe hash mismatch"), "{err}");
    }

    #[tokio::test]
    async fn verify_before_signing_propagates_rpc_failure() {
        // Nothing planted: the domain-separator read itself errors. The
        // failure must surface as Err — "couldn't verify" must never
        // collapse into "verified".
        let mock = CallMock::new();
        let safe = safe_addr();
        let chain = Chain::Mainnet;
        let tx = empty_safe_tx();
        let local = safe_tx_hash(&tx, &safe_domain(safe, chain));
        assert!(
            verify_safe_tx_before_signing(&mock, &tx, safe, chain, local)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn verify_before_signing_rejects_tx_hash_drift() {
        // Domain agrees but the contract computes a different SafeTx
        // hash — field-encoding drift must abort before signing.
        let mock = CallMock::new();
        let safe = safe_addr();
        let chain = Chain::Mainnet;
        let tx = empty_safe_tx();
        let domain = safe_domain(safe, chain);
        let local = safe_tx_hash(&tx, &domain);
        plant_domain_separator(&mock, safe, domain.separator());
        plant_tx_hash(&mock, safe, &tx, B256::repeat_byte(0x99));
        let err = verify_safe_tx_before_signing(&mock, &tx, safe, chain, local)
            .await
            .unwrap_err();
        assert!(err.contains("safe hash mismatch"), "{err}");
    }

    #[test]
    fn ensure_signable_version_accepts_only_chainid_domain_range() {
        for ok in ["1.3.0", "1.4.1", "1.5.0", "1.3.12"] {
            assert!(ensure_signable_version(ok).is_ok(), "{ok}");
        }
        for bad in [
            "1.0.0",
            "1.1.1",
            "1.2.0", // pre-chainId domain
            "1.6.0",
            "2.0.0", // newer than the reviewed range
            "1.4",
            "1.4.1-beta",
            "1.4.x",
            "",
            "hi there",
        ] {
            assert!(ensure_signable_version(bad).is_err(), "{bad}");
        }
    }
}
