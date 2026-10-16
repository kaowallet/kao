//! What Kao keeps of its own CoW Protocol signatures in Settings → Signed messages: every order it
//! signs (an EOA's EIP-712 `Order`, or a Safe owners' EIP-1271 `SafeMessage` over its digest) and
//! every off-chain cancellation (`OrderCancellations`, likewise) — with the EIP-712 typed data that
//! was signed and the ERC-8213 fingerprints the review shows for it, under the same labels.
//!
//! A sign task carries a [`CowHistory`]: the vault session captured when the task was spawned (an
//! op after a lock is dropped, like every vault op) and the account as Kao named it then. It
//! records the moment the signature exists and gets a [`Pending`] back, which it settles once the
//! orderbook answered: `Delivered` when the orderbook took the order or cancellation,
//! `NotDelivered` when it didn't — or when the signature never left Kao (a Safe signature that
//! failed its on-chain EIP-1271 check). The vault writes the raw signature to disk only once it was
//! delivered; a record whose task ended with Kao (a lock or quit before the orderbook answered)
//! stays `Sending`, with only the signature's hash.

use alloy::dyn_abi::TypedData;
use alloy::primitives::{B256, Bytes};
use alloy::sol_types::{Eip712Domain, SolStruct};
use serde::Serialize;

use crate::chain::Chain;
use crate::sign::digest::{
    COW_CANCELLATION_DIGEST_LABEL, COW_ORDER_DIGEST_LABEL, DOMAIN_HASH_LABEL, EIP712_DIGEST_LABEL,
    Eip712Digests, MESSAGE_HASH_LABEL,
};
use crate::vault::{
    AccountRef, CowOrderRecord, Delivery, DigestRow, NewSigned, SignOrigin, SignedKind,
    SignedPayload, VaultSession,
};

use super::order::{Order, build_cancellations, cow_domain, order_uid, uid_hex};

/// The tokens an order trades, as the composer named them. Token metadata: untrusted, sanitized
/// where the history draws it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrderTokens {
    pub sell_symbol: String,
    pub sell_decimals: u8,
    pub buy_symbol: String,
    pub buy_decimals: u8,
}

/// Where a CoW sign task records its signatures.
#[derive(Debug, Clone)]
pub struct CowHistory {
    session: VaultSession,
    /// The account that signs: the EOA itself, or the Safe whose owners sign for it.
    account: AccountRef,
}

impl CowHistory {
    pub fn new(session: VaultSession, account: AccountRef) -> Self {
        Self { session, account }
    }

    /// Record `order`, just signed on `chain` ([`order_record`]).
    pub fn order_signed(
        &self,
        order: &Order,
        chain: Chain,
        tokens: &OrderTokens,
        signature: &[u8],
    ) -> Pending {
        self.record(order_record(
            &self.account,
            order,
            chain,
            tokens,
            signature,
            now_secs(),
        ))
    }

    /// Record the cancellation of order `uid`, just signed on `chain` ([`cancellation_record`]).
    pub fn cancellation_signed(
        &self,
        uid: &[u8; 56],
        chain: Chain,
        order: CowOrderRecord,
        signature: &[u8],
    ) -> Pending {
        self.record(cancellation_record(
            &self.account,
            uid,
            chain,
            order,
            signature,
            now_secs(),
        ))
    }

    fn record(&self, rec: NewSigned) -> Pending {
        Pending {
            recorded: self
                .session
                .record_signed(rec)
                .map(|id| (self.session.clone(), id)),
        }
    }
}

/// A recorded signature awaiting the orderbook's answer. Nothing to settle when the session's
/// epoch had already ended (nothing was recorded).
#[must_use = "settle it with the orderbook's answer"]
#[derive(Debug)]
pub struct Pending {
    recorded: Option<(VaultSession, u64)>,
}

impl Pending {
    /// The orderbook answered: `Delivered` for an `Ok`, `NotDelivered` for an `Err`.
    pub fn settle<T, E>(self, outcome: &Result<T, E>) {
        if let Some((session, id)) = self.recorded {
            let d = if outcome.is_ok() {
                Delivery::Delivered
            } else {
                Delivery::NotDelivered
            };
            session.signed_delivery(id, d);
        }
    }
}

/// The record of `order`, signed on `chain` by `by` at `at` (`Sending`): an EOA's EIP-712 typed
/// data, or — `by` a Safe — the `SafeMessage` its owners signed over the order digest. The UID is
/// the order's own (`orderDigest ‖ by ‖ validTo`), so it matches the one the orderbook returns.
pub fn order_record(
    by: &AccountRef,
    order: &Order,
    chain: Chain,
    tokens: &OrderTokens,
    signature: &[u8],
    at: u64,
) -> NewSigned {
    let domain = cow_domain(chain);
    let digests = Eip712Digests::of(order, &domain);
    let summary = CowOrderRecord {
        uid: uid_hex(&order_uid(digests.digest, by.address(), order.validTo)),
        sell_token: order.sellToken,
        sell_symbol: tokens.sell_symbol.clone(),
        sell_decimals: tokens.sell_decimals,
        sell_amount: order.sellAmount,
        buy_token: order.buyToken,
        buy_symbol: tokens.buy_symbol.clone(),
        buy_decimals: tokens.buy_decimals,
        buy_amount: order.buyAmount,
        valid_to: order.validTo,
    };
    NewSigned {
        at,
        origin: SignOrigin::CowOrder { order: summary },
        account: by.clone(),
        chain_id: chain.chain_id(),
        kind: kind_of(by),
        primary_type: Some("Order".to_string()),
        payload: typed_payload(order, domain),
        digests: digest_rows(by, chain, &digests, COW_ORDER_DIGEST_LABEL),
        signature: Bytes::copy_from_slice(signature),
        delivery: Delivery::Sending,
    }
}

/// The record of the off-chain cancellation of order `uid`, signed on `chain` by `by` at `at`
/// (`Sending`). `order` is the cancelled order as Kao tracked it, for the row; its `uid` is set to
/// the one signed.
pub fn cancellation_record(
    by: &AccountRef,
    uid: &[u8; 56],
    chain: Chain,
    order: CowOrderRecord,
    signature: &[u8],
    at: u64,
) -> NewSigned {
    let domain = cow_domain(chain);
    let message = build_cancellations(std::slice::from_ref(uid));
    let digests = Eip712Digests::of(&message, &domain);
    NewSigned {
        at,
        origin: SignOrigin::CowCancel {
            order: CowOrderRecord {
                uid: uid_hex(uid),
                ..order
            },
        },
        account: by.clone(),
        chain_id: chain.chain_id(),
        kind: kind_of(by),
        primary_type: Some("OrderCancellations".to_string()),
        payload: typed_payload(&message, domain),
        digests: digest_rows(by, chain, &digests, COW_CANCELLATION_DIGEST_LABEL),
        signature: Bytes::copy_from_slice(signature),
        delivery: Delivery::Sending,
    }
}

fn kind_of(by: &AccountRef) -> SignedKind {
    match by {
        AccountRef::Eoa { .. } => SignedKind::TypedData,
        AccountRef::Safe { .. } => SignedKind::SafeMessage,
    }
}

/// The fingerprints the review shows, in its order and under its labels: an EOA's EIP-712 triple
/// of the CoW message (`SignStep::Typed`); for a Safe, the triple of the `SafeMessage` the owners
/// sign, then the CoW digest it wraps under `wrapped_label` (`SignStep::SafeMessage`).
fn digest_rows(
    by: &AccountRef,
    chain: Chain,
    cow: &Eip712Digests,
    wrapped_label: &str,
) -> Vec<DigestRow> {
    let row = |label: &str, hash: B256| DigestRow {
        label: label.to_string(),
        hash,
    };
    let triple = |d: &Eip712Digests| {
        vec![
            row(EIP712_DIGEST_LABEL, d.digest),
            row(DOMAIN_HASH_LABEL, d.domain_hash),
            row(MESSAGE_HASH_LABEL, d.message_hash),
        ]
    };
    match by {
        AccountRef::Eoa { .. } => triple(cow),
        AccountRef::Safe { address, .. } => {
            let mut rows = triple(&super::safe_sig::safe_message_digests(
                cow.digest, *address, chain,
            ));
            rows.push(row(wrapped_label, cow.digest));
            rows
        }
    }
}

/// The EIP-712 JSON (`types`, `primaryType`, `domain`, `message`) of exactly what was signed.
fn typed_payload<S: SolStruct + Serialize>(message: &S, domain: Eip712Domain) -> SignedPayload {
    SignedPayload::TypedData {
        json: serde_json::to_string(&TypedData::from_struct(message, Some(domain)))
            .unwrap_or_default(),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cow::order::{build_sell_order, cancellations_digest, order_digest};
    use crate::cow::safe_sig::{safe_message_digests, safe_message_hash};
    use alloy::primitives::{Address, U256, address};

    const SAFE: Address = address!("0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
    const EOA: Address = address!("0x1111111111111111111111111111111111111111");

    fn eoa() -> AccountRef {
        AccountRef::Eoa {
            address: EOA,
            label: "Account 1".into(),
        }
    }

    fn safe() -> AccountRef {
        AccountRef::Safe {
            address: SAFE,
            chain_id: 8453,
            label: "Treasury".into(),
        }
    }

    fn order(receiver: Address) -> Order {
        build_sell_order(
            address!("0x4200000000000000000000000000000000000006"),
            address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
            receiver,
            U256::from(10).pow(U256::from(18)),
            U256::from(2_500_000_000u64),
            1_900_000_000,
            50,
            crate::cow::market_app_data(50).1,
        )
    }

    fn tokens() -> OrderTokens {
        OrderTokens {
            sell_symbol: "WETH".into(),
            sell_decimals: 18,
            buy_symbol: "USDC".into(),
            buy_decimals: 6,
        }
    }

    fn typed(rec: &NewSigned) -> TypedData {
        let SignedPayload::TypedData { json } = &rec.payload else {
            panic!("typed data")
        };
        serde_json::from_str(json).expect("the kept JSON parses as EIP-712 typed data")
    }

    /// An EOA order: typed data that hashes to exactly the digest signed, the order's own UID,
    /// what it trades, and the review's three fingerprints.
    #[test]
    fn an_eoa_order_keeps_the_typed_data_it_signed() {
        let o = order(EOA);
        let rec = order_record(&eoa(), &o, Chain::Base, &tokens(), &[7; 65], 42);
        let domain = cow_domain(Chain::Base);
        let digest = order_digest(&o, &domain);
        assert_eq!(typed(&rec).eip712_signing_hash().unwrap(), digest);
        assert_eq!(typed(&rec).primary_type, "Order");
        let SignOrigin::CowOrder { order: summary } = &rec.origin else {
            panic!("an order")
        };
        assert_eq!(summary.uid, uid_hex(&order_uid(digest, EOA, o.validTo)));
        assert_eq!(
            (summary.sell_amount, summary.buy_amount, summary.valid_to),
            (o.sellAmount, o.buyAmount, o.validTo)
        );
        assert_eq!(
            (summary.sell_token, summary.buy_token),
            (o.sellToken, o.buyToken)
        );
        assert_eq!(
            (summary.sell_symbol.as_str(), summary.buy_decimals),
            ("WETH", 6)
        );
        assert_eq!(rec.kind, SignedKind::TypedData);
        assert_eq!(rec.primary_type.as_deref(), Some("Order"));
        assert_eq!((rec.chain_id, rec.at), (8453, 42));
        assert_eq!(rec.account, eoa());
        assert_eq!(rec.delivery, Delivery::Sending);
        assert_eq!(rec.signature.as_ref(), &[7; 65]);
        let d = Eip712Digests::of(&o, &domain);
        assert_eq!(
            rec.digests,
            vec![
                DigestRow {
                    label: EIP712_DIGEST_LABEL.into(),
                    hash: d.digest
                },
                DigestRow {
                    label: DOMAIN_HASH_LABEL.into(),
                    hash: d.domain_hash
                },
                DigestRow {
                    label: MESSAGE_HASH_LABEL.into(),
                    hash: d.message_hash
                },
            ]
        );
    }

    /// A Safe order: a SafeMessage — its triple first (the digest the owners signed), then the
    /// order digest it wraps — and the UID's owner is the Safe.
    #[test]
    fn a_safe_order_keeps_the_safe_message_then_the_order_digest() {
        let o = order(SAFE);
        let rec = order_record(&safe(), &o, Chain::Base, &tokens(), &[7; 130], 42);
        let digest = order_digest(&o, &cow_domain(Chain::Base));
        assert_eq!(rec.kind, SignedKind::SafeMessage);
        assert_eq!(typed(&rec).eip712_signing_hash().unwrap(), digest);
        let s = safe_message_digests(digest, SAFE, Chain::Base);
        assert_eq!(s.digest, safe_message_hash(digest, SAFE, Chain::Base));
        let rows: Vec<(&str, B256)> = rec
            .digests
            .iter()
            .map(|r| (r.label.as_str(), r.hash))
            .collect();
        assert_eq!(
            rows,
            vec![
                (EIP712_DIGEST_LABEL, s.digest),
                (DOMAIN_HASH_LABEL, s.domain_hash),
                (MESSAGE_HASH_LABEL, s.message_hash),
                (COW_ORDER_DIGEST_LABEL, digest),
            ]
        );
        let SignOrigin::CowOrder { order: summary } = &rec.origin else {
            panic!("an order")
        };
        assert_eq!(summary.uid, uid_hex(&order_uid(digest, SAFE, o.validTo)));
    }

    /// A cancellation: `OrderCancellations` over the one UID, which also names the order (whatever
    /// the tracked copy said).
    #[test]
    fn a_cancellation_keeps_its_typed_data_and_the_order_it_cancels() {
        let uid = [0xcd; 56];
        let tracked = CowOrderRecord {
            uid: "stale".into(),
            sell_symbol: "WETH".into(),
            ..Default::default()
        };
        let digest = cancellations_digest(&[uid], &cow_domain(Chain::Mainnet));
        for (by, kind) in [
            (eoa(), SignedKind::TypedData),
            (
                AccountRef::Safe {
                    address: SAFE,
                    chain_id: 1,
                    label: "Vault".into(),
                },
                SignedKind::SafeMessage,
            ),
        ] {
            let rec = cancellation_record(&by, &uid, Chain::Mainnet, tracked.clone(), &[1; 65], 9);
            assert_eq!(rec.kind, kind);
            assert_eq!(rec.primary_type.as_deref(), Some("OrderCancellations"));
            assert_eq!(typed(&rec).eip712_signing_hash().unwrap(), digest);
            assert_eq!(
                rec.origin,
                SignOrigin::CowCancel {
                    order: CowOrderRecord {
                        uid: uid_hex(&uid),
                        ..tracked.clone()
                    }
                }
            );
            let last = rec.digests.last().unwrap();
            match kind {
                SignedKind::SafeMessage => {
                    assert_eq!(rec.digests.len(), 4);
                    assert_eq!(
                        rec.digests[0].hash,
                        safe_message_hash(digest, SAFE, Chain::Mainnet)
                    );
                    assert_eq!(
                        (last.label.as_str(), last.hash),
                        (COW_CANCELLATION_DIGEST_LABEL, digest)
                    );
                }
                _ => {
                    assert_eq!(rec.digests.len(), 3);
                    assert_eq!(
                        (rec.digests[0].label.as_str(), rec.digests[0].hash),
                        (EIP712_DIGEST_LABEL, digest)
                    );
                }
            }
        }
    }

    /// Through the vault: recorded `Sending`, settled by the orderbook's answer; a dead session
    /// records nothing and has nothing to settle.
    #[test]
    fn a_pending_record_settles_by_the_outcome() {
        let vault = crate::vault::Vault::with_store_path(std::path::PathBuf::from(
            "/nonexistent/kao-cow-history-test.redb",
        ));
        vault.unlock(
            None,
            crate::wallet::KeyStatus::Ok,
            crate::wallet::SealedLoad::default(),
        );
        let h = CowHistory::new(vault.session(), eoa());
        let o = order(EOA);
        let ok = h.order_signed(&o, Chain::Base, &tokens(), &[1; 65]);
        let err = h.cancellation_signed(&[2; 56], Chain::Base, CowOrderRecord::default(), &[2; 65]);
        assert!(
            vault
                .signed()
                .iter()
                .all(|r| r.delivery == Delivery::Sending)
        );
        ok.settle(&Ok::<_, String>("uid"));
        err.settle(&Err::<(), _>("rejected"));
        let signed = vault.signed();
        assert!(matches!(signed[0].origin, SignOrigin::CowCancel { .. }));
        assert_eq!(signed[0].delivery, Delivery::NotDelivered);
        assert!(matches!(signed[1].origin, SignOrigin::CowOrder { .. }));
        assert_eq!(signed[1].delivery, Delivery::Delivered);
        assert!(signed[1].at > 0);

        let _ = vault.lock();
        let dead = h.order_signed(&o, Chain::Base, &tokens(), &[3; 65]);
        assert!(dead.recorded.is_none());
        dead.settle(&Ok::<(), ()>(()));
        assert!(vault.signed().is_empty());
    }
}
