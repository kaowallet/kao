//! In-process end-to-end tests: a dapp `SignClient` and Kao's [`super::runtime::WcRuntime`]
//! on one `RelayServer`, the test playing the coordinator.
//!
//! The coordinator steps each test performs are the dashboard's: pull the request from the event
//! stream, `request::validate` it against the bound session, `admit` it, move it through the book's
//! review states and answer it — signing with a throwaway local key.

use std::collections::BTreeMap;
use std::time::Duration;

use alloy::dyn_abi::TypedData;
use alloy::primitives::{Address, B256, Signature, address, b256};
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;
use serde_json::{Value, json};
use wallet_connect::crypto::{KeyPair, PublicKey, SymKey, Topic};
use wallet_connect::rpc::{ErrorObject, Payload, Request, Response};
use wallet_connect::sign::{
    ConnectParams, ConnectResponse, Participant, Relay, Session, SessionProposeParams,
    SessionProposeResponse, SignEvent,
};
use wallet_connect::uri::PairingUri;

use super::runtime::WcRuntime;
use super::testkit::{self, RawPeer};
use super::types::*;
use super::{TEARDOWN_PER_PHASE, caip2, namespaces, now_secs, request};

const SAFE: Address = address!("5afe5afe5afe5afe5afe5afe5afe5afe5afe5afe");
/// EIP-712's own example ("Ether Mail") and its signing hash.
const MAIL_DIGEST: B256 = b256!("be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
/// The crate sweeps expiries every 5 s; give a sweep room to happen.
const SWEEP_WAIT: Duration = Duration::from_secs(12);

fn label(chain_id: u64) -> String {
    format!("Chain {chain_id}")
}

/// Paste the dapp's link into Kao, plan the card for `caps` and approve what the plan grants.
/// Returns the dapp's view of the session.
async fn connect(kao: &WcRuntime, resp: ConnectResponse, caps: &IdentityCaps) -> Session {
    kao.pair(testkit::uri_of(&resp), now_secs())
        .expect("the link pairs");
    let p = testkit::wait_card(kao).await;
    let plan = namespaces::plan_proposal(&p, caps, &label);
    let grant = plan.verdict.expect("the plan grants a session");
    kao.approve(testkit::ticket(&p, caps, grant))
        .expect("approve starts");
    tokio::time::timeout(Duration::from_secs(5), resp.approval)
        .await
        .expect("the dapp hears the approval")
        .expect("the dapp holds the session")
}

/// The dashboard's admission step for the next request on the stream.
async fn admit_next(kao: &WcRuntime, caps: &IdentityCaps) -> (WcKey, Result<Admitted, Refusal>) {
    let (req, received_at) = testkit::next_request(&kao.events()).await;
    let session = kao
        .with_book(|b| b.session(&req.topic).cloned())
        .expect("a session Kao bound");
    let admitted = request::validate(&req, &session, caps);
    kao.admit(&req, received_at, admitted.clone());
    let key = WcKey {
        topic: req.topic.clone(),
        id: req.id,
    };
    (key, admitted)
}

/// Open the review and confirm it (the book's side of `open_wc_review` + `dispatch_wc`).
fn to_signing(kao: &WcRuntime, key: &WcKey, seq: u64) {
    kao.with_book(|b| {
        assert!(b.mark_in_review(key, seq));
        assert!(b.mark_signing(key, seq));
    });
}

fn sig_hex(sig: &Signature) -> Value {
    json!(format!("0x{}", alloy::hex::encode(sig.as_bytes())))
}

fn sig_of(result: &Value) -> Signature {
    let hex = result.as_str().expect("a hex string");
    let bytes = alloy::hex::decode(hex).expect("hex");
    Signature::try_from(bytes.as_slice()).expect("65 bytes")
}

fn peer_code(result: &wallet_connect::Result<Value>) -> Option<i64> {
    match result {
        Err(wallet_connect::Error::Peer(e)) => Some(e.code),
        _ => None,
    }
}

fn mail_typed_data() -> Value {
    testkit::fixtures::mail(1)
}

#[tokio::test]
async fn pair_approve_personal_sign_round_trip() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp =
        testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1, 8453])).await;
    let session = connect(&kao, resp, &caps).await;

    // Exactly one account per granted chain, all the active identity.
    let mut accounts = session.accounts();
    accounts.sort();
    let mut expected = vec![caps.identity.caip10(1), caps.identity.caip10(8453)];
    expected.sort();
    assert_eq!(accounts, expected);
    let snap = kao.snapshot(now_secs());
    assert_eq!(snap.sessions.len(), 1);
    assert_eq!(snap.sessions[0].identity, caps.identity);
    assert!(snap.proposal.is_none());

    let call = testkit::dapp_request(
        &dapp,
        &session.topic,
        1,
        "personal_sign",
        testkit::personal_sign_params("Hello Kao", signer.address()),
    );
    let (key, admitted) = admit_next(&kao, &caps).await;
    let Ok(Admitted {
        call: WcCall::PersonalSign(ps),
        ..
    }) = admitted
    else {
        panic!("personal_sign admitted: {admitted:?}");
    };
    assert_eq!(ps.message.as_ref(), b"Hello Kao");
    assert_eq!(
        kao.with_book(|b| b.state_of(&key)),
        Some(QueueState::Waiting)
    );
    to_signing(&kao, &key, 1);
    assert!(kao.is_live(&key));
    let sig = signer
        .sign_message_sync(&ps.message)
        .expect("local key signs");
    kao.answer(&key, Answer::Result(sig_hex(&sig)));

    let result = testkit::dapp_result(call).await.expect("a signature");
    let recovered = sig_of(&result)
        .recover_address_from_msg(b"Hello Kao")
        .expect("recovers");
    assert_eq!(recovered, signer.address());
    testkit::settle(|| kao.with_book(|b| b.outbox_len() == 0)).await;
    assert!(kao.with_book(|b| b.outbox_len() == 0 && b.request(&key).is_none()));
}

#[tokio::test]
async fn typed_data_round_trip_v4() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp = testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let session = connect(&kao, resp, &caps).await;

    let params = json!([
        signer.address().to_checksum(None),
        mail_typed_data().to_string()
    ]);
    let call = testkit::dapp_request(&dapp, &session.topic, 1, "eth_signTypedData_v4", params);
    let (key, admitted) = admit_next(&kao, &caps).await;
    let Ok(Admitted {
        call: WcCall::SignTypedData(tr),
        ..
    }) = admitted
    else {
        panic!("typed data admitted: {admitted:?}");
    };
    let signing_hash = tr.typed.eip712_signing_hash().expect("hashes");
    assert_eq!(
        tr.checked.digests.digest, signing_hash,
        "reviewed == signed"
    );
    assert_eq!(signing_hash, MAIL_DIGEST);
    to_signing(&kao, &key, 1);
    let sig = signer
        .sign_hash_sync(&signing_hash)
        .expect("local key signs");
    kao.answer(&key, Answer::Result(sig_hex(&sig)));

    let result = testkit::dapp_result(call).await.expect("a signature");
    let recovered = sig_of(&result)
        .recover_address_from_prehash(&signing_hash)
        .expect("recovers");
    assert_eq!(recovered, signer.address());
    // Kao's own parse of the same JSON is what was hashed.
    let reparsed: TypedData = serde_json::from_value(mail_typed_data()).expect("parses");
    assert_eq!(reparsed.eip712_signing_hash().ok(), Some(MAIL_DIGEST));
}

// ── Real-dapp-shaped payloads (`testkit::fixtures`) ──────────────────────────────────────────────

/// A dapp on the JS SDK, as raw relay traffic: its proposal and every request exactly as the SDK
/// and the dapp's library serialize them.
struct SdkDapp {
    raw: RawPeer,
    topic: Topic,
    key: SymKey,
    /// The `wc_sessionSettle` params Kao sent.
    settle: Value,
    plan: ProposalPlan,
    next_id: u64,
}

/// The JS SDK's `payloadId()`: milliseconds × 1000 plus a random 3-digit suffix.
const SDK_PAYLOAD_ID: u64 = 1_728_000_000_000_123;

/// The dapp shows a link and proposes `fixtures::ethereum_provider_proposal` over it; Kao pairs,
/// plans the card for `caps` and approves what the plan grants; the dapp acknowledges the settlement
/// as the SDK does.
async fn sdk_connect(
    relay: &wallet_connect::relay::RelayServer,
    kao: &WcRuntime,
    caps: &IdentityCaps,
) -> SdkDapp {
    let mut raw = RawPeer::attach(relay, "sdk-dapp");
    let pairing_key = SymKey::generate();
    let link = PairingUri::new(pairing_key.clone(), now_secs() + 300);
    let pairing = link.topic.clone();
    raw.subscribe(&pairing).await;
    let proposer = KeyPair::generate();
    let params =
        testkit::fixtures::ethereum_provider_proposal(&proposer.public_key(), &pairing, now_secs());
    let propose = Request::with_id(SDK_PAYLOAD_ID, "wc_sessionPropose", params);
    let propose = serde_json::to_value(propose).expect("serializes");
    raw.publish(&pairing, &pairing_key, &propose, 1100).await;

    kao.pair(zeroize::Zeroizing::new(link.to_string()), now_secs())
        .expect("the link pairs");
    let p = testkit::wait_card(kao).await;
    let plan = namespaces::plan_proposal(&p, caps, &label);
    let grant = plan.verdict.clone().expect("the plan grants a session");
    kao.approve(testkit::ticket(&p, caps, grant))
        .expect("approve starts");

    let Payload::Response(Response {
        outcome: Ok(answer),
        ..
    }) = raw.next_on(&pairing, &pairing_key).await
    else {
        panic!("the proposal is answered");
    };
    let answer: SessionProposeResponse = serde_json::from_value(answer).expect("propose response");
    let key = proposer
        .derive_sym_key(&answer.responder_public_key)
        .expect("derives");
    let topic = key.topic();
    raw.subscribe(&topic).await;
    let Payload::Request(settle) = raw.next_on(&topic, &key).await else {
        panic!("the settlement");
    };
    assert_eq!(settle.method, "wc_sessionSettle");
    let ack = serde_json::to_value(Response::result(settle.id, json!(true))).expect("serializes");
    raw.publish(&topic, &key, &ack, 1103).await;
    testkit::settle(|| {
        kao.with_book(|b| {
            b.session(&topic)
                .is_some_and(|s| s.ack == AckState::Confirmed)
        })
    })
    .await;
    assert_eq!(
        kao.with_book(|b| b.session(&topic).map(|s| s.ack)),
        Some(AckState::Confirmed),
        "the settlement was acknowledged"
    );
    SdkDapp {
        raw,
        topic,
        key,
        settle: settle.params,
        plan,
        next_id: SDK_PAYLOAD_ID,
    }
}

impl SdkDapp {
    /// One request through the coordinator's steps: the SDK sends it (expiryTimestamp = now + 5
    /// min), Kao validates and admits it, an admitted review is answered with `answer` — what the
    /// device would sign — and a refusal is answered by Kao on its own. Returns the admission and
    /// what the dapp received.
    async fn call(
        &mut self,
        kao: &WcRuntime,
        caps: &IdentityCaps,
        chain_id: u64,
        method: &str,
        params: Value,
        answer: impl FnOnce(&Admitted) -> Value,
    ) -> (Result<Admitted, Refusal>, Result<Value, ErrorObject>) {
        self.next_id += 1;
        let id = self.next_id;
        let sent_at = now_secs();
        let request = testkit::fixtures::sdk_request(method, params, sent_at);
        self.raw
            .inject_request(&self.topic, &self.key, id, chain_id, request)
            .await;
        let (key, admitted) = admit_next(kao, caps).await;
        assert_eq!(
            key,
            WcKey {
                topic: self.topic.clone(),
                id
            }
        );
        if let Ok(a) = &admitted
            && a.call.needs_review()
        {
            let deadline = kao.with_book(|b| b.request(&key).and_then(|q| q.dapp_deadline));
            assert_eq!(
                deadline,
                Some(sent_at + testkit::fixtures::SDK_REQUEST_TTL_SECS),
                "{method}: the SDK's expiry is the dapp's deadline"
            );
            to_signing(kao, &key, id);
            assert!(kao.is_live(&key), "{method}: live five minutes out");
            kao.answer(&key, Answer::Result(answer(a)));
        }
        let got = self.raw.next_response(&self.topic, &self.key, id).await;
        (admitted, got)
    }
}

/// An SDK personal_sign in `lib`'s shape: admitted as exactly the message's UTF-8 bytes from the
/// session's account, and the dapp's signature recovers to it.
async fn sdk_personal_sign_round_trip(libs: &[testkit::fixtures::PersonalSignLib]) {
    let (relay, _dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let mut dapp = sdk_connect(&relay, &kao, &caps).await;
    for &lib in libs {
        let message = format!("Sign in with {lib:?}");
        let params = testkit::fixtures::personal_sign(lib, &message, signer.address());
        let (admitted, got) = dapp
            .call(&kao, &caps, 1, "personal_sign", params, |a| {
                let WcCall::PersonalSign(ps) = &a.call else {
                    panic!("{lib:?}: a personal_sign: {a:?}");
                };
                sig_hex(&signer.sign_message_sync(&ps.message).expect("signs"))
            })
            .await;
        let Ok(Admitted {
            call: WcCall::PersonalSign(ps),
            ..
        }) = &admitted
        else {
            panic!("{lib:?}: personal_sign admitted: {admitted:?}");
        };
        assert_eq!(ps.from, signer.address(), "{lib:?}");
        assert_eq!(ps.message.as_ref(), message.as_bytes(), "{lib:?}");
        let sig = sig_of(&got.unwrap_or_else(|e| panic!("{lib:?}: {e:?}")));
        assert_eq!(
            sig.recover_address_from_msg(message.as_bytes()).ok(),
            Some(signer.address()),
            "{lib:?}"
        );
    }
}

/// A current ethereum-provider / AppKit proposal — every method optional, chains Kao can't serve
/// first, an `rpcMap` in each namespace, a Solana namespace and `sessionProperties` — connects with
/// exactly what Kao serves, and nothing of the dapp's own echoed back.
#[tokio::test]
async fn sdk_proposal_connects_with_what_kao_serves() {
    let (relay, _dapp, _events, kao, _slot) = testkit::harness().await;
    let caps = testkit::local_eoa_caps(PrivateKeySigner::random().address());
    let dapp = sdk_connect(&relay, &kao, &caps).await;

    let grant = dapp.plan.verdict.clone().expect("granted");
    assert_eq!(
        grant.chains,
        vec![1, 8453, 10],
        "served chains, the dapp's order"
    );
    for unserved in [42_161, 137] {
        let line = dapp
            .plan
            .chains
            .iter()
            .find(|l| l.chain_id == unserved)
            .expect("listed on the card");
        assert!(!line.granted && !line.required, "{unserved}");
    }
    let mut expected_methods: Vec<&str> = testkit::fixtures::ETHEREUM_PROVIDER_METHODS
        .iter()
        .copied()
        .filter(|m| namespaces::SERVED_METHODS.contains(m))
        .collect();
    expected_methods.sort_unstable();

    let settled = &dapp.settle["namespaces"];
    let keys: Vec<&String> = settled.as_object().expect("namespaces").keys().collect();
    assert_eq!(keys, vec!["eip155"], "no Solana namespace: {settled}");
    let eip155 = &settled["eip155"];
    let mut methods: Vec<&str> = eip155["methods"]
        .as_array()
        .expect("methods")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    methods.sort_unstable();
    assert_eq!(methods, expected_methods, "served methods only");
    let mut events: Vec<&str> = eip155["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    events.sort_unstable();
    assert_eq!(events, vec!["accountsChanged", "chainChanged"]);
    assert_eq!(
        eip155["accounts"],
        json!([1, 8453, 10].map(|c| caps.identity.caip10(c)))
    );
    assert!(eip155.get("rpcMap").is_none(), "{eip155}");
    let settle = dapp.settle.to_string();
    assert!(
        !settle.contains("caip154") && !settle.contains("rpc.walletconnect.org"),
        "nothing of the dapp's echoed: {settle}"
    );
    assert_eq!(
        kao.with_book(|b| b.session(&dapp.topic).map(|s| s.chains.clone())),
        Some(vec![1, 8453, 10])
    );
}

/// viem and ethers (v5, v6) `personal_sign`: `[hex message, address]`, the address checksummed or
/// lowercased.
#[tokio::test]
async fn sdk_personal_sign_viem_and_ethers_round_trip() {
    use testkit::fixtures::PersonalSignLib::*;
    sdk_personal_sign_round_trip(&[Viem, EthersV5, EthersV6]).await;
}

/// web3.js 1.x / 4.x `eth.personal.sign(data, address, password)` sends a third param, which is
/// never used.
#[tokio::test]
async fn sdk_personal_sign_web3js_three_params_round_trip() {
    use testkit::fixtures::PersonalSignLib::*;
    sdk_personal_sign_round_trip(&[Web3JsV1, Web3JsV4]).await;
}

/// The legacy `[address, message]` order, unambiguous when only one param is an address.
#[tokio::test]
async fn sdk_personal_sign_legacy_reversed_round_trip() {
    sdk_personal_sign_round_trip(&[testkit::fixtures::PersonalSignLib::LegacyReversed]).await;
}

/// `eth_sendTransaction` as viem and ethers (v5, v6) send it: admitted as exactly the dapp's call,
/// ethers' `gas` taken as the dapp's gas, and the hash Kao answers reaches the dapp.
#[tokio::test]
async fn sdk_send_transaction_library_shapes_round_trip() {
    use testkit::fixtures::{ETHERS_GAS, SendTxLib};
    let (relay, _dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let mut dapp = sdk_connect(&relay, &kao, &caps).await;
    let to = testkit::fixtures::UNIVERSAL_ROUTER;
    let value = alloy::primitives::U256::from(10_000_000_000_000_000u64);
    let data = alloy::hex::decode("3593564c0000").expect("hex");
    let tx_hash = json!(format!("0x{}", "ab".repeat(32)));
    for lib in SendTxLib::ALL {
        let params =
            testkit::fixtures::send_transaction(lib, signer.address(), to, value, &data, 8453);
        let (admitted, got) = dapp
            .call(&kao, &caps, 8453, "eth_sendTransaction", params, |_| {
                tx_hash.clone()
            })
            .await;
        let Ok(Admitted {
            call: WcCall::SendTransaction(t),
            chain_id: 8453,
            ..
        }) = &admitted
        else {
            panic!("{lib:?}: eth_sendTransaction admitted: {admitted:?}");
        };
        assert_eq!(
            (t.from, t.to, t.value, t.data.as_ref(), t.chain_id),
            (signer.address(), to, value, data.as_slice(), 8453),
            "{lib:?}"
        );
        let dapp_gas = match lib {
            SendTxLib::Viem => None,
            SendTxLib::EthersV5 | SendTxLib::EthersV6 => Some(ETHERS_GAS),
        };
        assert_eq!(t.dapp_gas, dapp_gas, "{lib:?}");
        assert!(t.ignored.describe().is_empty(), "{lib:?}: {:?}", t.ignored);
        assert_eq!(got, Ok(tx_hash.clone()), "{lib:?}");
    }
}

/// A hand-built transaction naming its gas limit `gasLimit` (ethers' property name): taken as the
/// dapp's gas, alone or beside an equal `gas`; refused when the two disagree.
#[tokio::test]
async fn sdk_send_transaction_gas_limit_round_trip() {
    let (relay, _dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let mut dapp = sdk_connect(&relay, &kao, &caps).await;
    let to = testkit::fixtures::USDC;
    let data = alloy::hex::decode("a9059cbb").expect("hex");
    let tx_hash = json!(format!("0x{}", "cd".repeat(32)));
    for gas in [None, Some(200_000)] {
        let params = testkit::fixtures::send_transaction_gas_limit(
            signer.address(),
            to,
            &data,
            200_000,
            gas,
        );
        let (admitted, got) = dapp
            .call(&kao, &caps, 1, "eth_sendTransaction", params, |_| {
                tx_hash.clone()
            })
            .await;
        let Ok(Admitted {
            call: WcCall::SendTransaction(t),
            ..
        }) = &admitted
        else {
            panic!("gas={gas:?}: admitted: {admitted:?}");
        };
        assert_eq!(
            t.dapp_gas,
            Some(200_000),
            "gas={gas:?}: gasLimit is the dapp's gas"
        );
        assert_eq!(got, Ok(tx_hash.clone()));
    }
    let params = testkit::fixtures::send_transaction_gas_limit(
        signer.address(),
        to,
        &data,
        200_000,
        Some(21_000),
    );
    let (admitted, got) = dapp
        .call(&kao, &caps, 1, "eth_sendTransaction", params, |_| {
            panic!("a disagreeing gas limit is never reviewed")
        })
        .await;
    assert_eq!(admitted.err().map(|r| r.code), Some(codes::INVALID_PARAMS));
    assert_eq!(got.err().map(|e| e.code), Some(codes::INVALID_PARAMS));
}

/// Permit2 through viem, a Seaport listing and Seaport bulk listings (12, 16 and 20 orders with a
/// creator royalty) through ethers: each admitted, reviewed as the digest alloy signs, and the
/// dapp's signature recovers to the account.
#[tokio::test]
async fn sdk_typed_data_permit2_and_seaport_round_trip() {
    use testkit::fixtures::{
        permit2_permit_single, seaport_bulk_order, seaport_order, sign_typed_data_ethers,
        sign_typed_data_viem,
    };
    let (relay, _dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let mut dapp = sdk_connect(&relay, &kao, &caps).await;
    let me = signer.address();
    let mut cases = vec![
        (
            "Permit2 PermitSingle",
            sign_typed_data_viem(me, &permit2_permit_single(1)),
        ),
        (
            "Seaport order",
            sign_typed_data_ethers(me, &seaport_order(me, true, 1)),
        ),
    ];
    for n in [12, 16, 20] {
        cases.push((
            "Seaport bulk order",
            sign_typed_data_ethers(me, &seaport_bulk_order(me, n, true, 1)),
        ));
    }
    for (what, params) in cases {
        let (admitted, got) = dapp
            .call(&kao, &caps, 1, "eth_signTypedData_v4", params, |a| {
                let WcCall::SignTypedData(tr) = &a.call else {
                    panic!("{what}: typed data: {a:?}");
                };
                let hash = tr.typed.eip712_signing_hash().expect("hashes");
                sig_hex(&signer.sign_hash_sync(&hash).expect("signs"))
            })
            .await;
        let Ok(Admitted {
            call: WcCall::SignTypedData(tr),
            ..
        }) = &admitted
        else {
            panic!("{what}: admitted: {admitted:?}");
        };
        let digest = tr.typed.eip712_signing_hash().expect("hashes");
        assert_eq!(
            tr.checked.digests.digest, digest,
            "{what}: reviewed == signed"
        );
        if what.starts_with("Permit2") {
            assert!(
                matches!(&tr.checked.kind, TypedKind::Allowance(g) if g.unlimited && g.spender == testkit::fixtures::UNIVERSAL_ROUTER),
                "{what}: {:?}",
                tr.checked.kind
            );
        }
        let sig = sig_of(&got.unwrap_or_else(|e| panic!("{what}: {e:?}")));
        assert_eq!(
            sig.recover_address_from_prehash(&digest).ok(),
            Some(me),
            "{what}"
        );
    }
}

#[tokio::test]
async fn user_reject_reaches_dapp_as_4001() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp = testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let session = connect(&kao, resp, &caps).await;
    let call = testkit::dapp_request(
        &dapp,
        &session.topic,
        1,
        "personal_sign",
        testkit::personal_sign_params("no thanks", signer.address()),
    );
    let (key, admitted) = admit_next(&kao, &caps).await;
    assert!(admitted.is_ok());
    assert!(kao.with_book(|b| b.mark_in_review(&key, 1)));
    kao.answer(&key, Answer::Refuse(Refusal::user_rejected()));
    let result = testkit::dapp_result(call).await;
    let Err(wallet_connect::Error::Peer(e)) = result else {
        panic!("a peer error: {result:?}");
    };
    assert_eq!(e, ErrorObject::new(4001, "User rejected the request."));
}

#[tokio::test]
async fn from_mismatch_is_refused_without_ui() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp = testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let session = connect(&kao, resp, &caps).await;
    let stranger = PrivateKeySigner::random().address();
    let call = testkit::dapp_request(
        &dapp,
        &session.topic,
        1,
        "personal_sign",
        testkit::personal_sign_params("sign as someone else", stranger),
    );
    let (key, admitted) = admit_next(&kao, &caps).await;
    assert_eq!(admitted.err().map(|r| r.code), Some(codes::UNAUTHORIZED));
    assert_eq!(peer_code(&testkit::dapp_result(call).await), Some(4100));
    assert!(
        kao.with_book(|b| b.request(&key).is_none()),
        "nothing queued"
    );
    assert_eq!(kao.snapshot(now_secs()).refused_count, 1);
}

#[tokio::test]
async fn eth_sign_refused_4200_when_required() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    // An older wagmi dapp that won't connect without eth_sign.
    let required = testkit::eip155(&[1], &["eth_sign", "personal_sign"], &[]);
    let resp = testkit::dapp_connect(&dapp, required, BTreeMap::new()).await;
    let session = connect(&kao, resp, &caps).await;
    assert!(
        session
            .namespaces
            .get("eip155")
            .is_some_and(|ns| ns.methods.iter().any(|m| m == "eth_sign")),
        "granted because required — refused per call"
    );
    let params = json!([
        signer.address().to_checksum(None),
        format!("0x{}", "11".repeat(32))
    ]);
    let call = testkit::dapp_request(&dapp, &session.topic, 1, "eth_sign", params);
    let (_key, admitted) = admit_next(&kao, &caps).await;
    assert_eq!(
        admitted.err().map(|r| r.code),
        Some(codes::UNSUPPORTED_METHOD)
    );
    assert_eq!(peer_code(&testkit::dapp_result(call).await), Some(4200));
}

#[tokio::test]
async fn unsupported_required_chain_rejected_5100() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let caps = testkit::local_eoa_caps(PrivateKeySigner::random().address());
    // Arbitrum isn't among the chains Kao serves to this identity.
    let required = testkit::eip155(&[42_161], &["personal_sign"], &[]);
    let resp = testkit::dapp_connect(&dapp, required, BTreeMap::new()).await;
    kao.pair(testkit::uri_of(&resp), now_secs())
        .expect("the link pairs");
    let p = testkit::wait_card(&kao).await;
    let plan = namespaces::plan_proposal(&p, &caps, &label);
    let block = plan.verdict.expect_err("Kao can't serve a required chain");
    assert_eq!(block.code, 5100);
    kao.reject_proposal(p.id, namespaces::proposal_reject_error(&block));
    let approval = tokio::time::timeout(Duration::from_secs(5), resp.approval)
        .await
        .expect("the dapp hears back");
    let Err(wallet_connect::Error::Peer(e)) = approval else {
        panic!("rejected: {approval:?}");
    };
    assert_eq!(e.code, 5100);
    testkit::settle(|| kao.card_proposal().is_none()).await;
    assert!(kao.card_proposal().is_none());
    assert!(kao.snapshot(now_secs()).sessions.is_empty());
}

/// Kao deletes the pasted pairing once the settle ack resolves, so the only window in which an
/// unsolicited proposal can reach Kao over a pasted pairing is before that — driven here
/// deterministically: the dapp proposes again over the same pairing while the first card is open.
#[tokio::test]
async fn unsolicited_proposal_on_active_pairing_is_rejected() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let caps = testkit::local_eoa_caps(PrivateKeySigner::random().address());
    let resp = testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let pairing = resp.pairing_topic.clone();
    kao.pair(testkit::uri_of(&resp), now_secs())
        .expect("the link pairs");
    let first = testkit::wait_card(&kao).await;

    let again = dapp
        .connect(ConnectParams {
            optional_namespaces: testkit::modern_optional(&[1]),
            pairing_topic: Some(pairing.clone()),
            ..Default::default()
        })
        .await
        .expect("the dapp proposes over its existing pairing");
    let refused = tokio::time::timeout(Duration::from_secs(5), again.approval)
        .await
        .expect("the dapp hears back");
    assert_eq!(peer_code(&refused.map(|_| Value::Null)), Some(5000));
    assert_eq!(
        kao.card_proposal().map(|p| p.id),
        Some(first.id),
        "one card per paste"
    );

    let plan = namespaces::plan_proposal(&first, &caps, &label);
    kao.approve(testkit::ticket(
        &first,
        &caps,
        plan.verdict.expect("grants"),
    ))
    .expect("approve starts");
    tokio::time::timeout(Duration::from_secs(5), resp.approval)
        .await
        .expect("approval in time")
        .expect("session");
    // After the settle ack Kao drops the pairing: nothing can propose over it any more.
    testkit::settle(|| !kao.client().pairings().iter().any(|p| p.topic == pairing)).await;
    assert!(!kao.client().pairings().iter().any(|p| p.topic == pairing));
    testkit::settle(|| !dapp.pairings().iter().any(|p| p.topic == pairing)).await;
    let late = dapp
        .connect(ConnectParams {
            optional_namespaces: testkit::modern_optional(&[1]),
            pairing_topic: Some(pairing),
            ..Default::default()
        })
        .await;
    assert!(matches!(late, Err(wallet_connect::Error::NoPairing(_))));
}

#[tokio::test]
async fn switch_chain_answers_null_and_emits_chain_changed() {
    let (_relay, dapp, mut dapp_events, kao, _slot) = testkit::harness().await;
    let caps = testkit::local_eoa_caps(PrivateKeySigner::random().address());
    let resp =
        testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1, 8453])).await;
    let session = connect(&kao, resp, &caps).await;
    let call = testkit::dapp_request(
        &dapp,
        &session.topic,
        1,
        "wallet_switchEthereumChain",
        json!([{ "chainId": "0x2105" }]),
    );
    let (_key, admitted) = admit_next(&kao, &caps).await;
    assert!(matches!(
        admitted,
        Ok(Admitted {
            call: WcCall::SwitchChain { chain_id: 8453 },
            ..
        })
    ));
    assert_eq!(testkit::dapp_result(call).await.ok(), Some(Value::Null));
    loop {
        match testkit::next_dapp_event(&mut dapp_events).await {
            SignEvent::SessionEvent {
                topic,
                chain_id,
                event,
                ..
            } => {
                assert_eq!(topic, session.topic);
                assert_eq!(chain_id, caip2(8453));
                assert_eq!(event.name, "chainChanged");
                assert_eq!(event.data, json!(8453));
                break;
            }
            _ => continue,
        }
    }
}

#[tokio::test]
async fn wallet_disconnect_notifies_dapp() {
    let (_relay, dapp, mut dapp_events, kao, _slot) = testkit::harness().await;
    let caps = testkit::local_eoa_caps(PrivateKeySigner::random().address());
    let resp = testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let session = connect(&kao, resp, &caps).await;
    kao.disconnect(&session.topic);
    assert!(
        kao.snapshot(now_secs()).sessions.is_empty(),
        "gone from Kao at once"
    );
    loop {
        if let SignEvent::SessionDelete { topic, reason, .. } =
            testkit::next_dapp_event(&mut dapp_events).await
        {
            assert_eq!(topic, session.topic);
            assert_eq!(reason.code, 6000);
            break;
        }
    }
    testkit::settle(|| kao.with_book(|b| b.is_idle())).await;
    assert!(
        kao.with_book(|b| b.is_idle()),
        "the disconnect was delivered"
    );
}

#[tokio::test]
async fn dapp_disconnect_drops_queue() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp = testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let session = connect(&kao, resp, &caps).await;
    let params = testkit::personal_sign_params("one", signer.address());
    let _a = testkit::dapp_request(&dapp, &session.topic, 1, "personal_sign", params.clone());
    let (in_review, _) = admit_next(&kao, &caps).await;
    let _b = testkit::dapp_request(&dapp, &session.topic, 1, "personal_sign", params);
    let (waiting, _) = admit_next(&kao, &caps).await;
    assert!(kao.with_book(|b| b.mark_in_review(&in_review, 1)));

    dapp.disconnect(&session.topic)
        .await
        .expect("dapp disconnects");
    let gone = testkit::next_ui(&kao.events(), |e| matches!(e, UiEffect::RequestGone { .. })).await;
    assert_eq!(
        gone,
        UiEffect::RequestGone {
            key: in_review.clone(),
            reason: GoneReason::DappDisconnected
        }
    );
    assert!(kao.with_book(|b| b.request(&waiting).is_none() && b.request(&in_review).is_none()));
    assert!(kao.snapshot(now_secs()).sessions.is_empty());
}

#[tokio::test]
async fn signature_discarded_when_dapp_disconnects_mid_sign() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp = testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let session = connect(&kao, resp, &caps).await;
    let call = testkit::dapp_request(
        &dapp,
        &session.topic,
        1,
        "personal_sign",
        testkit::personal_sign_params("slow device", signer.address()),
    );
    let (key, admitted) = admit_next(&kao, &caps).await;
    let Ok(Admitted {
        call: WcCall::PersonalSign(ps),
        ..
    }) = admitted
    else {
        panic!("admitted: {admitted:?}");
    };
    to_signing(&kao, &key, 1);
    let guard = kao.before_send_guard(key.clone());
    assert!(kao.is_live(&key) && guard().is_ok());

    // The device is still busy when the dapp gives up.
    dapp.disconnect(&session.topic)
        .await
        .expect("dapp disconnects");
    testkit::settle(|| !kao.is_live(&key)).await;
    assert!(!kao.is_live(&key));
    assert!(guard().is_err(), "nothing irreversible may happen now");
    assert_eq!(kao.failure_class(&key), FailureClass::Gone);

    let sig = signer.sign_message_sync(&ps.message).expect("signs");
    kao.answer(&key, Answer::Result(sig_hex(&sig)));
    assert!(kao.with_book(|b| b.request(&key).is_none() && b.outbox_len() == 0));
    assert_eq!(kao.snapshot(now_secs()).undelivered, 0);
    assert!(
        testkit::dapp_result(call).await.is_err(),
        "the dapp got no signature"
    );
}

#[tokio::test]
async fn respond_retries_after_relay_reconnect() {
    let (relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp = testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let session = connect(&kao, resp, &caps).await;
    let call = testkit::dapp_request(
        &dapp,
        &session.topic,
        1,
        "personal_sign",
        testkit::personal_sign_params("through the outage", signer.address()),
    );
    let (key, admitted) = admit_next(&kao, &caps).await;
    let Ok(Admitted {
        call: WcCall::PersonalSign(ps),
        ..
    }) = admitted
    else {
        panic!("admitted: {admitted:?}");
    };
    to_signing(&kao, &key, 1);
    let sig = signer.sign_message_sync(&ps.message).expect("signs");

    relay.disconnect_all();
    kao.answer(&key, Answer::Result(sig_hex(&sig)));
    let result = testkit::dapp_result(call)
        .await
        .expect("delivered after the reconnect");
    assert_eq!(result, sig_hex(&sig));
    testkit::settle(|| kao.with_book(|b| b.snapshot(now_secs()).undelivered == 0)).await;
    assert!(
        kao.client().pending_requests().is_empty(),
        "answered exactly once"
    );
    assert!(kao.with_book(|b| b.outbox_len() == 0));
}

#[tokio::test]
async fn request_expiry_is_reported() {
    let (relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp = testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let session = connect(&kao, resp, &caps).await;
    // A dapp SignClient refuses expiries under 5 min; a raw peer on the same session doesn't.
    let key = testkit::session_key(&dapp, &session.topic);
    let mut raw = RawPeer::attach(&relay, "raw");
    let expiry = now_secs() + 2;
    let params = testkit::personal_sign_params("hurry", signer.address());
    for id in [501, 502] {
        let request =
            json!({ "method": "personal_sign", "params": params, "expiryTimestamp": expiry });
        raw.inject_request(&session.topic, &key, id, 1, request)
            .await;
    }
    let (mut reviewing, mut signing) = (None, None);
    for _ in 0..2 {
        let (k, admitted) = admit_next(&kao, &caps).await;
        assert!(admitted.is_ok());
        // Opened at once: a waiting request this close to its deadline is dropped by the next tick.
        if k.id == 501 {
            assert!(kao.with_book(|b| b.mark_in_review(&k, 1)));
            reviewing = Some(k);
        } else {
            to_signing(&kao, &k, 2);
            signing = Some(k);
        }
    }
    let (reviewing, signing) = (reviewing.expect("501"), signing.expect("502"));
    // Inside the 5 s margin already: dead for Kao though the crate still holds it.
    assert!(!kao.is_live(&signing) && !kao.is_live(&reviewing));

    let gone = testkit::next_ui(&kao.events(), |e| matches!(e, UiEffect::RequestGone { .. })).await;
    assert_eq!(
        gone,
        UiEffect::RequestGone {
            key: reviewing.clone(),
            reason: GoneReason::Expired
        }
    );
    // The crate's own sweep reports the signing one.
    testkit::settle_within(SWEEP_WAIT, || {
        kao.with_book(|b| b.request(&signing).and_then(|q| q.gone)) == Some(GoneReason::Expired)
    })
    .await;
    assert_eq!(
        kao.with_book(|b| b.request(&signing).and_then(|q| q.gone)),
        Some(GoneReason::Expired)
    );
    assert!(!kao.client().pending_requests().iter().any(|p| p.id == 502));
    assert!(kao.with_book(|b| b.request(&reviewing).is_none()));
}

#[tokio::test]
async fn colliding_ids_on_two_sessions() {
    let (relay, dapp_a, _events, kao, _slot) = testkit::harness().await;
    let (dapp_b, _events_b) = testkit::dapp_client(&relay, "dapp-b").await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp_a =
        testkit::dapp_connect(&dapp_a, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let a = connect(&kao, resp_a, &caps).await;
    let resp_b =
        testkit::dapp_connect(&dapp_b, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let b = connect(&kao, resp_b, &caps).await;
    let (key_a, key_b) = (
        testkit::session_key(&dapp_a, &a.topic),
        testkit::session_key(&dapp_b, &b.topic),
    );
    let mut raw = RawPeer::attach(&relay, "raw");
    raw.subscribe(&a.topic).await;
    raw.subscribe(&b.topic).await;
    let params = testkit::personal_sign_params("same id", signer.address());
    let request = json!({ "method": "personal_sign", "params": params });

    // Session A's request 777 …
    raw.inject_request(&a.topic, &key_a, 777, 1, request.clone())
        .await;
    let (ka, admitted) = admit_next(&kao, &caps).await;
    assert!(admitted.is_ok());
    assert_eq!(
        ka,
        WcKey {
            topic: a.topic.clone(),
            id: 777
        }
    );
    kao.answer(&ka, Answer::Refuse(Refusal::user_rejected()));
    let on_a = raw.next_response(&a.topic, &key_a, 777).await;
    assert_eq!(on_a.err().map(|e| e.code), Some(4001));

    // … then session B's own 777 is a different request, not a replay.
    raw.inject_request(&b.topic, &key_b, 777, 1, request).await;
    let (kb, admitted) = admit_next(&kao, &caps).await;
    assert!(admitted.is_ok());
    assert_eq!(
        kb,
        WcKey {
            topic: b.topic.clone(),
            id: 777
        }
    );
    assert_eq!(
        kao.with_book(|bk| bk.state_of(&kb)),
        Some(QueueState::Waiting)
    );
    to_signing(&kao, &kb, 1);
    kao.answer(&kb, Answer::Result(json!("0xb0b")));
    let on_b = raw.next_response(&b.topic, &key_b, 777).await;
    assert_eq!(on_b, Ok(json!("0xb0b")));
}

#[tokio::test]
async fn teardown_notifies_every_dapp_and_closes() {
    let (relay, dapp_a, mut events_a, kao, slot) = testkit::harness().await;
    let (dapp_b, mut events_b) = testkit::dapp_client(&relay, "dapp-b").await;
    let signer = PrivateKeySigner::random();
    let caps = testkit::local_eoa_caps(signer.address());
    let resp_a =
        testkit::dapp_connect(&dapp_a, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let a = connect(&kao, resp_a, &caps).await;
    let resp_b =
        testkit::dapp_connect(&dapp_b, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let b = connect(&kao, resp_b, &caps).await;
    let queued = testkit::dapp_request(
        &dapp_a,
        &a.topic,
        1,
        "personal_sign",
        testkit::personal_sign_params("left waiting", signer.address()),
    );
    let (key, _) = admit_next(&kao, &caps).await;
    assert_eq!(
        kao.with_book(|bk| bk.state_of(&key)),
        Some(QueueState::Waiting)
    );

    // Lock: the App closes the slot and tears the runtime down.
    let rt = slot.close().expect("installed");
    rt.mark_closed();
    rt.teardown(TEARDOWN_PER_PHASE).await;

    assert_eq!(peer_code(&testkit::dapp_result(queued).await), Some(4900));
    for (events, topic) in [(&mut events_a, &a.topic), (&mut events_b, &b.topic)] {
        loop {
            if let SignEvent::SessionDelete { topic: t, .. } =
                testkit::next_dapp_event(events).await
            {
                assert_eq!(&t, topic);
                break;
            }
        }
    }
    assert!(kao.is_closed());
    assert!(
        kao.pair(zeroize::Zeroizing::new("wc:late".into()), now_secs())
            .is_err()
    );
    let fresh =
        testkit::dapp_connect(&dapp_a, BTreeMap::new(), testkit::modern_optional(&[1])).await;
    let uri = testkit::uri_of(&fresh);
    assert!(matches!(
        kao.client().pair(&uri).await,
        Err(wallet_connect::Error::Closed)
    ));
}

#[tokio::test]
async fn safe_session_exposes_single_chain() {
    let (_relay, dapp, _events, kao, _slot) = testkit::harness().await;
    let caps = testkit::safe_caps(SAFE, 8453, 1, 1);
    let resp =
        testkit::dapp_connect(&dapp, BTreeMap::new(), testkit::modern_optional(&[1, 8453])).await;
    let session = connect(&kao, resp, &caps).await;
    assert_eq!(
        session.accounts(),
        vec![format!("eip155:8453:{}", SAFE.to_checksum(None))]
    );
    let bound = kao
        .with_book(|b| b.session(&session.topic).cloned())
        .expect("bound");
    assert_eq!(
        bound.identity,
        WcIdentity::Safe {
            address: SAFE,
            chain_id: 8453
        }
    );
    assert_eq!(bound.chains, vec![8453]);
}

/// A dapp that answers Kao's settlement with an error: only the approval's ack sees it (the crate
/// deletes the session without an event), and the book must drop the session and its pairing.
#[tokio::test]
async fn settle_refusal_removes_session() {
    let (relay, _dapp, _events, kao, _slot) = testkit::harness().await;
    let caps = testkit::local_eoa_caps(PrivateKeySigner::random().address());
    let mut raw = RawPeer::attach(&relay, "raw-dapp");

    // The raw dapp shows a link and proposes over it.
    let pairing_key = SymKey::generate();
    let link = PairingUri::new(pairing_key.clone(), now_secs() + 300);
    let pairing = link.topic.clone();
    raw.subscribe(&pairing).await;
    let proposer = KeyPair::generate();
    let propose = SessionProposeParams {
        relays: vec![Relay::default()],
        proposer: Participant {
            public_key: proposer.public_key(),
            metadata: testkit::dapp_meta("refuser"),
        },
        required_namespaces: BTreeMap::new(),
        optional_namespaces: testkit::modern_optional(&[1]),
        session_properties: None,
        scoped_properties: None,
        expiry_timestamp: Some(now_secs() + 300),
        pairing_topic: Some(pairing.clone()),
    };
    let propose = Request::with_id(
        9_001,
        "wc_sessionPropose",
        serde_json::to_value(propose).expect("serializes"),
    );
    raw.publish(
        &pairing,
        &pairing_key,
        &serde_json::to_value(propose).expect("serializes"),
        1100,
    )
    .await;

    kao.pair(zeroize::Zeroizing::new(link.to_string()), now_secs())
        .expect("the link pairs");
    let p = testkit::wait_card(&kao).await;
    let plan = namespaces::plan_proposal(&p, &caps, &label);
    kao.approve(testkit::ticket(&p, &caps, plan.verdict.expect("grants")))
        .expect("approve starts");

    // Kao answers the proposal on the pairing, then settles on the derived session topic.
    let Payload::Response(Response {
        outcome: Ok(answer),
        ..
    }) = raw.next_on(&pairing, &pairing_key).await
    else {
        panic!("the proposal response");
    };
    let answer: SessionProposeResponse = serde_json::from_value(answer).expect("propose response");
    let responder: PublicKey = answer.responder_public_key;
    let session_key = proposer.derive_sym_key(&responder).expect("derives");
    let session: Topic = session_key.topic();
    raw.subscribe(&session).await;
    let Payload::Request(settle) = raw.next_on(&session, &session_key).await else {
        panic!("the settlement");
    };
    assert_eq!(settle.method, "wc_sessionSettle");
    testkit::settle(|| kao.with_book(|b| b.session(&session).is_some())).await;
    assert!(kao.with_book(|b| b.session(&session).is_some()));

    let refusal = Response::error(settle.id, ErrorObject::new(5000, "not today"));
    raw.publish(
        &session,
        &session_key,
        &serde_json::to_value(refusal).expect("serializes"),
        1103,
    )
    .await;
    let notice = testkit::next_ui(&kao.events(), |e| matches!(e, UiEffect::Notice { .. })).await;
    assert!(matches!(notice, UiEffect::Notice { text } if text.contains("declined")));
    assert!(kao.with_book(|b| b.session(&session).is_none()));
    // And the pasted pairing goes too: nothing can propose over it again.
    testkit::settle(|| !kao.client().pairings().iter().any(|p| p.topic == pairing)).await;
    assert!(!kao.client().pairings().iter().any(|p| p.topic == pairing));
}

/// Under Kao's default log filter a dapp can't write into Kao's log. The protocol crate echoes the
/// text of a dapp's settlement refusal in a warning, and that text can carry a newline and a
/// forged Kao line after it; Kao's own lines keep logging.
#[tokio::test]
async fn a_dapps_text_stays_out_of_the_default_log() {
    let (_guard, log) = testkit::capture_logs(crate::DEFAULT_LOG_FILTER);
    let (relay, _dapp, _events, kao, _slot) = testkit::harness().await;
    let caps = testkit::local_eoa_caps(PrivateKeySigner::random().address());
    let mut raw = RawPeer::attach(&relay, "raw-dapp");
    let pairing_key = SymKey::generate();
    let link = PairingUri::new(pairing_key.clone(), now_secs() + 300);
    let pairing = link.topic.clone();
    raw.subscribe(&pairing).await;
    let proposer = KeyPair::generate();
    let propose = SessionProposeParams {
        relays: vec![Relay::default()],
        proposer: Participant {
            public_key: proposer.public_key(),
            metadata: testkit::dapp_meta("forger"),
        },
        required_namespaces: BTreeMap::new(),
        optional_namespaces: testkit::modern_optional(&[1]),
        session_properties: None,
        scoped_properties: None,
        expiry_timestamp: Some(now_secs() + 300),
        pairing_topic: Some(pairing.clone()),
    };
    let propose = Request::with_id(
        9_002,
        "wc_sessionPropose",
        serde_json::to_value(propose).expect("serializes"),
    );
    raw.publish(
        &pairing,
        &pairing_key,
        &serde_json::to_value(propose).expect("serializes"),
        1100,
    )
    .await;
    kao.pair(zeroize::Zeroizing::new(link.to_string()), now_secs())
        .expect("the link pairs");
    let p = testkit::wait_card(&kao).await;
    let plan = namespaces::plan_proposal(&p, &caps, &label);
    kao.approve(testkit::ticket(&p, &caps, plan.verdict.expect("grants")))
        .expect("approve starts");
    let Payload::Response(Response {
        outcome: Ok(answer),
        ..
    }) = raw.next_on(&pairing, &pairing_key).await
    else {
        panic!("the proposal response");
    };
    let answer: SessionProposeResponse = serde_json::from_value(answer).expect("propose response");
    let session_key = proposer
        .derive_sym_key(&answer.responder_public_key)
        .expect("derives");
    let session: Topic = session_key.topic();
    raw.subscribe(&session).await;
    let Payload::Request(settle) = raw.next_on(&session, &session_key).await else {
        panic!("the settlement");
    };
    testkit::settle(|| kao.with_book(|b| b.session(&session).is_some())).await;

    let forged = "DAPP-CONTROLLED\n2026-10-13T00:00:00Z  INFO kao::ui: wc: dapp transaction \
                  broadcast hash=0xdead";
    let refusal = Response::error(settle.id, ErrorObject::new(5000, forged));
    raw.publish(
        &session,
        &session_key,
        &serde_json::to_value(refusal).expect("serializes"),
        1103,
    )
    .await;
    testkit::settle(|| kao.with_book(|b| b.session(&session).is_none())).await;
    assert!(kao.with_book(|b| b.session(&session).is_none()));

    let log = log.text();
    assert!(
        !log.contains("DAPP-CONTROLLED"),
        "the dapp's text reached the log:\n{log}"
    );
    assert!(
        log.contains("WalletConnect session approved")
            && log.contains("the dapp refused the session settlement code=5000"),
        "Kao's own lines still log:\n{log}"
    );
}
