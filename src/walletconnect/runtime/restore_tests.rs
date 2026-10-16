//! Saved state, suspend and restore, end to end on the in-process relay: a runtime persisting to an
//! in-memory vault is locked (suspended) and unlocked (restored) under the SAME relay client id —
//! as production reuses the relay identity, so the relay never pushes again what that id took.
//!
//! "The store" here is what a lock leaves in the vault ([`Saved`]) handed back at the next unlock —
//! in the form the vault's writer puts it on disk ([`disk_form`]).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use alloy::primitives::{Address, B256, Bytes, address, keccak256};
use serde_json::{Value, json};
use wallet_connect::relay::{Connector, RelayServer};
use wallet_connect::sign::{SignClient, SignEvent, SignEvents};
use zeroize::Zeroizing;

use super::tests::{Tap, is_publish, tapped};
use super::*;
use crate::sign::digest::{
    DOMAIN_HASH_LABEL, EIP191_DIGEST_LABEL, EIP712_DIGEST_LABEL, MESSAGE_HASH_LABEL,
};
use crate::vault::{
    AccountRef, AckRecord, ConnectionRecord, DigestRow, NewConnection, SignOrigin, SignedKind,
    SignedPayload, SignedRecord,
};
use crate::wallet::{DataKey, KeyOrigin, KeyStatus, SealedLoad, SealedRows};
use crate::walletconnect::persist::PersistedRoute;
use crate::walletconnect::testkit::{self, TEST_DATA_KEY};

const ADDR: Address = address!("ab16a96D359eC26a11e2C2b3d8f8B8942d5Bfcdb");
const TURN_OFF: &str = "You turned WalletConnect off.";
/// How long a vault writer's drain may take to end (its bounded retries, should the test store
/// refuse writes).
const DRAIN_BOUND: Duration = Duration::from_secs(10);

/// What a lock leaves for the next unlock: the saved state and the history.
struct Saved {
    wc_state: Option<Zeroizing<Vec<u8>>>,
    connections: Vec<ConnectionRecord>,
    signed: Vec<SignedRecord>,
}

impl Saved {
    fn record(&self) -> WcStateRecord {
        WcStateRecord::decode(self.wc_state.as_ref().expect("a saved state")).expect("decodes")
    }
}

/// A signed record as the vault writes it to disk: its raw signature only once delivered.
fn disk_form(mut r: SignedRecord) -> SignedRecord {
    if r.delivery != Delivery::Delivered {
        r.signature = None;
    }
    r
}

/// Lock with a data key, as the App does: the vault's epoch ends, the slot closes and its runtime
/// suspends (counted until done). Returns the slot the next unlock gets and what the store holds.
async fn lock_wallet(vault: &Vault, slot: &WcSlot) -> (WcSlot, Saved) {
    let connections = vault.connections();
    let signed = vault.signed().into_iter().map(disk_form).collect();
    let flush = vault.lock();
    let next = slot.successor();
    let rt = slot.close().expect("a runtime is installed");
    slot.spawn_suspend(rt, flush)
        .await
        .expect("the suspend task");
    vault.wait_writer_idle().await;
    let wc_state = vault.last_saved_wc_state().flatten();
    let saved = Saved {
        wc_state,
        connections,
        signed,
    };
    (next, saved)
}

fn rows<T: serde::Serialize>(records: &[T], id: impl Fn(&T) -> u64) -> SealedRows {
    SealedRows {
        rows: records
            .iter()
            .map(|r| {
                let json = serde_json::to_vec(r).expect("a record serializes");
                (id(r), Zeroizing::new(json))
            })
            .collect(),
        dropped: 0,
    }
}

/// Unlock again with what the store holds.
fn unlock(vault: &Vault, saved: &Saved) {
    vault.unlock(
        Some(DataKey::for_test(TEST_DATA_KEY)),
        KeyStatus::Ok,
        SealedLoad {
            wc_state: saved.wc_state.clone(),
            connections: rows(&saved.connections, |r| r.id),
            signed: rows(&saved.signed, |r| r.id),
        },
    );
}

/// Restore over the in-process relay as the settings would have it: the same relay, a route as
/// private as the saved one.
async fn restore(slot: &WcSlot, relay: &RelayServer) -> RestoreOutcome {
    restore_with_connector(
        slot,
        relay.connector("kao"),
        TEST_RELAY_URL,
        RouteKind::Loopback,
    )
    .await
}

/// The in-process relay under Kao's client id, counting dials.
fn counted(relay: &RelayServer) -> (impl Connector, Arc<AtomicUsize>) {
    let dials = Arc::new(AtomicUsize::new(0));
    let (relay, n) = (relay.clone(), dials.clone());
    let connector = move || {
        n.fetch_add(1, Ordering::SeqCst);
        let conn = relay.accept("kao");
        async move { wallet_connect::Result::Ok(conn) }
    };
    (connector, dials)
}

/// Every dapp event within `window`, relay connectivity aside.
async fn dapp_events_for(events: &mut SignEvents, window: Duration) -> Vec<SignEvent> {
    let mut seen = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(Some(e)) = tokio::time::timeout_at(deadline, events.recv()).await {
        if !matches!(e, SignEvent::RelayConnected | SignEvent::RelayDisconnected) {
            seen.push(e);
        }
    }
    seen
}

fn deletes(events: &[SignEvent]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, SignEvent::SessionDelete { .. }))
        .count()
}

/// The dapp asks for personal_sign of "hi".
fn ask(dapp: &SignClient, topic: &Topic) -> testkit::DappCall {
    testkit::dapp_request(
        dapp,
        topic,
        1,
        "personal_sign",
        testkit::personal_sign_params("hi", ADDR),
    )
}

/// The dashboard's admission of the next request, taken up to Signing.
async fn to_signing(kao: &WcRuntime) -> WcKey {
    let (req, at) = testkit::next_request(&kao.events()).await;
    let key = WcKey {
        topic: req.topic.clone(),
        id: req.id,
    };
    kao.admit(&req, at, Ok(testkit::admitted_personal(ADDR, 1, "hi")));
    kao.with_book(|b| {
        assert!(b.mark_in_review(&key, 1));
        assert!(b.mark_signing(&key, 1));
    });
    key
}

fn signature() -> (Bytes, Value) {
    let bytes = Bytes::from(vec![0x11; 65]);
    let hex = json!(format!("0x{}", alloy::hex::encode(&bytes)));
    (bytes, hex)
}

fn peer_error(result: wallet_connect::Result<Value>) -> wallet_connect::rpc::ErrorObject {
    match result {
        Err(wallet_connect::Error::Peer(e)) => e,
        other => panic!("the dapp got an error from Kao: {other:?}"),
    }
}

async fn saved_state(vault: &Vault) -> Option<WcStateRecord> {
    vault.wait_writer_idle().await;
    vault
        .last_saved_wc_state()
        .flatten()
        .map(|b| WcStateRecord::decode(&b).expect("decodes"))
}

fn cleared(vault: &Vault) -> bool {
    matches!(vault.last_saved_wc_state(), Some(None))
}

/// Kao's first connection refuses every publish of `tag` while `refuse` is set; counts them.
fn refusing(
    relay: &RelayServer,
    tag: u64,
    refuse: &Arc<AtomicBool>,
) -> (impl Connector, Arc<AtomicUsize>) {
    let tries = Arc::new(AtomicUsize::new(0));
    let (refuse, n) = (refuse.clone(), tries.clone());
    let connector = tapped(
        relay.clone(),
        move |v| {
            if !is_publish(v, tag) {
                return Tap::Pass;
            }
            n.fetch_add(1, Ordering::SeqCst);
            match refuse.load(Ordering::SeqCst) {
                true => Tap::Fail,
                false => Tap::Pass,
            }
        },
        |_| Tap::Pass,
    );
    (connector, tries)
}

/// Kao over `connector`, persisting to `vault`, installed in a slot over it.
async fn kao_over(vault: &Vault, connector: impl Connector) -> (WcRuntime, WcSlot) {
    let kao = WcRuntime::start_with_connector_in(
        connector,
        next_generation(),
        RouteKind::Loopback,
        vault.session(),
    )
    .await
    .expect("starts");
    let slot = WcSlot::with_vault(vault.clone());
    slot.install(kao.clone()).expect("installs");
    (kao, slot)
}

/// The in-process relay under Kao's client id, once `gate` is notified; `dialed` once asked.
fn gated(
    relay: &RelayServer,
    gate: &Arc<tokio::sync::Notify>,
    dialed: &Arc<AtomicBool>,
) -> impl Connector {
    let (relay, gate, dialed) = (relay.clone(), gate.clone(), dialed.clone());
    move || {
        dialed.store(true, Ordering::SeqCst);
        let (relay, gate) = (relay.clone(), gate.clone());
        async move {
            gate.notified().await;
            wallet_connect::Result::Ok(relay.accept("kao"))
        }
    }
}

/// A send and its quick re-sends all refused: the answer (or disconnect) waits for the relay —
/// in no hurry, the housekeeper's next re-send being seconds away.
async fn wait_out_quick_resends(tries: &AtomicUsize) {
    testkit::settle(|| tries.load(Ordering::SeqCst) >= 3).await;
    assert!(
        tries.load(Ordering::SeqCst) >= 3,
        "the send and its quick re-sends"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
}

fn notices(rt: &WcRuntime) -> Vec<String> {
    rt.snapshot(now_secs())
        .notices
        .into_iter()
        .map(|n| n.text)
        .collect()
}

#[tokio::test]
async fn restore_round_trip_serves_a_request_sent_while_kao_was_away() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    let record = saved.record();
    assert_eq!(record.session_count(), 1);
    assert!(record.identity_seed.is_some());
    // The dapp asks while Kao is away: the relay keeps it for Kao's client id.
    let call = ask(&dapp, &topic);
    unlock(&vault, &saved);

    let outcome = restore(&next, &relay).await;
    let rt = next.get().expect("restored and installed");
    assert_eq!(
        outcome,
        RestoreOutcome::Restored {
            sessions: 1,
            generation: rt.generation()
        }
    );
    assert!(next.restore_view().is_none() && !next.is_starting());
    assert_eq!(
        rt.state_record().identity_seed.map(|s| *s.expose()),
        record.identity_seed.as_ref().map(|s| *s.expose()),
        "the saved relay identity, reused (the relay pushes nothing twice to it)"
    );
    let bound = rt
        .with_book(|b| b.session(&topic).cloned())
        .expect("the book was seeded");
    assert_eq!(bound.identity, WcIdentity::Eoa { address: ADDR });
    assert_eq!((bound.ordinal, bound.chains.as_slice()), (1, &[1u64][..]));

    // The request reaches review, and the answer reaches the dapp.
    let key = to_signing(&rt).await;
    assert_eq!(key.topic, topic);
    rt.answer(&key, Answer::Result(json!("0xfeed")));
    assert_eq!(
        testkit::dapp_result(call).await.expect("a result"),
        json!("0xfeed")
    );
    let records = vault.connections();
    assert_eq!(records.len(), 1);
    assert!(records[0].is_open(), "the lock ended nothing: {records:?}");
}

#[tokio::test]
async fn suspend_sends_no_delete_and_saves_the_state() {
    let vault = testkit::keyed_vault();
    let (_relay, dapp, mut events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let flush = vault.lock();
    let rt = slot.close().expect("installed");
    let running = slot.spawn_suspend(rt, flush);
    assert!(
        kao.is_closed(),
        "closed synchronously: a signature still in flight broadcasts nothing"
    );
    assert!(slot.teardowns_running() >= 1, "counted while it runs");
    running.await.expect("the suspend task");
    // The writer's drain is counted until it ends (bounded retries if the disk refuses).
    testkit::settle_within(DRAIN_BOUND, || slot.teardowns_running() == 0).await;
    assert_eq!(slot.teardowns_running(), 0, "the writer's drain ended too");
    assert!(!kao.client().relay().is_connected());

    assert_eq!(
        deletes(&dapp_events_for(&mut events, Duration::from_millis(500)).await),
        0
    );
    assert!(dapp.sessions().iter().any(|s| s.topic == topic));
    let saved = saved_state(&vault).await.expect("the suspend saved");
    assert_eq!(saved.sessions.len(), 1);
    assert_eq!(saved.sessions[0].topic, topic);
    let state = serde_json::to_value(&saved.snapshot).expect("serializes");
    assert!(state["symKeys"][topic.as_str()].is_string(), "with its key");
    assert_eq!(saved.route_kind, PersistedRoute::Loopback);
    assert_eq!(saved.relay_url, TEST_RELAY_URL);
}

#[tokio::test]
async fn quit_with_a_data_key_suspends_and_waits_for_it() {
    let vault = testkit::keyed_vault();
    let (_relay, dapp, mut events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let wait = slot.quit(vault.lock()).expect("the suspend is running");
    assert!(kao.is_closed() && slot.is_closed());
    wait.await;
    testkit::settle_within(DRAIN_BOUND, || slot.teardowns_running() == 0).await;
    assert_eq!(slot.teardowns_running(), 0);
    assert_eq!(
        saved_state(&vault).await.map(|s| s.session_count()),
        Some(1)
    );
    assert_eq!(
        deletes(&dapp_events_for(&mut events, Duration::from_millis(300)).await),
        0
    );
    assert!(dapp.sessions().iter().any(|s| s.topic == topic));
    assert!(
        slot.quit(VaultFlush::none()).is_none(),
        "nothing left to wait for"
    );
}

#[tokio::test]
async fn an_expired_saved_session_ends_expired_and_nothing_dials() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, mut saved) = lock_wallet(&vault, &slot).await;
    let mut record = saved.record();
    let expired_at = now_secs() - 60;
    let mut state = serde_json::to_value(&record.snapshot).expect("serializes");
    state["sessions"][topic.as_str()]["expiry"] = json!(expired_at);
    record.snapshot = serde_json::from_value(state).expect("deserializes");
    saved.wc_state = Some(record.encode());
    unlock(&vault, &saved);

    let (connector, dials) = counted(&relay);
    let outcome =
        restore_with_connector(&next, connector, TEST_RELAY_URL, RouteKind::Loopback).await;
    assert_eq!(outcome, RestoreOutcome::Nothing);
    assert_eq!(dials.load(Ordering::SeqCst), 0, "nothing alive: no dial");
    assert!(next.get().is_none() && next.restore_view().is_none() && !next.is_starting());
    vault.wait_writer_idle().await;
    assert!(cleared(&vault), "the saved state is cleared");
    let records = vault.connections();
    assert_eq!(records[0].end, Some(EndReason::Expired));
    assert_eq!(records[0].ended_at, Some(expired_at));
}

#[tokio::test]
async fn a_saved_session_without_a_binding_is_deleted_until_the_dapp_hears() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, mut events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let (dapp_b, mut events_b) = testkit::dapp_client(&relay, "dapp-b").await;
    let kept = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let orphan = testkit::connect_raw(&kao, &dapp_b, ADDR, &[1]).await;
    let (next, mut saved) = lock_wallet(&vault, &slot).await;
    let mut record = saved.record();
    record.sessions.retain(|s| s.topic != orphan);
    saved.wc_state = Some(record.encode());
    unlock(&vault, &saved);

    // The relay refuses the first delete: Kao sends it again.
    let failed = Arc::new(AtomicBool::new(false));
    let f = failed.clone();
    let connector = tapped(
        relay.clone(),
        move |v| match is_publish(v, 1112) && !f.swap(true, Ordering::SeqCst) {
            true => Tap::Fail,
            false => Tap::Pass,
        },
        |_| Tap::Pass,
    );
    let outcome =
        restore_with_connector(&next, connector, TEST_RELAY_URL, RouteKind::Loopback).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { sessions: 1, .. }),
        "{outcome:?}"
    );
    testkit::settle_within(Duration::from_secs(5), || {
        !dapp_b.sessions().iter().any(|s| s.topic == orphan)
    })
    .await;
    assert!(
        failed.load(Ordering::SeqCst),
        "the first delete was refused"
    );
    assert!(
        !dapp_b.sessions().iter().any(|s| s.topic == orphan),
        "the dapp was told"
    );
    assert!(deletes(&dapp_events_for(&mut events_b, Duration::from_millis(100)).await) <= 1);
    assert_eq!(
        deletes(&dapp_events_for(&mut events, Duration::from_millis(300)).await),
        0
    );
    assert!(dapp.sessions().iter().any(|s| s.topic == kept));
}

#[tokio::test]
async fn a_request_kao_never_reviewed_is_refused_as_restarted() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let call = ask(&dapp, &topic);
    // It reaches the stream, but no dashboard admits it before the lock.
    let (req, _) = testkit::next_request(&kao.events()).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    let state = serde_json::to_value(&saved.record().snapshot).expect("serializes");
    assert!(state["pendingRequests"][req.id.to_string()].is_object());
    unlock(&vault, &saved);

    let outcome = restore(&next, &relay).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { .. }),
        "{outcome:?}"
    );
    let e = peer_error(testkit::dapp_result(call).await);
    assert_eq!(e.code, codes::DISCONNECTED);
    assert_eq!(e.message, "Kao restarted before this request was reviewed.");
    let rt = next.get().expect("installed");
    assert!(
        rt.snapshot(now_secs())
            .notices
            .iter()
            .any(|n| n.text.contains("wasn't reviewed")),
        "the Activity list says so"
    );
}

#[tokio::test]
async fn an_answer_kao_owed_is_sent_again_not_refused() {
    let vault = testkit::keyed_vault();
    let relay = RelayServer::new();
    let (dapp, _events) = testkit::dapp_client(&relay, "dapp").await;
    // The relay refuses every answer Kao publishes on its first connection.
    let connector = tapped(
        relay.clone(),
        |v| match is_publish(v, 1109) {
            true => Tap::Fail,
            false => Tap::Pass,
        },
        |_| Tap::Pass,
    );
    let kao = WcRuntime::start_with_connector_in(
        connector,
        next_generation(),
        RouteKind::Loopback,
        vault.session(),
    )
    .await
    .expect("starts");
    let slot = WcSlot::with_vault(vault.clone());
    slot.install(kao.clone()).expect("installs");
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let call = ask(&dapp, &topic);
    let key = to_signing(&kao).await;
    let (sig, hex) = signature();
    kao.answer(&key, Answer::Result(hex.clone()));
    testkit::settle(|| kao.snapshot(now_secs()).undelivered == 1).await;
    assert_eq!(vault.signed()[0].delivery, Delivery::Sending);
    let (next, saved) = lock_wallet(&vault, &slot).await;
    assert!(
        saved
            .record()
            .outbox
            .iter()
            .any(|a| a.id == key.id && a.signed_message && a.answer == Ok(hex.clone())),
        "saved write-ahead"
    );
    unlock(&vault, &saved);

    let outcome = restore(&next, &relay).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        testkit::dapp_result(call)
            .await
            .expect("the answer Kao owed"),
        hex
    );
    testkit::settle(|| vault.signed()[0].delivery == Delivery::Delivered).await;
    let record = &vault.signed()[0];
    assert_eq!(record.delivery, Delivery::Delivered);
    assert_eq!(record.signature.as_ref(), Some(&sig));
}

#[tokio::test]
async fn a_transaction_that_may_be_on_its_way_is_refused_as_unconfirmed() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let call = ask(&dapp, &topic);
    let key = to_signing(&kao).await;
    let hash = B256::repeat_byte(0xab);
    kao.note_unconfirmed(
        &key,
        UnconfirmedTx {
            hash,
            raw: Bytes::from_static(&[1, 2, 3]),
            nonce: 7,
        },
    );
    let (next, saved) = lock_wallet(&vault, &slot).await;
    assert!(
        saved
            .record()
            .outbox
            .iter()
            .any(|a| a.id == key.id && a.unconfirmed_tx == Some(hash))
    );
    unlock(&vault, &saved);

    let outcome = restore(&next, &relay).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { .. }),
        "{outcome:?}"
    );
    let e = peer_error(testkit::dapp_result(call).await);
    assert_eq!(e.code, codes::INTERNAL, "never \"cancelled\"");
    assert_eq!(e.message, Refusal::unconfirmed(hash).message);
}

#[tokio::test]
async fn another_relay_forgets_the_saved_sessions_without_dialing() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    unlock(&vault, &saved);

    let (connector, dials) = counted(&relay);
    let outcome = restore_with_connector(
        &next,
        connector,
        "wss://another-relay.kao.test",
        RouteKind::Loopback,
    )
    .await;
    assert_eq!(outcome, RestoreOutcome::Nothing);
    assert_eq!(dials.load(Ordering::SeqCst), 0, "no dial");
    vault.wait_writer_idle().await;
    assert!(cleared(&vault));
    assert_eq!(vault.connections()[0].end, Some(EndReason::RelayChanged));
    let notice = next.take_retire_notice().expect("the pane says why");
    assert!(notice.text.contains("another relay"), "{notice:?}");
    assert!(next.get().is_none() && next.restore_view().is_none() && !next.is_starting());
    // Nobody could tell the dapp (it's on the old relay).
    assert!(dapp.sessions().iter().any(|s| s.topic == topic));
}

#[tokio::test]
async fn a_less_private_route_waits_for_the_user() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) =
        testkit::harness_with_vault_on(&vault, RouteKind::Proxied).await;
    testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    assert_eq!(saved.record().route_kind, PersistedRoute::Proxied);
    unlock(&vault, &saved);

    let (connector, dials) = counted(&relay);
    let outcome = restore_with_connector(&next, connector, TEST_RELAY_URL, RouteKind::Direct).await;
    assert_eq!(outcome, RestoreOutcome::Waiting);
    assert_eq!(dials.load(Ordering::SeqCst), 0, "no direct dial on its own");
    assert_eq!(
        next.restore_view(),
        Some(RestoreView {
            sessions: 1,
            pending_disconnects: 0,
            phase: RestorePhase::NeedsYou {
                error: RESTORE_PROXY_OFF.to_string(),
                direct_override: true,
            },
        })
    );
    assert!(!next.is_starting(), "a paste isn't blocked by a start");
    assert!(!cleared(&vault), "the saved state waits too");

    // Reconnect anyway.
    let retry = next.retry_restore(true).expect("a new try");
    let outcome = retry.await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { sessions: 1, .. }),
        "{outcome:?}"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    assert!(next.get().is_some() && next.restore_view().is_none());
    let restored = next.get().expect("installed").state_record();
    assert_ne!(
        restored.identity_seed.map(|s| *s.expose()),
        saved.record().identity_seed.map(|s| *s.expose()),
        "a less private route gets a fresh relay identity"
    );
}

#[tokio::test]
async fn forget_ends_every_saved_session_and_clears_the_state() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) =
        testkit::harness_with_vault_on(&vault, RouteKind::Proxied).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    unlock(&vault, &saved);
    let outcome = restore_with_connector(
        &next,
        relay.connector("kao"),
        TEST_RELAY_URL,
        RouteKind::Direct,
    )
    .await;
    assert_eq!(outcome, RestoreOutcome::Waiting);

    next.forget_restore();
    assert!(next.restore_view().is_none());
    assert!(next.retry_restore(false).is_none(), "nothing left to retry");
    vault.wait_writer_idle().await;
    assert!(cleared(&vault));
    let records = vault.connections();
    assert_eq!(records[0].topic, topic.to_string());
    assert_eq!(records[0].end, Some(EndReason::Forgotten));
    assert!(next.begin_start(), "a fresh start may go ahead");
}

/// The lock / quit / Forget that lands while a restore still dials: the restored client is shut
/// down without a word to any dapp, and the vault is left exactly as it was.
#[tokio::test]
async fn a_slot_closed_during_the_restore_disconnects_nothing_and_writes_nothing() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, mut events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let call = ask(&dapp, &topic);
    let (next, saved) = lock_wallet(&vault, &slot).await;
    unlock(&vault, &saved);

    let gate = Arc::new(tokio::sync::Notify::new());
    let dialed = Arc::new(AtomicBool::new(false));
    let connector = {
        let (relay, gate, dialed) = (relay.clone(), gate.clone(), dialed.clone());
        move || {
            dialed.store(true, Ordering::SeqCst);
            let (relay, gate) = (relay.clone(), gate.clone());
            async move {
                gate.notified().await;
                wallet_connect::Result::Ok(relay.accept("kao"))
            }
        }
    };
    let restore = next
        .begin_restore_over(connector, TEST_RELAY_URL, RouteKind::Loopback)
        .expect("the restore starts");
    let task = tokio::spawn(restore);
    testkit::settle(|| dialed.load(Ordering::SeqCst)).await;
    assert!(matches!(
        next.restore_view(),
        Some(RestoreView {
            phase: RestorePhase::Connecting,
            ..
        })
    ));
    let saved_before = vault.last_saved_wc_state();
    let records_before = vault.connections();
    assert!(next.close().is_none(), "nothing installed yet");
    gate.notify_one();
    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the restore ends")
        .expect("task");
    assert_eq!(outcome, RestoreOutcome::Stopped);
    assert!(next.get().is_none() && next.restore_view().is_none());

    assert_eq!(
        deletes(&dapp_events_for(&mut events, Duration::from_millis(500)).await),
        0,
        "no dapp is told anything"
    );
    assert!(dapp.sessions().iter().any(|s| s.topic == topic));
    assert!(!call.is_finished(), "the request still waits (no refusal)");
    vault.wait_writer_idle().await;
    assert_eq!(
        vault.last_saved_wc_state(),
        saved_before,
        "nothing saved or cleared"
    );
    assert_eq!(vault.connections(), records_before, "no history written");
}

#[tokio::test]
async fn a_retry_wakes_a_restore_waiting_for_its_next_try() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    unlock(&vault, &saved);

    // The relay can't be reached at the first try.
    let attempts = Arc::new(AtomicUsize::new(0));
    let connector = {
        let (relay, attempts) = (relay.clone(), attempts.clone());
        move || {
            let first = attempts.fetch_add(1, Ordering::SeqCst) == 0;
            let conn = (!first).then(|| relay.accept("kao"));
            async move { conn.ok_or_else(|| wallet_connect::Error::Transport("relay down".into())) }
        }
    };
    let restore = next
        .begin_restore_over(connector, TEST_RELAY_URL, RouteKind::Loopback)
        .expect("the restore starts");
    let task = tokio::spawn(restore);
    testkit::settle(|| {
        matches!(
            next.restore_view(),
            Some(RestoreView {
                phase: RestorePhase::RetryingAt { .. },
                ..
            })
        )
    })
    .await;
    let Some(RestoreView {
        sessions: 1,
        pending_disconnects: 0,
        phase: RestorePhase::RetryingAt { at, error },
    }) = next.restore_view()
    else {
        panic!("retrying: {:?}", next.restore_view());
    };
    assert!(error.starts_with("Couldn't reach the relay"), "{error}");
    assert!(at >= now_secs() + 3, "the first backoff is 5 s");
    assert!(next.is_starting(), "nothing else starts meanwhile");

    let woke = tokio::time::Instant::now();
    assert!(
        next.retry_restore(false).is_none(),
        "wakes the waiting loop"
    );
    let outcome = tokio::time::timeout(Duration::from_secs(4), task)
        .await
        .expect("woken, it tries at once")
        .expect("task");
    assert!(woke.elapsed() < Duration::from_secs(4));
    assert!(
        matches!(outcome, RestoreOutcome::Restored { sessions: 1, .. }),
        "{outcome:?}"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn begin_restore_looks_once_per_unlock() {
    let relay = RelayServer::new();
    let vault = Vault::with_store_path(crate::paths::data_dir().join("wc-tests/absent.redb"));
    let left_open = ConnectionRecord {
        id: 3,
        topic: "left-open".into(),
        connected_at: 10,
        ..Default::default()
    };
    let saved = Saved {
        wc_state: None,
        connections: vec![left_open],
        signed: Vec::new(),
    };
    unlock(&vault, &saved);
    let slot = WcSlot::with_vault(vault.clone());
    let begin =
        || slot.begin_restore_over(relay.connector("kao"), TEST_RELAY_URL, RouteKind::Loopback);
    assert!(begin().is_none(), "nothing saved");
    assert_eq!(
        vault.connections()[0].end,
        Some(EndReason::Lost),
        "it ended while Kao was closed"
    );
    assert!(vault.last_saved_wc_state().is_none(), "nothing to clear");

    // A dashboard built again in the same unlock looks no more: a live session's record stays.
    vault.session().connection_opened(NewConnection {
        topic: "live".into(),
        ..Default::default()
    });
    assert!(begin().is_none());
    assert!(vault.connections()[0].is_open());

    // The next unlock looks again: an unreadable state is cleared.
    let _ = vault.lock();
    let unreadable = Saved {
        wc_state: Some(Zeroizing::new(b"not json".to_vec())),
        connections: Vec::new(),
        signed: Vec::new(),
    };
    unlock(&vault, &unreadable);
    assert!(begin().is_none());
    assert!(cleared(&vault));
}

#[tokio::test]
async fn turn_off_ends_the_history_and_clears_the_saved_state() {
    let vault = testkit::keyed_vault();
    let (_relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    testkit::settle(|| vault.last_saved_wc_state().flatten().is_some()).await;
    kao.retire(TURN_OFF);
    assert!(
        cleared(&vault),
        "cleared synchronously, before the teardown"
    );
    let records = vault.connections();
    assert_eq!(records[0].end, Some(EndReason::TurnedOff));
    let wait = slot.quit(VaultFlush::none()).expect("the teardown runs");
    wait.await;
    testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
    assert!(!dapp.sessions().iter().any(|s| s.topic == topic), "told");
    vault.wait_writer_idle().await;
    assert!(cleared(&vault), "and nothing saved it back");
}

#[tokio::test]
async fn a_save_scheduled_before_turn_off_cannot_bring_the_state_back() {
    let vault = testkit::keyed_vault();
    let (_relay, dapp, _events, kao, _slot) = testkit::harness_with_vault(&vault).await;
    testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    testkit::settle(|| vault.last_saved_wc_state().flatten().is_some()).await;
    // A save is spawned but hasn't run (the test runtime is single-threaded) when Turn off lands.
    kao.inner.persist.scheduled.store(false, Ordering::SeqCst);
    kao.schedule_persist();
    assert!(kao.inner.persist.scheduled.load(Ordering::SeqCst));
    kao.retire(TURN_OFF);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !kao.inner.persist.scheduled.load(Ordering::SeqCst),
        "it ran"
    );
    vault.wait_writer_idle().await;
    assert!(cleared(&vault));
}

#[tokio::test]
async fn a_closed_runtime_saves_nothing() {
    let relay = RelayServer::new();
    let vault = testkit::keyed_vault();
    let closed = WcRuntime::start_with_connector_in(
        relay.connector("kao"),
        next_generation(),
        RouteKind::Loopback,
        vault.session(),
    )
    .await
    .expect("starts");
    closed.mark_closed();
    closed.persist_now();
    closed.schedule_persist();
    tokio::time::sleep(Duration::from_millis(50)).await;
    vault.wait_writer_idle().await;
    assert!(vault.last_saved_wc_state().is_none());

    // An open one does.
    let open = WcRuntime::start_with_connector_in(
        relay.connector("kao-2"),
        next_generation(),
        RouteKind::Loopback,
        vault.session(),
    )
    .await
    .expect("starts");
    open.persist_now();
    assert!(saved_state(&vault).await.is_some());
}

#[tokio::test]
async fn a_runtime_from_an_earlier_unlock_writes_nothing() {
    let vault = testkit::keyed_vault();
    let (_relay, dapp, _events, kao, _slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    testkit::settle(|| vault.last_saved_wc_state().flatten().is_some()).await;
    let history = Saved {
        wc_state: None,
        connections: vault.connections(),
        signed: Vec::new(),
    };
    let _ = vault.lock();
    unlock(&vault, &history);
    let before = vault.last_saved_wc_state();

    kao.persist_now();
    kao.disconnect(&topic);
    testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    vault.wait_writer_idle().await;
    assert_eq!(
        vault.last_saved_wc_state(),
        before,
        "no save into this unlock"
    );
    assert!(
        vault.connections()[0].is_open(),
        "nor a history change: {:?}",
        vault.connections()
    );
}

#[tokio::test]
async fn binding_saves_the_state_and_opens_its_record() {
    let vault = testkit::keyed_vault();
    let (_relay, dapp, _events, kao, _slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    testkit::settle(|| vault.last_saved_wc_state().flatten().is_some()).await;
    let saved = saved_state(&vault).await.expect("saved on bind");
    assert_eq!(saved.sessions.len(), 1);
    assert_eq!(saved.sessions[0].topic, topic);
    assert_eq!(saved.next_ordinal, 2);
    assert!(saved.identity_seed.is_some());
    assert_eq!(
        kao.state_record().sessions,
        saved.sessions,
        "what a save takes now"
    );
    let records = vault.connections();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].topic, topic.to_string());
    assert_eq!(
        records[0].account,
        AccountRef::Eoa {
            address: ADDR,
            label: "Account 1".into()
        }
    );
    assert_eq!(records[0].chains, vec![1]);
    testkit::settle(|| vault.connections()[0].ack == AckRecord::Confirmed).await;
    assert_eq!(vault.connections()[0].ack, AckRecord::Confirmed);
}

/// Answered with no dashboard (as the off-screen path does): every message signature is in the
/// history with the review's digests, `Sending` until the relay confirms it.
#[tokio::test]
async fn message_signatures_are_recorded_with_digests_and_delivery() {
    let vault = testkit::keyed_vault();
    let (_relay, dapp, _events, kao, _slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;

    let call = ask(&dapp, &topic);
    let key = to_signing(&kao).await;
    let (sig, hex) = signature();
    kao.answer(&key, Answer::Result(hex.clone()));
    let signed = vault.signed();
    assert_eq!(signed.len(), 1);
    let r = &signed[0];
    assert_eq!(r.kind, SignedKind::Message);
    assert_eq!(
        r.payload,
        SignedPayload::Message {
            bytes: b"hi".to_vec()
        }
    );
    assert_eq!(
        r.digests,
        vec![DigestRow {
            label: EIP191_DIGEST_LABEL.to_string(),
            hash: crate::walletconnect::message::eip191_hash(b"hi"),
        }]
    );
    assert_eq!(r.signature.as_ref(), Some(&sig));
    assert_eq!(
        r.account,
        AccountRef::Eoa {
            address: ADDR,
            label: "Account 1".into()
        }
    );
    assert_eq!(r.chain_id, 1);
    assert_eq!(
        r.origin,
        crate::vault::SignOrigin::WalletConnect {
            topic: topic.to_string(),
            request_id: key.id,
            session_ordinal: 1,
            dapp: crate::vault::DappRecord::from(
                &kao.with_book(|b| b.session(&topic).map(|s| s.dapp.clone()))
                    .expect("bound")
            ),
        }
    );
    assert_eq!(testkit::dapp_result(call).await.expect("a result"), hex);
    testkit::settle(|| vault.signed()[0].delivery == Delivery::Delivered).await;
    assert_eq!(vault.signed()[0].delivery, Delivery::Delivered);

    // Typed data: the EIP-712 triple, under the review's labels.
    let caps = testkit::local_eoa_caps(ADDR);
    let typed = testkit::dapp_request(
        &dapp,
        &topic,
        1,
        "eth_signTypedData_v4",
        json!([ADDR.to_checksum(None), testkit::fixtures::mail(1)]),
    );
    let (req, at) = testkit::next_request(&kao.events()).await;
    let session = kao
        .with_book(|b| b.session(&req.topic).cloned())
        .expect("bound");
    let admitted = request::validate(&req, &session, &caps).expect("admitted");
    let WcCall::SignTypedData(t) = &admitted.call else {
        panic!("typed data");
    };
    let digests = t.checked.digests;
    let key = WcKey {
        topic: req.topic.clone(),
        id: req.id,
    };
    kao.admit(&req, at, Ok(admitted));
    kao.with_book(|b| {
        assert!(b.mark_in_review(&key, 2));
        assert!(b.mark_signing(&key, 2));
    });
    kao.answer(&key, Answer::Result(hex.clone()));
    let r = &vault.signed()[0];
    assert_eq!(r.kind, SignedKind::TypedData);
    assert_eq!(r.primary_type.as_deref(), Some("Mail"));
    assert_eq!(
        r.digests,
        vec![
            DigestRow {
                label: EIP712_DIGEST_LABEL.into(),
                hash: digests.digest
            },
            DigestRow {
                label: DOMAIN_HASH_LABEL.into(),
                hash: digests.domain_hash
            },
            DigestRow {
                label: MESSAGE_HASH_LABEL.into(),
                hash: digests.message_hash
            },
        ]
    );
    let SignedPayload::TypedData { json } = &r.payload else {
        panic!("the typed data is kept");
    };
    let kept: Value = serde_json::from_str(json).expect("json");
    assert_eq!(kept["primaryType"], "Mail");
    assert_eq!(testkit::dapp_result(typed).await.expect("a result"), hex);
}

/// The checked-in golden record (`testkit/wc_state_v1.json`, built once from a testkit session
/// with a request left pending) still plans a restore: its session with its key, its pending
/// request — pinning the crate's snapshot format and Kao's record against silent changes.
#[test]
fn the_golden_record_still_plans_a_restore() {
    let record = WcStateRecord::decode(include_bytes!("../testkit/wc_state_v1.json"))
        .expect("the golden record decodes");
    let plan = plan_restore(&record, record.saved_at).expect("plans");
    assert_eq!(plan.seed.sessions.len(), 1);
    let session = &plan.seed.sessions[0];
    assert_eq!(session.topic, record.sessions[0].topic);
    assert_eq!(session.identity, WcIdentity::Eoa { address: ADDR });
    assert_eq!(session.ack, AckState::Confirmed);
    assert!(session.expiry > record.saved_at);
    assert_eq!(plan.work.stale.len(), 1, "the pending request");
    assert_eq!(plan.work.stale[0].topic, session.topic);
    assert!(plan.ended.is_empty() && plan.work.unbound.is_empty());
    let state = serde_json::to_value(&plan.snapshot).expect("serializes");
    assert!(state["symKeys"][session.topic.as_str()].is_string());

    // A week later, everything in it has expired: nothing is dialed for.
    let later = plan_restore(&record, session.expiry).expect("plans");
    assert!(later.seed.sessions.is_empty());
    assert_eq!(later.ended.len(), 1);
    assert_eq!(later.ended[0].2, EndReason::Expired);
    let state = serde_json::to_value(&later.snapshot).expect("serializes");
    assert!(
        state["symKeys"].get(session.topic.as_str()).is_none(),
        "its key pruned"
    );
    assert!(
        state["pendingRequests"]
            .as_object()
            .is_none_or(|p| p.is_empty()),
        "its request pruned"
    );
}

/// A restore future dropped unfinished (its task gone) leaves the saved sessions waiting for the
/// user — never a restore that looks like it runs forever and blocks every start.
#[tokio::test]
async fn a_restore_dropped_unfinished_waits_for_the_user() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    unlock(&vault, &saved);

    let gate = Arc::new(tokio::sync::Notify::new());
    let dialed = Arc::new(AtomicBool::new(false));
    let connector = {
        let (relay, gate, dialed) = (relay.clone(), gate.clone(), dialed.clone());
        move || {
            dialed.store(true, Ordering::SeqCst);
            let (relay, gate) = (relay.clone(), gate.clone());
            async move {
                gate.notified().await;
                wallet_connect::Result::Ok(relay.accept("kao"))
            }
        }
    };
    let restore = next
        .begin_restore_over(connector, TEST_RELAY_URL, RouteKind::Loopback)
        .expect("the restore starts");
    let task = tokio::spawn(restore);
    testkit::settle(|| dialed.load(Ordering::SeqCst)).await;
    task.abort();
    assert!(task.await.is_err(), "cancelled");
    assert_eq!(
        next.restore_view(),
        Some(RestoreView {
            sessions: 1,
            pending_disconnects: 0,
            phase: RestorePhase::NeedsYou {
                error: RESTORE_INTERRUPTED.to_string(),
                direct_override: false,
            },
        })
    );
    assert!(!next.is_starting());

    gate.notify_one();
    let outcome = next.retry_restore(false).expect("a new try").await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { sessions: 1, .. }),
        "{outcome:?}"
    );
}

// ───────────────────────── end to end over a real wallet file ─────────────────────────

/// The whole persistence path with nothing emulated: a real wallet file and its data key
/// (`store`), the vault's writer thread sealing into it, a lock that suspends through the
/// writer's flush, and an unlock that reads the file back (`load_wallet_at`) into a new vault
/// epoch and restores under the same relay client id. The dapp's session keeps working, the
/// signed message is on disk with its digests (and, delivered, its signature), and the connection
/// record is still open.
#[tokio::test]
async fn a_real_wallet_file_carries_sessions_and_history_across_a_lock() {
    use crate::wallet::{
        AccountDescriptor, SecretKeyBytes, WalletDescriptor, load_wallet_at, save_descriptor_at,
    };
    use secrecy::SecretString;

    let pw = || SecretString::new("correct horse".to_string().into_boxed_str());
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("wallet.redb");
    let desc = WalletDescriptor::single(AccountDescriptor::Local {
        name: None,
        key_bytes: SecretKeyBytes::new([0x42; 32]),
    });
    let minted = save_descriptor_at(&path, &desc, &pw()).expect("the wallet file is written");

    // Unlock as the App does: one read of the file, its data key and sealed tables into the vault.
    let vault = Vault::with_store_path(path.clone());
    let first = load_wallet_at(&path, &pw()).expect("unlocks");
    assert_eq!(
        first.data_key.as_ref().map(|k| *k.expose()),
        Some(*minted.expose()),
        "the save's key is the one the unlock reads"
    );
    assert!(first.sealed.wc_state.is_none() && first.sealed.signed.rows.is_empty());
    vault.unlock(first.data_key, KeyStatus::Ok, first.sealed);
    assert!(vault.can_persist());

    // Connect a dapp and sign a personal message for it; the dapp gets the signature.
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let call = ask(&dapp, &topic);
    let key = to_signing(&kao).await;
    let (sig, hex) = signature();
    kao.answer(&key, Answer::Result(hex.clone()));
    assert_eq!(testkit::dapp_result(call).await.expect("a result"), hex);
    testkit::settle(|| {
        vault
            .signed()
            .first()
            .is_some_and(|r| r.delivery == Delivery::Delivered)
    })
    .await;

    // Lock: the epoch ends, the runtime suspends through the writer's flush, and the next unlock
    // waits (as the unlock screen does) for the suspend and the writer's drain.
    let flush = vault.lock();
    assert!(flush.can_persist());
    let next = slot.successor();
    let rt = slot.close().expect("a runtime is installed");
    slot.spawn_suspend(rt, flush)
        .await
        .expect("the suspend task");
    next.wait_idle(DRAIN_BOUND).await;
    assert_eq!(next.teardowns_running(), 0, "suspend and drain both ended");
    assert!(dapp.sessions().iter().any(|s| s.topic == topic), "no 6000");

    // Unlock: everything comes back from the file.
    let second = load_wallet_at(&path, &pw()).expect("unlocks again");
    assert_eq!(
        second.data_key.as_ref().map(|k| *k.expose()),
        Some(*minted.expose()),
        "the data key is stable across unlocks"
    );
    let sealed = &second.sealed;
    assert_eq!(
        (sealed.connections.dropped, sealed.signed.dropped),
        (0, 0),
        "every sealed row decrypts under the data key"
    );
    let on_disk = WcStateRecord::decode(sealed.wc_state.as_ref().expect("the suspend's state"))
        .expect("decodes");
    assert_eq!(on_disk.session_count(), 1);
    assert_eq!(on_disk.sessions[0].topic, topic);
    assert!(on_disk.identity_seed.is_some());
    let connections: Vec<ConnectionRecord> = sealed
        .connections
        .rows
        .iter()
        .map(|(_, b)| serde_json::from_slice(b).expect("a connection record"))
        .collect();
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].topic, topic.to_string());
    assert!(connections[0].is_open(), "the lock ended nothing");
    assert_eq!(connections[0].ack, AckRecord::Confirmed);
    let signed: Vec<SignedRecord> = sealed
        .signed
        .rows
        .iter()
        .map(|(_, b)| serde_json::from_slice(b).expect("a signed record"))
        .collect();
    assert_eq!(signed.len(), 1);
    let record = &signed[0];
    assert_eq!(record.kind, SignedKind::Message);
    assert_eq!(
        record.payload,
        SignedPayload::Message {
            bytes: b"hi".to_vec()
        }
    );
    assert_eq!(
        record.digests,
        vec![DigestRow {
            label: EIP191_DIGEST_LABEL.to_string(),
            hash: crate::walletconnect::message::eip191_hash(b"hi"),
        }]
    );
    assert_eq!(record.delivery, Delivery::Delivered);
    assert_eq!(
        record.signature.as_ref(),
        Some(&sig),
        "delivered, so the signature was written"
    );
    assert_eq!(record.signature_hash, alloy::primitives::keccak256(&sig));
    assert_eq!(record.signature_len, 65);

    // A new epoch over what was read, and the restore under the same relay client id.
    vault.unlock(second.data_key, KeyStatus::Ok, second.sealed);
    assert_eq!(vault.signed().len(), 1);
    assert!(vault.connections().iter().all(ConnectionRecord::is_open));
    let outcome = restore(&next, &relay).await;
    let rt = next.get().expect("restored and installed");
    assert_eq!(
        outcome,
        RestoreOutcome::Restored {
            sessions: 1,
            generation: rt.generation()
        }
    );

    // The dapp's session still works: its next request reaches review and the answer reaches it.
    let call = ask(&dapp, &topic);
    let key = to_signing(&rt).await;
    assert_eq!(key.topic, topic);
    let (sig2, hex2) = (
        Bytes::from(vec![0x22; 65]),
        json!(format!("0x{}", "22".repeat(65))),
    );
    rt.answer(&key, Answer::Result(hex2.clone()));
    assert_eq!(testkit::dapp_result(call).await.expect("a result"), hex2);
    let records = vault.connections();
    assert_eq!(records.len(), 1, "the same connection, not a new one");
    assert!(records[0].is_open(), "and still open: {records:?}");
    testkit::settle(|| {
        vault
            .signed()
            .first()
            .is_some_and(|r| r.delivery == Delivery::Delivered)
    })
    .await;

    // A second lock and unlock: both signatures on disk, under ids that kept climbing.
    let flush = vault.lock();
    let next2 = next.successor();
    let rt = next.close().expect("installed");
    next.spawn_suspend(rt, flush)
        .await
        .expect("the suspend task");
    next2.wait_idle(DRAIN_BOUND).await;
    let third = load_wallet_at(&path, &pw()).expect("unlocks a third time");
    assert_eq!(third.sealed.connections.rows.len(), 1);
    let signed: Vec<(u64, SignedRecord)> = third
        .sealed
        .signed
        .rows
        .iter()
        .map(|(id, b)| (*id, serde_json::from_slice(b).expect("a signed record")))
        .collect();
    assert_eq!(signed.len(), 2);
    assert!(signed[0].0 < signed[1].0, "ids climb across unlocks");
    assert_eq!(signed[0].1.signature.as_ref(), Some(&sig));
    assert_eq!(signed[1].1.signature.as_ref(), Some(&sig2));
    assert!(
        signed
            .iter()
            .all(|(_, r)| r.delivery == Delivery::Delivered)
    );
}

// ───────────────────────── review round 1 ─────────────────────────

/// A lock that lands while the restore still dials: the dial is abandoned before it subscribes,
/// so the relay keeps the request a dapp sent while Kao was away for the saved identity — and the
/// next unlock's restore, under that identity, still brings it to review (DESIGN §7).
#[tokio::test]
async fn a_lock_during_the_restore_dial_leaves_the_relay_its_messages() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    let call = ask(&dapp, &topic);
    tokio::time::sleep(Duration::from_millis(200)).await;
    unlock(&vault, &saved);

    let (gate, dialed) = (Arc::default(), Arc::default());
    let stale = next
        .begin_restore_over(
            gated(&relay, &gate, &dialed),
            TEST_RELAY_URL,
            RouteKind::Loopback,
        )
        .expect("the restore starts");
    let task = tokio::spawn(stale);
    testkit::settle(|| dialed.load(Ordering::SeqCst)).await;
    assert_eq!(
        next.teardowns_running(),
        1,
        "the dial is counted: the next unlock's restore waits for it"
    );
    let acks = relay.stats().acks;
    // Lock, as the App does.
    let flush = vault.lock();
    let after = next.successor();
    assert!(next.close().is_none(), "nothing installed yet");
    next.track_flush(flush);
    gate.notify_one();
    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the restore ends")
        .expect("task");
    assert_eq!(outcome, RestoreOutcome::Stopped);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        relay.stats().acks,
        acks,
        "Kao took nothing the relay kept for it"
    );
    testkit::settle_within(DRAIN_BOUND, || after.teardowns_running() == 0).await;
    assert_eq!(after.teardowns_running(), 0);

    unlock(&vault, &saved);
    let outcome = restore(&after, &relay).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { sessions: 1, .. }),
        "{outcome:?}"
    );
    let rt = after.get().expect("installed");
    let key = to_signing(&rt).await;
    assert_eq!(key.topic, topic, "the request reaches review");
    rt.answer(&key, Answer::Result(json!("0xfeed")));
    assert_eq!(
        testkit::dapp_result(call).await.expect("a result"),
        json!("0xfeed")
    );
}

/// A lock — or Forget — that lands while the restore waits for the last epoch's teardown: nothing
/// dials under the saved identity.
#[tokio::test]
async fn a_restore_stopped_while_it_waits_for_the_last_teardown_dials_nothing() {
    for lock in [true, false] {
        let vault = testkit::keyed_vault();
        let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
        testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let (next, saved) = lock_wallet(&vault, &slot).await;
        unlock(&vault, &saved);

        // Something of the last epoch still runs (a suspend, a writer's drain).
        let lingering = next.begin_teardown();
        let (connector, dials) = counted(&relay);
        let stale = next
            .begin_restore_over(connector, TEST_RELAY_URL, RouteKind::Loopback)
            .expect("the restore starts");
        let task = tokio::spawn(stale);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(dials.load(Ordering::SeqCst), 0, "it waits for that first");
        if lock {
            let _ = vault.lock();
            assert!(next.close().is_none());
        } else {
            // The vault epoch stays current: only the slot says the run is over.
            next.forget_restore();
        }
        drop(lingering);
        let outcome = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the restore ends")
            .expect("task");
        assert_eq!(outcome, RestoreOutcome::Stopped, "lock: {lock}");
        assert_eq!(
            dials.load(Ordering::SeqCst),
            0,
            "nothing dialed (lock: {lock})"
        );
    }
}

/// A request Kao was signing when it locked (its transaction may already be on its way) is never
/// refused as "not reviewed" after the restore: the dapp hears it may have gone through.
#[tokio::test]
async fn a_request_kao_was_signing_at_the_lock_is_told_it_may_have_gone_through() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let call = ask(&dapp, &topic);
    let key = to_signing(&kao).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    assert!(
        saved
            .record()
            .outbox
            .iter()
            .any(|a| a.id == key.id && a.answer == Err(Refusal::interrupted().error_object())),
        "owed, not stale"
    );
    unlock(&vault, &saved);

    let outcome = restore(&next, &relay).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { .. }),
        "{outcome:?}"
    );
    let e = peer_error(testkit::dapp_result(call).await);
    assert_eq!(e.code, codes::INTERNAL);
    assert_eq!(e.message, Refusal::interrupted().message);
    let said = notices(&next.get().expect("installed"));
    assert!(!said.iter().any(|n| n.contains("reviewed")), "{said:?}");
    assert!(
        said.iter().any(|n| n.contains("may have gone through")),
        "{said:?}"
    );
}

/// The suspend's last try delivers a signed answer the relay had refused: the epoch already
/// ended, so the saved state carries the delivery — with the signature — and the restore records
/// it. The history row ends Delivered, its signature kept, never "Delivery unconfirmed" forever.
#[tokio::test]
async fn a_signature_the_suspend_delivers_ends_delivered_with_its_bytes() {
    let vault = testkit::keyed_vault();
    let relay = RelayServer::new();
    let (dapp, _events) = testkit::dapp_client(&relay, "dapp").await;
    let refuse = Arc::new(AtomicBool::new(true));
    let (connector, tries) = refusing(&relay, 1109, &refuse);
    let (kao, slot) = kao_over(&vault, connector).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let call = ask(&dapp, &topic);
    let key = to_signing(&kao).await;
    let (sig, hex) = signature();
    kao.answer(&key, Answer::Result(hex.clone()));
    wait_out_quick_resends(&tries).await;
    assert_eq!(vault.signed()[0].delivery, Delivery::Sending);

    refuse.store(false, Ordering::SeqCst);
    let (next, saved) = lock_wallet(&vault, &slot).await;
    assert_eq!(testkit::dapp_result(call).await.expect("delivered"), hex);
    let record = saved.record();
    assert!(
        record.outbox.iter().all(|a| a.id != key.id),
        "nothing owed any more"
    );
    assert_eq!(
        record.deliveries,
        vec![PersistedDelivery {
            topic: topic.clone(),
            id: key.id,
            delivery: Delivery::Delivered,
            signature: Some(sig.clone()),
        }]
    );
    assert_eq!(
        (saved.signed[0].delivery, saved.signed[0].signature.as_ref()),
        (Delivery::Sending, None),
        "what the disk holds"
    );
    unlock(&vault, &saved);

    let outcome = restore(&next, &relay).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { .. }),
        "{outcome:?}"
    );
    let r = &vault.signed()[0];
    assert_eq!(r.delivery, Delivery::Delivered);
    assert_eq!(r.signature.as_ref(), Some(&sig));
}

/// Deliveries a saved state carries still reach the history when it has nothing left to restore.
#[tokio::test]
async fn deliveries_in_a_state_with_nothing_to_restore_still_reach_the_history() {
    let relay = RelayServer::new();
    let vault = Vault::with_store_path(crate::paths::data_dir().join("wc-tests/absent.redb"));
    let sig = Bytes::from(vec![0x33; 65]);
    let sending = SignedRecord {
        id: 4,
        origin: SignOrigin::WalletConnect {
            topic: "gone-topic".into(),
            request_id: 7,
            session_ordinal: 1,
            dapp: Default::default(),
        },
        signature: None,
        signature_hash: keccak256(&sig),
        signature_len: 65,
        delivery: Delivery::Sending,
        ..Default::default()
    };
    let record = WcStateRecord {
        v: WC_STATE_VERSION,
        deliveries: vec![PersistedDelivery {
            topic: Topic::new("gone-topic"),
            id: 7,
            delivery: Delivery::Delivered,
            signature: Some(sig.clone()),
        }],
        ..Default::default()
    };
    unlock(
        &vault,
        &Saved {
            wc_state: Some(record.encode()),
            connections: Vec::new(),
            signed: vec![sending],
        },
    );
    let slot = WcSlot::with_vault(vault.clone());
    assert!(
        slot.begin_restore_over(relay.connector("kao"), TEST_RELAY_URL, RouteKind::Loopback)
            .is_none()
    );
    let r = &vault.signed()[0];
    assert_eq!(r.delivery, Delivery::Delivered);
    assert_eq!(r.signature.as_ref(), Some(&sig));
    assert!(cleared(&vault));
}

/// Turn off's teardown gives an undelivered signed answer its last try; delivered, the history
/// says so (the epoch is still current).
#[tokio::test]
async fn turn_off_books_a_signature_its_last_try_delivers() {
    let vault = testkit::keyed_vault();
    let relay = RelayServer::new();
    let (dapp, _events) = testkit::dapp_client(&relay, "dapp").await;
    let refuse = Arc::new(AtomicBool::new(true));
    let (connector, tries) = refusing(&relay, 1109, &refuse);
    let (kao, _slot) = kao_over(&vault, connector).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let call = ask(&dapp, &topic);
    let key = to_signing(&kao).await;
    let (_, hex) = signature();
    kao.answer(&key, Answer::Result(hex.clone()));
    wait_out_quick_resends(&tries).await;

    refuse.store(false, Ordering::SeqCst);
    kao.retire(TURN_OFF);
    assert_eq!(testkit::dapp_result(call).await.expect("delivered"), hex);
    testkit::settle(|| vault.signed()[0].delivery == Delivery::Delivered).await;
    assert_eq!(vault.signed()[0].delivery, Delivery::Delivered);
}

/// A session restored live whose connection record never opened (an approve that finished while
/// a lock's suspend waited for it: the ended epoch dropped its opening) gets one at the restore.
#[tokio::test]
async fn a_live_session_without_an_open_record_gets_one_at_the_restore() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    testkit::settle(|| vault.connections()[0].ack == AckRecord::Confirmed).await;
    let (next, mut saved) = lock_wallet(&vault, &slot).await;
    saved.connections.clear();
    unlock(&vault, &saved);

    let outcome = restore(&next, &relay).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { sessions: 1, .. }),
        "{outcome:?}"
    );
    let records = vault.connections();
    assert_eq!(records.len(), 1, "{records:?}");
    let r = &records[0];
    assert!(r.is_open());
    assert_eq!(r.topic, topic.to_string());
    assert_eq!(
        r.account,
        AccountRef::Eoa {
            address: ADDR,
            label: "Account 1".into()
        }
    );
    assert_eq!(r.chains, vec![1]);
    assert_eq!(r.connected_at, saved.record().saved_at);
    assert_eq!(r.ack, AckRecord::Confirmed);
}

/// A record the dapp ended while Kao was closed (its end dropped with the lock's epoch, its
/// binding gone from the saved state) ends Lost after the restore; the live one stays open.
#[tokio::test]
async fn an_open_record_no_live_session_backs_ends_lost_after_the_restore() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, mut saved) = lock_wallet(&vault, &slot).await;
    saved.connections.push(ConnectionRecord {
        id: 99,
        topic: "gone".into(),
        connected_at: 10,
        ..Default::default()
    });
    unlock(&vault, &saved);

    let outcome = restore(&next, &relay).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { sessions: 1, .. }),
        "{outcome:?}"
    );
    let records = vault.connections();
    let gone = records
        .iter()
        .find(|r| r.topic == "gone")
        .expect("the record");
    assert_eq!(gone.end, Some(EndReason::Lost));
    let live = records
        .iter()
        .find(|r| r.topic == topic.to_string())
        .expect("the live one");
    assert!(live.is_open());
}

/// A disconnect that reached neither the relay nor, at the lock, its last try: the saved state has
/// no binding left, but the dapp still holds the session — so the next unlock dials and tells it.
#[tokio::test]
async fn a_disconnect_that_never_reached_the_dapp_is_delivered_by_the_next_restore() {
    let vault = testkit::keyed_vault();
    let relay = RelayServer::new();
    let (dapp, _events) = testkit::dapp_client(&relay, "dapp").await;
    let refuse = Arc::new(AtomicBool::new(true));
    let (connector, tries) = refusing(&relay, 1112, &refuse);
    let (kao, slot) = kao_over(&vault, connector).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    kao.disconnect(&topic);
    wait_out_quick_resends(&tries).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    assert!(dapp.sessions().iter().any(|s| s.topic == topic));
    let record = saved.record();
    assert_eq!(record.session_count(), 0);
    let state = serde_json::to_value(&record.snapshot).expect("serializes");
    assert!(
        state["sessions"][topic.as_str()].is_object(),
        "the client still holds it"
    );
    unlock(&vault, &saved);

    let (connector, dials) = counted(&relay);
    let outcome =
        restore_with_connector(&next, connector, TEST_RELAY_URL, RouteKind::Loopback).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { sessions: 0, .. }),
        "{outcome:?}"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 1);
    testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
    assert!(
        !dapp.sessions().iter().any(|s| s.topic == topic),
        "the dapp was told"
    );
    assert_eq!(vault.connections()[0].end, Some(EndReason::YouDisconnected));
}

/// A lock gives a disconnect the relay refused its last try (as a teardown does): delivered, the
/// dapp is told and the saved client state no longer holds the session.
#[tokio::test]
async fn a_lock_gives_an_owed_disconnect_its_last_try() {
    let vault = testkit::keyed_vault();
    let relay = RelayServer::new();
    let (dapp, _events) = testkit::dapp_client(&relay, "dapp").await;
    let refuse = Arc::new(AtomicBool::new(true));
    let (connector, tries) = refusing(&relay, 1112, &refuse);
    let (kao, slot) = kao_over(&vault, connector).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    kao.disconnect(&topic);
    wait_out_quick_resends(&tries).await;
    assert!(dapp.sessions().iter().any(|s| s.topic == topic));

    refuse.store(false, Ordering::SeqCst);
    let (_next, saved) = lock_wallet(&vault, &slot).await;
    testkit::settle(|| !dapp.sessions().iter().any(|s| s.topic == topic)).await;
    assert!(
        !dapp.sessions().iter().any(|s| s.topic == topic),
        "the dapp was told"
    );
    let state = serde_json::to_value(&saved.record().snapshot).expect("serializes");
    assert!(
        state["sessions"].get(topic.as_str()).is_none(),
        "nothing left for a restore to dial for"
    );
}

/// A request that reaches Kao during the suspend's answers phase — after its early save — is in
/// the final save: the relay won't push it to this identity again, and the restore refuses it.
#[tokio::test]
async fn a_request_that_arrives_during_the_suspend_is_refused_after_the_restore() {
    let vault = testkit::keyed_vault();
    let relay = RelayServer::new();
    let (dapp, _events) = testkit::dapp_client(&relay, "dapp").await;
    let (hold, held) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let holding = Arc::new(AtomicBool::new(false));
    let connector = {
        let (hold, held, holding) = (hold.clone(), held.clone(), holding.clone());
        tapped(
            relay.clone(),
            move |v| match is_publish(v, 1109) && holding.load(Ordering::SeqCst) {
                true => {
                    held.notify_one();
                    Tap::HoldUntil(hold.clone())
                }
                false => Tap::Pass,
            },
            |_| Tap::Pass,
        )
    };
    let (kao, slot) = kao_over(&vault, connector).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let first = ask(&dapp, &topic);
    let (req, at) = testkit::next_request(&kao.events()).await;
    kao.admit(&req, at, Ok(testkit::admitted_personal(ADDR, 1, "hi")));
    holding.store(true, Ordering::SeqCst);

    // Lock: the suspend's refusal of the first request waits at the relay's door …
    let connections = vault.connections();
    let flush = vault.lock();
    let next = slot.successor();
    let suspend = slot.spawn_suspend(slot.close().expect("installed"), flush);
    tokio::time::timeout(Duration::from_secs(3), held.notified())
        .await
        .expect("the suspend's answer is on its way");
    // … while the dapp asks again, and Kao's client takes it.
    let second = ask(&dapp, &topic);
    testkit::settle(|| {
        kao.client()
            .pending_requests()
            .iter()
            .any(|p| p.id != req.id)
    })
    .await;
    hold.notify_one();
    suspend.await.expect("the suspend task");
    vault.wait_writer_idle().await;
    let saved = Saved {
        wc_state: vault.last_saved_wc_state().flatten(),
        connections,
        signed: Vec::new(),
    };
    let e = peer_error(testkit::dapp_result(first).await);
    assert_eq!(e.message, Refusal::closing().message);
    unlock(&vault, &saved);

    let outcome = restore(&next, &relay).await;
    assert!(
        matches!(outcome, RestoreOutcome::Restored { .. }),
        "{outcome:?}"
    );
    let e = peer_error(testkit::dapp_result(second).await);
    assert_eq!(e.code, codes::DISCONNECTED);
    assert_eq!(e.message, Refusal::restarted().message);
}

/// A request handed to the stream that no dashboard admitted is saved as the client took it —
/// the only save there is until a dashboard looks, and the relay won't push it again.
#[tokio::test]
async fn a_request_no_dashboard_admitted_is_saved_as_the_client_took_it() {
    let vault = testkit::keyed_vault();
    let (_relay, dapp, _events, kao, _slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    testkit::settle(|| vault.connections()[0].ack == AckRecord::Confirmed).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // No later save (the pairing's delete marks the state dirty) may stand in for the one tested.
    testkit::settle_within(Duration::from_secs(5), || {
        lock(&kao.inner.persist.dirty_since).is_none()
    })
    .await;
    let _call = ask(&dapp, &topic);
    let (req, _) = testkit::next_request(&kao.events()).await;
    let saved_pending = || {
        vault
            .last_saved_wc_state()
            .flatten()
            .map(|b| WcStateRecord::decode(&b).expect("decodes"))
            .is_some_and(|r| {
                let state = serde_json::to_value(&r.snapshot).expect("serializes");
                state["pendingRequests"][req.id.to_string()].is_object()
            })
    };
    testkit::settle_within(Duration::from_secs(1), saved_pending).await;
    assert!(saved_pending(), "saved without admission");
}

/// The restore watch wakes the dashboard at every phase change of a retry loop that runs with
/// no runtime (so no event stream): Connecting, the failure's RetryingAt, the retry, the install
/// — and a close.
#[tokio::test]
async fn the_restore_watch_wakes_the_dashboard_at_every_phase_change() {
    use futures::StreamExt;
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    unlock(&vault, &saved);
    let watch = next.restore_watch();
    assert_eq!(watch, next.restore_watch(), "one identity per slot");
    assert_ne!(watch, next.successor().restore_watch());
    let mut changes = restore_watch_stream(&watch);

    // The relay can't be reached at the first try.
    let attempts = Arc::new(AtomicUsize::new(0));
    let connector = {
        let (relay, attempts) = (relay.clone(), attempts.clone());
        move || {
            let first = attempts.fetch_add(1, Ordering::SeqCst) == 0;
            let conn = (!first).then(|| relay.accept("kao"));
            async move { conn.ok_or_else(|| wallet_connect::Error::Transport("relay down".into())) }
        }
    };
    let task = tokio::spawn(
        next.begin_restore_over(connector, TEST_RELAY_URL, RouteKind::Loopback)
            .expect("the restore starts"),
    );
    let mut seen = Vec::new();
    while let Ok(Some(())) = tokio::time::timeout(Duration::from_secs(1), changes.next()).await {
        let phase = next.restore_view().map(|v| v.phase);
        let retrying = matches!(phase, Some(RestorePhase::RetryingAt { .. }));
        seen.push(phase);
        if retrying {
            break;
        }
    }
    assert!(
        matches!(seen.last(), Some(Some(RestorePhase::RetryingAt { .. }))),
        "woken for the retry loop's own phase change: {seen:?}"
    );
    assert!(next.retry_restore(false).is_none(), "wakes the loop");
    let mut ended = false;
    while let Ok(Some(())) = tokio::time::timeout(Duration::from_secs(2), changes.next()).await {
        if next.restore_view().is_none() {
            ended = true;
            break;
        }
    }
    assert!(ended, "woken when the restore installed");
    let outcome = task.await.expect("task");
    assert!(
        matches!(outcome, RestoreOutcome::Restored { .. }),
        "{outcome:?}"
    );
    let _ = next.close();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), changes.next())
            .await
            .is_ok_and(|c| c.is_some()),
        "and when the slot closes"
    );
}

// ───────────────────────── review round 2 ─────────────────────────

/// `topic`'s session in `saved`'s client state now expires at `at`.
fn expire_in(saved: &mut Saved, topic: &Topic, at: u64) {
    let mut record = saved.record();
    let mut state = serde_json::to_value(&record.snapshot).expect("serializes");
    state["sessions"][topic.as_str()]["expiry"] = json!(at);
    record.snapshot = serde_json::from_value(state).expect("deserializes");
    saved.wc_state = Some(record.encode());
}

/// `topic`'s connection record: how and when it ended.
fn end_of(vault: &Vault, topic: &Topic) -> (Option<EndReason>, Option<u64>) {
    let records = vault.connections();
    let r = records
        .iter()
        .find(|r| r.topic == topic.to_string())
        .unwrap_or_else(|| panic!("a record for the topic: {records:?}"));
    (r.end, r.ended_at)
}

/// Kao on `route` over a relay refusing its answers (tag 1109) with one dapp connected, a
/// personal_sign answered and its quick re-sends refused: the signature waits in the outbox.
async fn a_signature_the_relay_refuses(
    vault: &Vault,
    route: RouteKind,
) -> (RelayServer, SignClient, WcRuntime, WcSlot, Topic, WcKey) {
    let relay = RelayServer::new();
    let (dapp, _events) = testkit::dapp_client(&relay, "dapp").await;
    let refuse = Arc::new(AtomicBool::new(true));
    let (connector, tries) = refusing(&relay, 1109, &refuse);
    let kao =
        WcRuntime::start_with_connector_in(connector, next_generation(), route, vault.session())
            .await
            .expect("starts");
    let slot = WcSlot::with_vault(vault.clone());
    slot.install(kao.clone()).expect("installs");
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let _call = ask(&dapp, &topic);
    let key = to_signing(&kao).await;
    kao.answer(&key, Answer::Result(signature().1));
    wait_out_quick_resends(&tries).await;
    assert_eq!(vault.signed()[0].delivery, Delivery::Sending);
    (relay, dapp, kao, slot, topic, key)
}

/// Turn off while the relay refuses an answer: its last try fails too, and the signature ends
/// `NotDelivered` — the saved state that held it is cleared and the client shut down, so nothing
/// will send it again (never "Kao keeps this signature … to send it again after a restart").
#[tokio::test]
async fn turn_off_gives_up_a_signature_its_last_try_cannot_deliver() {
    let vault = testkit::keyed_vault();
    let (_relay, _dapp, kao, slot, _topic, _key) =
        a_signature_the_relay_refuses(&vault, RouteKind::Loopback).await;
    kao.retire(TURN_OFF);
    slot.quit(VaultFlush::none())
        .expect("the teardown runs")
        .await;
    testkit::settle(|| vault.signed()[0].delivery == Delivery::NotDelivered).await;
    assert_eq!(vault.signed()[0].delivery, Delivery::NotDelivered);
    vault.wait_writer_idle().await;
    assert!(cleared(&vault));
}

/// A signature the relay never took, still owed when the saved state is dropped unrestored — the
/// user forgets the saved dapps, the relay changed, the session expired while Kao was closed — is
/// given up: `NotDelivered`, never "Delivery unconfirmed" over a state that's gone.
#[tokio::test]
async fn a_signature_still_owed_when_the_saved_state_is_dropped_ends_not_delivered() {
    for how in ["forget", "relay", "expired"] {
        let vault = testkit::keyed_vault();
        let (relay, _dapp, _kao, slot, topic, key) =
            a_signature_the_relay_refuses(&vault, RouteKind::Proxied).await;
        let (next, mut saved) = lock_wallet(&vault, &slot).await;
        assert!(
            saved
                .record()
                .outbox
                .iter()
                .any(|a| a.id == key.id && a.signed_message),
            "{how}: still owed at the lock"
        );
        let expired_at = now_secs() - 60;
        if how == "expired" {
            expire_in(&mut saved, &topic, expired_at);
        }
        unlock(&vault, &saved);

        let (relay_url, route) = match how {
            "relay" => ("wss://another-relay.kao.test", RouteKind::Proxied),
            "forget" => (TEST_RELAY_URL, RouteKind::Direct),
            _ => (TEST_RELAY_URL, RouteKind::Proxied),
        };
        let (connector, dials) = counted(&relay);
        let outcome = restore_with_connector(&next, connector, relay_url, route).await;
        if how == "forget" {
            assert_eq!(outcome, RestoreOutcome::Waiting);
            next.forget_restore();
        } else {
            assert_eq!(outcome, RestoreOutcome::Nothing, "{how}");
        }
        assert_eq!(dials.load(Ordering::SeqCst), 0, "{how}");
        vault.wait_writer_idle().await;
        assert!(cleared(&vault), "{how}");
        let r = &vault.signed()[0];
        assert_eq!(r.delivery, Delivery::NotDelivered, "{how}");
        assert_eq!(r.signature, None, "{how}: never kept");
        let (end, at) = end_of(&vault, &topic);
        let expected = match how {
            "forget" => EndReason::Forgotten,
            "relay" => EndReason::RelayChanged,
            _ => EndReason::Expired,
        };
        assert_eq!(end, Some(expected), "{how}");
        if how == "expired" {
            assert_eq!(at, Some(expired_at));
        }
    }
}

/// Two dapps saved, one session expired while Kao was closed: the waiting restore counts one dapp,
/// and Forget ends the expired one `Expired` at its expiry — `Forgotten` only for the live one.
#[tokio::test]
async fn a_restore_counts_and_forgets_only_the_live_sessions() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) =
        testkit::harness_with_vault_on(&vault, RouteKind::Proxied).await;
    let (dapp_b, _events_b) = testkit::dapp_client(&relay, "dapp-b").await;
    let live = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let gone = testkit::connect_raw(&kao, &dapp_b, ADDR, &[1]).await;
    let (next, mut saved) = lock_wallet(&vault, &slot).await;
    assert_eq!(saved.record().session_count(), 2);
    let expired_at = now_secs() - 600;
    expire_in(&mut saved, &gone, expired_at);
    unlock(&vault, &saved);

    let outcome = restore_with_connector(
        &next,
        relay.connector("kao"),
        TEST_RELAY_URL,
        RouteKind::Direct,
    )
    .await;
    assert_eq!(outcome, RestoreOutcome::Waiting);
    assert_eq!(
        next.restore_view().map(|v| v.sessions),
        Some(1),
        "only the dapp that can come back waits"
    );
    let before = now_secs();
    next.forget_restore();
    vault.wait_writer_idle().await;
    assert!(cleared(&vault));
    assert_eq!(
        end_of(&vault, &gone),
        (Some(EndReason::Expired), Some(expired_at))
    );
    let (end, at) = end_of(&vault, &live);
    assert_eq!(end, Some(EndReason::Forgotten));
    assert!(at.is_some_and(|at| at >= before), "{at:?}");
}

/// Another relay with one saved session alive and one expired: the notice counts the live one,
/// which ends `RelayChanged`; the expired one ends `Expired`, at its expiry.
#[tokio::test]
async fn a_relay_change_forgets_and_counts_only_the_live_sessions() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let (dapp_b, _events_b) = testkit::dapp_client(&relay, "dapp-b").await;
    let live = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let gone = testkit::connect_raw(&kao, &dapp_b, ADDR, &[1]).await;
    let (next, mut saved) = lock_wallet(&vault, &slot).await;
    let expired_at = now_secs() - 600;
    expire_in(&mut saved, &gone, expired_at);
    unlock(&vault, &saved);

    let (connector, dials) = counted(&relay);
    let outcome = restore_with_connector(
        &next,
        connector,
        "wss://another-relay.kao.test",
        RouteKind::Loopback,
    )
    .await;
    assert_eq!(outcome, RestoreOutcome::Nothing);
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    let notice = next.take_retire_notice().expect("the pane says why");
    assert_eq!(
        notice.text,
        "Kao forgot 1 saved dapp: WalletConnect uses another relay now."
    );
    assert_eq!(
        end_of(&vault, &gone),
        (Some(EndReason::Expired), Some(expired_at))
    );
    assert_eq!(end_of(&vault, &live).0, Some(EndReason::RelayChanged));
}

/// Saved state whose every binding expired is dropped as the restore is begun: no run starts, so
/// the pane never shows "Reconnecting to N saved dapps…" for dapps that can't come back.
#[tokio::test]
async fn saved_sessions_that_all_expired_start_no_restore_run() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, mut saved) = lock_wallet(&vault, &slot).await;
    let expired_at = now_secs() - 60;
    expire_in(&mut saved, &topic, expired_at);
    unlock(&vault, &saved);

    let watch = next.restore_watch();
    let (connector, dials) = counted(&relay);
    assert!(
        next.begin_restore_over(connector, TEST_RELAY_URL, RouteKind::Loopback)
            .is_none(),
        "no run"
    );
    assert!(next.restore_view().is_none() && !next.is_starting());
    assert!(
        !watch.rx.has_changed().unwrap_or(true),
        "the restore never showed"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    vault.wait_writer_idle().await;
    assert!(cleared(&vault));
    assert_eq!(
        end_of(&vault, &topic),
        (Some(EndReason::Expired), Some(expired_at))
    );
}

/// A binding counts as waiting to reconnect only while its session is alive past the expiry
/// margin — one that expires during a long wait for the user stops counting. An owed disconnect
/// counts apart, the same way; the restore lapses once neither has anything alive.
#[test]
fn a_restore_job_counts_only_the_sessions_still_alive() {
    let now = 1_000_000;
    let job = RestoreJob {
        record: Arc::default(),
        expiries: Arc::from([now + 600, now + EXPIRY_MARGIN_SECS, now - 1]),
        unbound_expiries: Arc::from([now + 900, now + 10]),
        session: Vault::new().session(),
        dial: RestoreDial::Settings,
    };
    assert_eq!(job.live_sessions(now), 1);
    assert_eq!(job.live_sessions(now - 3), 2, "still past the margin");
    assert_eq!(job.live_sessions(now + 600), 0);
    assert_eq!(job.live_unbound(now), 2);
    assert_eq!(job.live_unbound(now + 10 - EXPIRY_MARGIN_SECS), 1);
    assert_eq!(
        (job.live_sessions(now + 600), job.live_unbound(now + 600)),
        (0, 1),
        "only a disconnect left"
    );
    let lapses = now + 900 - EXPIRY_MARGIN_SECS;
    assert_eq!(job.lapses_at(), lapses);
    assert_eq!(job.live_unbound(lapses - 1), 1);
    assert_eq!(
        (job.live_sessions(lapses), job.live_unbound(lapses)),
        (0, 0),
        "nothing alive from the moment it lapses"
    );

    let none_owed = RestoreJob {
        unbound_expiries: Arc::from([]),
        ..job
    };
    assert_eq!(none_owed.live_unbound(now), 0);
    assert_eq!(none_owed.lapses_at(), now + 600 - EXPIRY_MARGIN_SECS);
}

/// A relay change when the saved state holds only a disconnect Kao still owed (no saved dapp):
/// the reason the pane shows says that disconnect couldn't be finished — never "Kao forgot 0
/// saved dapps".
#[tokio::test]
async fn a_relay_change_with_only_a_disconnect_owed_says_so() {
    let vault = testkit::keyed_vault();
    let relay = RelayServer::new();
    let (dapp, _events) = testkit::dapp_client(&relay, "dapp").await;
    let refuse = Arc::new(AtomicBool::new(true));
    let (connector, tries) = refusing(&relay, 1112, &refuse);
    let (kao, slot) = kao_over(&vault, connector).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    kao.disconnect(&topic);
    wait_out_quick_resends(&tries).await;
    let (next, saved) = lock_wallet(&vault, &slot).await;
    assert_eq!(saved.record().session_count(), 0);
    unlock(&vault, &saved);

    let (connector, dials) = counted(&relay);
    let outcome = restore_with_connector(
        &next,
        connector,
        "wss://another-relay.kao.test",
        RouteKind::Loopback,
    )
    .await;
    assert_eq!(outcome, RestoreOutcome::Nothing);
    assert_eq!(dials.load(Ordering::SeqCst), 0);
    let notice = next.take_retire_notice().expect("the pane says why");
    assert_eq!(
        notice.text,
        "Kao couldn't finish disconnecting a dapp: WalletConnect uses another relay now."
    );
    vault.wait_writer_idle().await;
    assert!(cleared(&vault));
    assert_eq!(
        end_of(&vault, &topic).0,
        Some(EndReason::YouDisconnected),
        "its record keeps how it ended"
    );
}

#[test]
fn the_relay_change_notice_counts_live_dapps_or_owed_disconnects() {
    let relay = "WalletConnect uses another relay now.";
    for (live, unbound, lead) in [
        (1, 0, "Kao forgot 1 saved dapp:"),
        (3, 1, "Kao forgot 3 saved dapps:"),
        (0, 1, "Kao couldn't finish disconnecting a dapp:"),
        (0, 2, "Kao couldn't finish disconnecting 2 dapps:"),
    ] {
        assert_eq!(
            relay_changed_notice(live, unbound),
            format!("{lead} {relay}"),
            "{live} live, {unbound} unbound"
        );
    }
}

/// An owed signature whose request the saved client state no longer holds, with a dapp deadline
/// already passed by the save: the crate may have dropped that request unanswered at its deadline
/// (its expiry sweep), so the restore can't call it delivered — it ends `NotDelivered`, and its
/// signature never reaches the history. Before its deadline, a missing request still means the
/// answer went out: `Delivered`, with the signature.
#[tokio::test]
async fn a_missing_request_past_its_deadline_is_not_taken_for_a_delivery() {
    for deadline_passed in [true, false] {
        let vault = testkit::keyed_vault();
        let (relay, _dapp, _kao, slot, _topic, key) =
            a_signature_the_relay_refuses(&vault, RouteKind::Loopback).await;
        let (next, mut saved) = lock_wallet(&vault, &slot).await;
        // What a save taken right after the crate's sweep holds: the answer still owed (in
        // flight), its request gone from the client state.
        let mut record = saved.record();
        let mut state = serde_json::to_value(&record.snapshot).expect("serializes");
        state["pendingRequests"]
            .as_object_mut()
            .expect("pending requests")
            .retain(|_, r| r["id"] != key.id);
        record.snapshot = serde_json::from_value(state).expect("deserializes");
        let saved_at = record.saved_at;
        let answer = record
            .outbox
            .iter_mut()
            .find(|a| a.id == key.id)
            .expect("owed");
        answer.dapp_deadline = Some(match deadline_passed {
            true => saved_at - 1,
            false => saved_at + 600,
        });
        saved.wc_state = Some(record.encode());
        unlock(&vault, &saved);

        let outcome = restore(&next, &relay).await;
        assert!(
            matches!(outcome, RestoreOutcome::Restored { sessions: 1, .. }),
            "{outcome:?}"
        );
        let r = &vault.signed()[0];
        let expected = match deadline_passed {
            true => (Delivery::NotDelivered, None),
            false => (Delivery::Delivered, Some(signature().0)),
        };
        assert_eq!(
            (r.delivery, r.signature.clone()),
            expected,
            "deadline passed: {deadline_passed}"
        );
    }
}

/// Forget lands while a try still dials (`Connecting`): the dial is aborted — the try installs
/// nothing, takes nothing the relay kept, and writes nothing — and the history ends as Forget
/// says: the live session `Forgotten`, the expired one `Expired` at its expiry.
#[tokio::test]
async fn forget_while_a_try_dials_aborts_it_and_writes_nothing_more() {
    let vault = testkit::keyed_vault();
    let (relay, dapp, mut events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let (dapp_b, _events_b) = testkit::dapp_client(&relay, "dapp-b").await;
    let live = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let gone = testkit::connect_raw(&kao, &dapp_b, ADDR, &[1]).await;
    let (next, mut saved) = lock_wallet(&vault, &slot).await;
    // A request the relay keeps for Kao's identity meanwhile.
    let call = ask(&dapp, &live);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let expired_at = now_secs() - 600;
    expire_in(&mut saved, &gone, expired_at);
    unlock(&vault, &saved);

    let (gate, dialed) = (Arc::default(), Arc::default());
    let task = tokio::spawn(
        next.begin_restore_over(
            gated(&relay, &gate, &dialed),
            TEST_RELAY_URL,
            RouteKind::Loopback,
        )
        .expect("the restore starts"),
    );
    testkit::settle(|| dialed.load(Ordering::SeqCst)).await;
    assert_eq!(
        next.restore_view(),
        Some(RestoreView {
            sessions: 1,
            pending_disconnects: 0,
            phase: RestorePhase::Connecting,
        })
    );
    let acks = relay.stats().acks;
    let before = now_secs();
    next.forget_restore();
    assert!(next.restore_view().is_none() && !next.is_starting());
    vault.wait_writer_idle().await;
    assert!(cleared(&vault));
    assert_eq!(
        end_of(&vault, &gone),
        (Some(EndReason::Expired), Some(expired_at))
    );
    let (end, at) = end_of(&vault, &live);
    assert_eq!(end, Some(EndReason::Forgotten));
    assert!(at.is_some_and(|at| at >= before), "{at:?}");
    let (state, records) = (vault.last_saved_wc_state(), vault.connections());

    gate.notify_one();
    let outcome = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the restore ends")
        .expect("task");
    assert_eq!(outcome, RestoreOutcome::Stopped);
    tokio::time::sleep(Duration::from_millis(200)).await;
    vault.wait_writer_idle().await;
    assert!(next.get().is_none(), "nothing installed");
    assert_eq!(
        vault.last_saved_wc_state(),
        state,
        "the aborted try saves nothing"
    );
    assert_eq!(vault.connections(), records, "nor writes history");
    assert_eq!(relay.stats().acks, acks, "Kao took nothing the relay kept");
    assert_eq!(
        deletes(&dapp_events_for(&mut events, Duration::from_millis(300)).await),
        0,
        "no dapp is told anything"
    );
    assert!(!call.is_finished(), "nor answered");
    assert!(next.begin_start(), "a fresh start may go ahead");
}

// ───────────────────────── review round 3 ─────────────────────────

/// Kao on a relay that refuses its disconnects (tag 1112), with dapp A saved and bound, and dapp
/// B's disconnect still owed at the lock (the saved client state keeps B's session, unbound). A's
/// session now expires at `kept(now)`, B's at `owed(now)`. Returns the slot the next unlock gets,
/// A and A's expiry.
async fn a_saved_dapp_and_an_owed_disconnect(
    vault: &Vault,
    relay: &RelayServer,
    kept: impl Fn(u64) -> u64,
    owed: impl Fn(u64) -> u64,
) -> (WcSlot, Topic, u64) {
    let (dapp, _events) = testkit::dapp_client(relay, "dapp").await;
    let (dapp_b, _events_b) = testkit::dapp_client(relay, "dapp-b").await;
    let refuse = Arc::new(AtomicBool::new(false));
    let (connector, tries) = refusing(relay, 1112, &refuse);
    let (kao, slot) = kao_over(vault, connector).await;
    let a = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let b = testkit::connect_raw(&kao, &dapp_b, ADDR, &[1]).await;
    refuse.store(true, Ordering::SeqCst);
    kao.disconnect(&b);
    wait_out_quick_resends(&tries).await;
    let (next, mut saved) = lock_wallet(vault, &slot).await;
    assert_eq!(saved.record().session_count(), 1, "only A stays bound");
    let now = now_secs();
    expire_in(&mut saved, &a, kept(now));
    expire_in(&mut saved, &b, owed(now));
    unlock(vault, &saved);
    (next, a, kept(now))
}

/// A restore waiting for the user counts its saved dapps and its owed disconnects apart — a
/// disconnect is never taken for a saved dapp, nor 0 saved dapps for "only a disconnect left". When
/// everything it holds expires during the wait, both read 0 (nothing pretends a disconnect is
/// still owed), and its watch ends it through the nothing-alive path: each binding `Expired` at
/// its expiry, the saved state cleared, no dial — and the dashboard woken for it.
#[tokio::test]
async fn a_waiting_restore_whose_sessions_all_expire_ends_through_its_watch() {
    let vault = testkit::keyed_vault();
    let relay = RelayServer::new();
    let lapse_in = 3;
    let (next, a, a_expiry) = a_saved_dapp_and_an_owed_disconnect(
        &vault,
        &relay,
        |now| now + EXPIRY_MARGIN_SECS + lapse_in,
        |now| now + EXPIRY_MARGIN_SECS + lapse_in - 1,
    )
    .await;

    let (connector, dials) = counted(&relay);
    let outcome = restore_with_connector(&next, connector, TEST_RELAY_URL, RouteKind::Direct).await;
    assert_eq!(outcome, RestoreOutcome::Waiting);
    let view = next.restore_view().expect("waits for the user");
    assert_eq!(
        (view.sessions, view.pending_disconnects),
        (1, 1),
        "one saved dapp, one disconnect owed"
    );

    // Nothing watches yet: past the lapse the view says nothing is alive — neither a dapp nor a
    // disconnect — and the saved state still waits.
    tokio::time::sleep(Duration::from_secs(lapse_in + 1)).await;
    let view = next
        .restore_view()
        .expect("still there: nothing ended it yet");
    assert_eq!((view.sessions, view.pending_disconnects), (0, 0));
    assert!(!cleared(&vault));

    // The dashboard's watch ends it at once, and wakes the dashboard.
    let mut changes = restore_watch_stream(&next.restore_watch());
    use futures::StreamExt;
    let woke = tokio::time::timeout(Duration::from_secs(2), changes.next()).await;
    assert!(matches!(woke, Ok(Some(()))), "woken for the end: {woke:?}");
    assert!(next.restore_view().is_none() && !next.is_starting());
    vault.wait_writer_idle().await;
    assert!(cleared(&vault), "the saved state is cleared");
    // Within the expiry margin a session counts as expired — ended then, never after its expiry.
    let (end, at) = end_of(&vault, &a);
    assert_eq!(end, Some(EndReason::Expired));
    assert!(
        at.is_some_and(|at| (a_expiry - EXPIRY_MARGIN_SECS..=a_expiry).contains(&at)),
        "{at:?}"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 0, "nothing dials for it");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), changes.next())
            .await
            .is_err(),
        "one wake for one change"
    );
    assert!(next.begin_start(), "a paste may go ahead");
}

/// A restore sleeping until its next try whose saved dapps all expire before that try: its watch
/// ends it at the lapse — the sleeping loop stops without dialing again — and the history and the
/// saved state end as the next try's nothing-alive path would leave them.
#[tokio::test]
async fn a_retrying_restore_that_lapses_ends_before_its_next_try() {
    use futures::StreamExt;
    let vault = testkit::keyed_vault();
    let (_relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    let (next, mut saved) = lock_wallet(&vault, &slot).await;
    let expiry = now_secs() + EXPIRY_MARGIN_SECS + 2;
    expire_in(&mut saved, &topic, expiry);
    unlock(&vault, &saved);
    let mut changes = restore_watch_stream(&next.restore_watch());

    // The relay can't be reached: the loop sleeps 5 s before its next try.
    let attempts = Arc::new(AtomicUsize::new(0));
    let connector = {
        let attempts = attempts.clone();
        move || {
            attempts.fetch_add(1, Ordering::SeqCst);
            async {
                Err::<wallet_connect::relay::Connection, _>(wallet_connect::Error::Transport(
                    "relay down".into(),
                ))
            }
        }
    };
    let task = tokio::spawn(
        next.begin_restore_over(connector, TEST_RELAY_URL, RouteKind::Loopback)
            .expect("the restore starts"),
    );
    let mut ended = false;
    while let Ok(Some(())) = tokio::time::timeout(Duration::from_secs(4), changes.next()).await {
        if next.restore_view().is_none() {
            ended = true;
            break;
        }
    }
    assert!(ended, "woken when the lapsed restore ended");
    let outcome = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("the loop stops")
        .expect("task");
    assert_eq!(outcome, RestoreOutcome::Stopped);
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "no try after the lapse");
    assert!(!next.is_starting(), "a paste may go ahead");
    vault.wait_writer_idle().await;
    assert!(cleared(&vault));
    let (end, at) = end_of(&vault, &topic);
    assert_eq!(end, Some(EndReason::Expired));
    assert!(
        at.is_some_and(|at| (expiry - EXPIRY_MARGIN_SECS..=expiry).contains(&at)),
        "{at:?}"
    );
}

/// A runtime started in a keyless epoch (the data key couldn't be read) keeps what it couldn't
/// save: once the session gets its key — "Reset saved history and connections…", or the wallet's
/// first save — the housekeeper saves the live state at its next tick, with no WalletConnect event
/// needed, so a crash then can't lose the dapps the pane now says stay connected. A runtime from
/// an earlier unlock still never saves.
#[tokio::test]
async fn a_keyless_runtime_saves_once_its_session_gets_its_key() {
    let vault = Vault::with_store_path(crate::paths::data_dir().join("wc-tests/absent.redb"));
    vault.unlock(None, KeyStatus::Unavailable, SealedLoad::default());
    let (_relay, dapp, _events, kao, _slot) = testkit::harness_with_vault(&vault).await;
    let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
    testkit::settle(|| {
        vault
            .connections()
            .first()
            .is_some_and(|r| r.ack == AckRecord::Confirmed)
    })
    .await;
    tokio::time::sleep(PERSIST_SOON_AFTER + 2 * HOUSEKEEPING_EVERY).await;
    assert_eq!(
        vault.last_saved_wc_state(),
        None,
        "nothing saved while keyless"
    );

    vault.set_key(DataKey::for_test(TEST_DATA_KEY), KeyOrigin::Minted);
    assert!(vault.can_persist());
    let keyed = std::time::Instant::now();
    testkit::settle_within(2 * HOUSEKEEPING_EVERY + Duration::from_millis(500), || {
        vault.last_saved_wc_state().flatten().is_some()
    })
    .await;
    assert!(
        keyed.elapsed() < 2 * HOUSEKEEPING_EVERY + Duration::from_millis(500),
        "saved at the next housekeeping tick"
    );
    let record = saved_state(&vault).await.expect("saved once keyed");
    assert!(
        record.sessions.iter().any(|s| s.topic == topic),
        "with the dapp connected while keyless"
    );

    // The next unlock: this runtime's session is stale, and stays unsaved however dirty it gets.
    let history = Saved {
        wc_state: Some(vault.last_saved_wc_state().flatten().expect("saved")),
        connections: vault.connections(),
        signed: Vec::new(),
    };
    let _ = vault.lock();
    unlock(&vault, &history);
    let before = vault.last_saved_wc_state();
    kao.schedule_persist();
    kao.mark_dirty();
    tokio::time::sleep(PERSIST_SOON_AFTER + 2 * HOUSEKEEPING_EVERY).await;
    vault.wait_writer_idle().await;
    assert_eq!(
        vault.last_saved_wc_state(),
        before,
        "no save into this unlock"
    );
}

/// Connections that ended while Kao was closed end `Lost` at the last moment Kao knew how things
/// stood — the saved state's save — never at the unlock that found out, days later: a binding the
/// saved client state no longer holds, and an open record no saved binding backs — after a
/// restore, or when nothing is left to restore. With no saved state at all, nothing better than
/// the unlock is known.
#[tokio::test]
async fn connections_lost_while_kao_was_closed_end_at_the_save() {
    for how in ["restored", "nothing alive", "no saved state"] {
        let vault = testkit::keyed_vault();
        let (relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
        let (dapp_b, _events_b) = testkit::dapp_client(&relay, "dapp-b").await;
        let kept = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let gone = testkit::connect_raw(&kao, &dapp_b, ADDR, &[1]).await;
        let (next, mut saved) = lock_wallet(&vault, &slot).await;
        // Saved three days ago; B's session left the client state since (its binding stayed).
        let saved_at = now_secs() - 3 * 86_400;
        let mut record = saved.record();
        record.saved_at = saved_at;
        let mut state = serde_json::to_value(&record.snapshot).expect("serializes");
        state["sessions"]
            .as_object_mut()
            .expect("sessions")
            .remove(gone.as_str());
        let kept_expiry = saved_at + 60;
        if how == "nothing alive" {
            state["sessions"][kept.as_str()]["expiry"] = json!(kept_expiry);
        }
        record.snapshot = serde_json::from_value(state).expect("deserializes");
        saved.wc_state = (how != "no saved state").then(|| record.encode());
        // And an open record no saved binding backs.
        saved.connections.push(ConnectionRecord {
            id: 99,
            topic: "stray".into(),
            connected_at: saved_at - 600,
            ..Default::default()
        });
        unlock(&vault, &saved);

        let before = now_secs();
        let outcome = restore(&next, &relay).await;
        let stray = vault
            .connections()
            .into_iter()
            .find(|r| r.topic == "stray")
            .expect("the stray record");
        let (gone_end, gone_at) = end_of(&vault, &gone);
        assert_eq!(gone_end, Some(EndReason::Lost), "{how}");
        assert_eq!(stray.end, Some(EndReason::Lost), "{how}");
        match how {
            "restored" => {
                assert!(
                    matches!(outcome, RestoreOutcome::Restored { sessions: 1, .. }),
                    "{outcome:?}"
                );
                assert_eq!(gone_at, Some(saved_at), "{how}");
                assert_eq!(stray.ended_at, Some(saved_at), "{how}");
                assert_eq!(end_of(&vault, &kept).0, None, "{how}: A comes back");
            }
            "nothing alive" => {
                assert_eq!(outcome, RestoreOutcome::Nothing);
                assert_eq!(gone_at, Some(saved_at), "{how}");
                assert_eq!(stray.ended_at, Some(saved_at), "{how}");
                assert_eq!(
                    end_of(&vault, &kept),
                    (Some(EndReason::Expired), Some(kept_expiry))
                );
            }
            _ => {
                assert_eq!(outcome, RestoreOutcome::Nothing);
                assert!(gone_at.is_some_and(|at| at >= before), "{how}: {gone_at:?}");
                assert!(
                    stray.ended_at.is_some_and(|at| at >= before),
                    "{how}: {:?}",
                    stray.ended_at
                );
            }
        }
    }
}

/// Without a plan (the saved client state unreadable), every saved binding ends as `live` says:
/// `Lost` at the save — it went while Kao was closed — but `Forgotten` now, as the user forgets.
#[tokio::test]
async fn an_unplanned_saved_state_ends_its_bindings_lost_at_the_save() {
    for live in [EndReason::Lost, EndReason::Forgotten] {
        let vault = testkit::keyed_vault();
        let (_relay, dapp, _events, kao, slot) = testkit::harness_with_vault(&vault).await;
        let topic = testkit::connect_raw(&kao, &dapp, ADDR, &[1]).await;
        let (_next, saved) = lock_wallet(&vault, &slot).await;
        let mut record = saved.record();
        record.saved_at = now_secs() - 86_400;
        unlock(&vault, &saved);

        let now = now_secs();
        end_saved_state(&vault.session(), &record, None, live, now);
        let at = match live {
            EndReason::Lost => record.saved_at,
            _ => now,
        };
        assert_eq!(end_of(&vault, &topic), (Some(live), Some(at)), "{live:?}");
    }
}

/// The plan's Lost ending takes the save's time — clamped to now should the save's clock have
/// been ahead.
#[test]
fn a_binding_missing_from_the_saved_client_state_ends_lost_at_the_save() {
    let mut record =
        WcStateRecord::decode(include_bytes!("../testkit/wc_state_v1.json")).expect("decodes");
    let topic = record.sessions[0].topic.clone();
    let mut state = serde_json::to_value(&record.snapshot).expect("serializes");
    state["sessions"]
        .as_object_mut()
        .expect("sessions")
        .remove(topic.as_str());
    record.snapshot = serde_json::from_value(state).expect("deserializes");
    let now = record.saved_at + 86_400;
    let plan = plan_restore(&record, now).expect("plans");
    assert_eq!(
        plan.ended,
        vec![(topic.to_string(), record.saved_at, EndReason::Lost)]
    );
    let ahead = plan_restore(&record, record.saved_at - 10).expect("plans");
    assert_eq!(ahead.ended[0].1, record.saved_at - 10);
}
