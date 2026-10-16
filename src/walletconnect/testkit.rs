//! Test harness for the runtime: an in-process `RelayServer`, a dapp `SignClient` on it, and a Kao
//! [`WcRuntime`] installed in a fresh [`WcSlot`] — persisting nowhere, or to an in-memory vault
//! ([`harness_with_vault`]). No real network, no settings, no wallet.
//!
//! Besides the harness helpers there is a [`RawPeer`]: a bare relay client that publishes hand-built,
//! encrypted JSON-RPC (a short-expiry request, a colliding id, a refused settlement) — things a
//! well-behaved dapp `SignClient` refuses to send.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use alloy::primitives::Address;
use futures::StreamExt;
use serde_json::{Value, json};
use wallet_connect::crypto::{SymKey, Topic};
use wallet_connect::relay::{Connection, RelayServer};
use wallet_connect::rpc::{Payload, Request};
use wallet_connect::sign::{
    ConnectParams, ConnectResponse, Metadata, PendingRequest, Proposal, ProposalNamespace,
    ProposalNamespaces, SignClient, SignEvent, SignEvents, SupportedNamespace,
    build_approved_namespaces,
};
use zeroize::Zeroizing;

use super::runtime::{WcEventSource, WcRuntime, WcSlot, event_stream, next_generation};
use super::types::*;
use super::{caip2, now_secs};
use crate::chain::Chain;
use crate::vault::Vault;

const ITEM_TIMEOUT: Duration = Duration::from_secs(2);
const SETTLE_TIMEOUT: Duration = Duration::from_secs(2);
const SETTLE_POLL: Duration = Duration::from_millis(10);
/// Relay round trips of the raw peer, and dapp-side waits.
const PEER_TIMEOUT: Duration = Duration::from_secs(5);

/// Proposals and requests shaped as real dapp libraries send them.
pub(crate) mod fixtures;

/// relay = RelayServer::new(); dapp on `relay.connector("dapp")`; kao =
/// `WcRuntime::start_with_connector(relay.connector("kao"), next_generation(), RouteKind::Loopback)`;
/// slot = WcSlot::new() with kao installed.
pub(crate) async fn harness() -> (RelayServer, SignClient, SignEvents, WcRuntime, WcSlot) {
    harness_on(RouteKind::Loopback).await
}

/// [`harness`] with Kao's runtime reporting `route` — the in-process relay is reached the same
/// way whatever it says.
pub(crate) async fn harness_on(
    route: RouteKind,
) -> (RelayServer, SignClient, SignEvents, WcRuntime, WcSlot) {
    let relay = RelayServer::new();
    let (dapp, dapp_events) = dapp_client(&relay, "dapp").await;
    let kao = WcRuntime::start_with_connector(relay.connector("kao"), next_generation(), route)
        .await
        .expect("Kao's runtime starts on the in-process relay");
    let slot = WcSlot::new();
    slot.install(kao.clone())
        .expect("a fresh slot accepts the runtime");
    (relay, dapp, dapp_events, kao, slot)
}

/// The data key [`keyed_vault`] unlocks with.
pub(crate) const TEST_DATA_KEY: [u8; 32] = [0x7e; 32];

/// A vault unlocked with a data key — so what the runtime saves and records lands in it — over a
/// store file that doesn't exist in the test sandbox: nothing reaches a disk.
pub(crate) fn keyed_vault() -> Vault {
    let vault = Vault::with_store_path(crate::paths::data_dir().join("wc-tests/absent.redb"));
    vault.unlock(
        Some(crate::wallet::DataKey::for_test(TEST_DATA_KEY)),
        crate::wallet::KeyStatus::Ok,
        crate::wallet::SealedLoad::default(),
    );
    vault
}

/// [`harness`] with Kao's runtime persisting to `vault`'s current epoch, in a slot over `vault`.
pub(crate) async fn harness_with_vault(
    vault: &Vault,
) -> (RelayServer, SignClient, SignEvents, WcRuntime, WcSlot) {
    harness_with_vault_on(vault, RouteKind::Loopback).await
}

/// [`harness_with_vault`] with Kao's runtime reporting `route`.
pub(crate) async fn harness_with_vault_on(
    vault: &Vault,
    route: RouteKind,
) -> (RelayServer, SignClient, SignEvents, WcRuntime, WcSlot) {
    let relay = RelayServer::new();
    let (dapp, dapp_events) = dapp_client(&relay, "dapp").await;
    let kao = WcRuntime::start_with_connector_in(
        relay.connector("kao"),
        next_generation(),
        route,
        vault.session(),
    )
    .await
    .expect("Kao's runtime starts on the in-process relay");
    let slot = WcSlot::with_vault(vault.clone());
    slot.install(kao.clone())
        .expect("a fresh slot accepts the runtime");
    (relay, dapp, dapp_events, kao, slot)
}

/// Another dapp on the same relay (its own client id, so the relay treats it as a separate peer).
pub(crate) async fn dapp_client(relay: &RelayServer, name: &str) -> (SignClient, SignEvents) {
    SignClient::builder(dapp_meta(name))
        .connector(relay.connector(name))
        .build()
        .await
        .expect("dapp client starts")
}

pub(crate) fn dapp_meta(name: &str) -> Metadata {
    Metadata::new(
        name,
        format!("{name} (test dapp)"),
        format!("https://{name}.example"),
    )
}

/// The capabilities of EOA `address` signing as `kind` on `chains`, labelled "Account 1".
pub(crate) fn eoa_caps(
    address: Address,
    kind: EoaKind,
    safe_owner: bool,
    chains: &[u64],
) -> IdentityCaps {
    IdentityCaps {
        identity: WcIdentity::Eoa { address },
        label: "Account 1".into(),
        kind: IdentityKind::Eoa(EoaCaps { kind, safe_owner }),
        chains: chains.to_vec(),
    }
}

/// A local EOA on every built-in chain. The list is fixed instead of `served_chain_ids()`: tests
/// never depend on the settings state.
pub(crate) fn local_eoa_caps(address: Address) -> IdentityCaps {
    let chains: Vec<u64> = Chain::ALL.iter().map(|c| c.chain_id()).collect();
    eoa_caps(address, EoaKind::Local, false, &chains)
}

/// A Safe 1.4.1 on `chain` whose fallback handler validates EIP-1271 messages: `owner_count`
/// owners, `local_signers` of them held by Kao.
pub(crate) fn safe_kind_caps(
    chain: Chain,
    threshold: u32,
    owner_count: u32,
    local_signers: u32,
) -> SafeCaps {
    SafeCaps {
        chain,
        version: "1.4.1".into(),
        threshold,
        owner_count,
        local_signers,
        fallback_handler: true,
        signing_block: None,
    }
}

/// The capabilities of Safe `address` on `chain_id` ([`safe_kind_caps`]), labelled "Treasury".
pub(crate) fn safe_identity_caps(
    address: Address,
    chain_id: u64,
    threshold: u32,
    owner_count: u32,
    local_signers: u32,
) -> IdentityCaps {
    let chain = Chain::from_chain_id(chain_id).unwrap_or(Chain::Mainnet);
    IdentityCaps {
        identity: WcIdentity::Safe { address, chain_id },
        label: "Treasury".into(),
        kind: IdentityKind::Safe(safe_kind_caps(chain, threshold, owner_count, local_signers)),
        chains: vec![chain_id],
    }
}

/// [`safe_identity_caps`] with as few owners as `threshold` and `local` allow.
pub(crate) fn safe_caps(
    address: Address,
    chain_id: u64,
    threshold: u32,
    local: u32,
) -> IdentityCaps {
    safe_identity_caps(
        address,
        chain_id,
        threshold,
        threshold.max(local).max(1),
        local,
    )
}

/// 2 s timeout.
pub(crate) async fn next_item(src: &WcEventSource) -> (u64, WcStreamItem) {
    let mut stream = std::pin::pin!(event_stream(src));
    tokio::time::timeout(ITEM_TIMEOUT, stream.next())
        .await
        .expect("a WalletConnect stream item within 2 s")
        .expect("the event stream is still open")
}

/// The next session request handed to the dashboard, skipping `Changed` / UI items.
pub(crate) async fn next_request(src: &WcEventSource) -> (PendingRequest, u64) {
    loop {
        if let (_, WcStreamItem::Request { req, received_at }) = next_item(src).await {
            return (req, received_at);
        }
    }
}

/// The next UI effect matching `pick`, skipping everything else.
pub(crate) async fn next_ui(src: &WcEventSource, pick: impl Fn(&UiEffect) -> bool) -> UiEffect {
    loop {
        if let (_, WcStreamItem::Ui(e)) = next_item(src).await
            && pick(&e)
        {
            return e;
        }
    }
}

/// Every item that arrives within `window` (for "nothing happened" assertions).
pub(crate) async fn drain_for(src: &WcEventSource, window: Duration) -> Vec<WcStreamItem> {
    let mut items = Vec::new();
    let mut stream = std::pin::pin!(event_stream(src));
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(Some((_, item))) = tokio::time::timeout_at(deadline, stream.next()).await {
        items.push(item);
    }
    items
}

/// Yield / sleep 10 ms until `cond` holds, ≤ 2 s.
pub(crate) async fn settle(cond: impl Fn() -> bool) {
    settle_within(SETTLE_TIMEOUT, cond).await;
}

/// [`settle`] with a longer bound — for the crate's 5 s expiry sweep.
pub(crate) async fn settle_within(bound: Duration, cond: impl Fn() -> bool) {
    let deadline = tokio::time::Instant::now() + bound;
    while !cond() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(SETTLE_POLL).await;
    }
}

/// What this thread logs under `filter` while the guard lives — the lines Kao's stderr would show.
/// A `#[tokio::test]` runtime is single-threaded, so the tasks it spawns log here too.
pub(crate) fn capture_logs(filter: &str) -> (tracing::subscriber::DefaultGuard, LogCapture) {
    // While only one dispatcher is registered anywhere, tracing works out a new callsite's
    // interest from the default of whichever thread hits it first. Another test thread (no
    // subscriber) hitting one of Kao's callsites first would cache it as never-enabled, for this
    // capture too. A second dispatcher, kept for the whole run, makes every callsite ask them all.
    static KEEP_TWO: std::sync::OnceLock<tracing::Dispatch> = std::sync::OnceLock::new();
    KEEP_TWO.get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
    let log = LogCapture::default();
    let sink = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(move || sink.clone())
        .with_ansi(false)
        .finish();
    (tracing::subscriber::set_default(subscriber), log)
}

/// The sink behind [`capture_logs`].
#[derive(Clone, Default)]
pub(crate) struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl LogCapture {
    pub(crate) fn text(&self) -> String {
        let bytes = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A dapp call in flight (it resolves when Kao answers).
pub(crate) type DappCall = tokio::task::JoinHandle<wallet_connect::Result<Value>>;

/// The dapp asks Kao for `method` on `chain_id`.
pub(crate) fn dapp_request(
    dapp: &SignClient,
    session: &Topic,
    chain_id: u64,
    method: &str,
    params: Value,
) -> DappCall {
    let (dapp, session, method) = (dapp.clone(), session.clone(), method.to_string());
    tokio::spawn(async move {
        dapp.request(
            &session,
            &caip2(chain_id),
            wallet_connect::sign::SessionRequest::new(method, params),
        )
        .await
    })
}

/// The dapp's view of a call's outcome.
pub(crate) async fn dapp_result(call: DappCall) -> wallet_connect::Result<Value> {
    tokio::time::timeout(PEER_TIMEOUT * 2, call)
        .await
        .expect("the dapp hears back in time")
        .expect("dapp task")
}

/// `{ "eip155": { chains, methods, events } }`.
pub(crate) fn eip155(chains: &[u64], methods: &[&str], events: &[&str]) -> ProposalNamespaces {
    BTreeMap::from([(
        "eip155".to_string(),
        ProposalNamespace::new(
            chains.iter().map(|c| caip2(*c)),
            methods.iter().map(|m| m.to_string()),
            events.iter().map(|e| e.to_string()),
        ),
    )])
}

/// What a modern dapp asks for: everything optional (js SDK ≥ 2.26).
pub(crate) fn modern_optional(chains: &[u64]) -> ProposalNamespaces {
    eip155(
        chains,
        &[
            "personal_sign",
            "eth_signTypedData_v4",
            "eth_sendTransaction",
            "wallet_switchEthereumChain",
            "eth_accounts",
            "eth_chainId",
        ],
        &["chainChanged", "accountsChanged"],
    )
}

/// The dapp shows a fresh link.
pub(crate) async fn dapp_connect(
    dapp: &SignClient,
    required: ProposalNamespaces,
    optional: ProposalNamespaces,
) -> ConnectResponse {
    dapp.connect(ConnectParams {
        required_namespaces: required,
        optional_namespaces: optional,
        ..Default::default()
    })
    .await
    .expect("dapp proposes")
}

/// The `wc:` link as the user copies it.
pub(crate) fn uri_of(resp: &ConnectResponse) -> Zeroizing<String> {
    Zeroizing::new(
        resp.uri
            .as_ref()
            .expect("a fresh pairing has a link")
            .to_string(),
    )
}

/// Wait until the pasted link put a card up.
pub(crate) async fn wait_card(kao: &WcRuntime) -> Proposal {
    settle(|| kao.card_proposal().is_some()).await;
    kao.card_proposal().expect("a proposal card within 2 s")
}

/// The ticket the coordinator builds from the card and the plan it displayed.
pub(crate) fn ticket(p: &Proposal, caps: &IdentityCaps, grant: Grant) -> ApproveTicket {
    ApproveTicket {
        proposal_id: p.id,
        pairing_topic: p.pairing_topic.clone(),
        proposer_key: p.proposer.public_key,
        grant,
        identity: caps.identity,
        identity_label: caps.label.clone(),
        dapp: DappLabel::from_metadata(&p.proposer.metadata),
    }
}

/// A grant built straight from the crate's helper — for runtime tests that must not depend on
/// `namespaces::plan_proposal`. Exposes `address` on `chains`.
pub(crate) fn manual_grant(p: &Proposal, address: Address, chains: &[u64]) -> Grant {
    let supported = BTreeMap::from([(
        "eip155".to_string(),
        SupportedNamespace {
            chains: chains.iter().map(|c| caip2(*c)).collect(),
            methods: super::namespaces::SERVED_METHODS
                .iter()
                .map(|m| m.to_string())
                .collect(),
            events: ["accountsChanged", "chainChanged"]
                .map(String::from)
                .to_vec(),
            accounts: chains
                .iter()
                .map(|c| format!("eip155:{c}:{}", address.to_checksum(None)))
                .collect(),
        },
    )]);
    let namespaces =
        build_approved_namespaces(&p.required_namespaces, &p.optional_namespaces, &supported)
            .expect("the test proposal fits what the test wallet supports");
    let ns = namespaces.get("eip155");
    Grant {
        chains: chains.to_vec(),
        methods: ns.map(|n| n.methods.clone()).unwrap_or_default(),
        events: ns.map(|n| n.events.clone()).unwrap_or_default(),
        namespaces,
    }
}

/// Connect `dapp` to Kao as a local EOA without going through `request::parse_pairing_uri` or
/// `namespaces::plan_proposal`: the paste is registered by hand and the grant comes from the
/// crate. Returns the session topic once the dapp holds the session.
pub(crate) async fn connect_raw(
    kao: &WcRuntime,
    dapp: &SignClient,
    address: Address,
    chains: &[u64],
) -> Topic {
    let resp = dapp_connect(dapp, BTreeMap::new(), modern_optional(chains)).await;
    let uri = uri_of(&resp);
    kao.with_book(|b| b.expect_pairing(resp.pairing_topic.clone(), now_secs(), None));
    kao.client().pair(&uri).await.expect("Kao pairs");
    let p = wait_card(kao).await;
    let caps = local_eoa_caps(address);
    let grant = manual_grant(&p, address, chains);
    kao.approve(ticket(&p, &caps, grant))
        .expect("approve starts");
    let session = tokio::time::timeout(PEER_TIMEOUT, resp.approval)
        .await
        .expect("dapp sees the approval")
        .expect("dapp holds the session");
    session.topic
}

/// The dapp-side symmetric key of a session (from its snapshot) — what a [`RawPeer`] needs to talk
/// on that session as if it were the dapp.
pub(crate) fn session_key(dapp: &SignClient, topic: &Topic) -> SymKey {
    let snap = serde_json::to_value(dapp.snapshot()).expect("snapshot serializes");
    let hex = snap["symKeys"][topic.as_str()]
        .as_str()
        .expect("the dapp holds the session key")
        .to_string();
    SymKey::from_hex(&hex).expect("a 32-byte key")
}

/// Wait for the dapp's next event other than relay connectivity.
pub(crate) async fn next_dapp_event(events: &mut SignEvents) -> SignEvent {
    loop {
        let e = tokio::time::timeout(PEER_TIMEOUT, events.recv())
            .await
            .expect("a dapp event in time")
            .expect("dapp events still open");
        if !matches!(e, SignEvent::RelayConnected | SignEvent::RelayDisconnected) {
            return e;
        }
    }
}

/// A bare relay client speaking the irn JSON-RPC directly.
pub(crate) struct RawPeer {
    conn: Connection,
    next_id: u64,
    /// (topic, encrypted message) pushed by the relay, acknowledged, not yet read.
    inbox: VecDeque<(Topic, String)>,
}

impl RawPeer {
    pub(crate) fn attach(relay: &RelayServer, client_id: &str) -> Self {
        Self {
            conn: relay.accept(client_id),
            next_id: 1,
            inbox: VecDeque::new(),
        }
    }

    async fn recv_frame(&mut self) -> Value {
        let text = tokio::time::timeout(PEER_TIMEOUT, self.conn.receiver.recv())
            .await
            .expect("relay frame in time")
            .expect("relay connection open");
        let frame: Value = serde_json::from_str(&text).expect("relay sends json");
        if frame["method"] == "irn_subscription" {
            let ack = json!({ "id": frame["id"], "jsonrpc": "2.0", "result": true });
            let _ = self.conn.sender.send(ack.to_string());
            let data = &frame["params"]["data"];
            if let (Some(topic), Some(message)) = (data["topic"].as_str(), data["message"].as_str())
            {
                self.inbox
                    .push_back((Topic::new(topic), message.to_string()));
            }
        }
        frame
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({ "id": id, "jsonrpc": "2.0", "method": method, "params": params });
        self.conn
            .sender
            .send(req.to_string())
            .expect("relay connection open");
        loop {
            let frame = self.recv_frame().await;
            if frame["id"] == id && frame.get("method").is_none() {
                assert!(
                    frame.get("error").is_none(),
                    "relay refused {method}: {frame}"
                );
                return frame["result"].clone();
            }
        }
    }

    pub(crate) async fn subscribe(&mut self, topic: &Topic) {
        self.call("irn_subscribe", json!({ "topic": topic })).await;
    }

    /// Encrypt `payload` (type 0) with `key` and publish it on `topic`.
    pub(crate) async fn publish(&mut self, topic: &Topic, key: &SymKey, payload: &Value, tag: u32) {
        let message = key.encrypt(payload.to_string().as_bytes());
        self.call(
            "irn_publish",
            json!({ "topic": topic, "message": message, "ttl": 300, "tag": tag }),
        )
        .await;
    }

    /// The next decrypted JSON-RPC payload on `topic`.
    pub(crate) async fn next_on(&mut self, topic: &Topic, key: &SymKey) -> Payload {
        loop {
            if let Some(pos) = self.inbox.iter().position(|(t, _)| t == topic) {
                let (_, message) = self.inbox.remove(pos).expect("position is in range");
                let plain = key.decrypt(&message).expect("decrypts with the topic key");
                let text = String::from_utf8(plain).expect("utf-8 json");
                return Payload::parse(&text).expect("a json-rpc payload");
            }
            self.recv_frame().await;
        }
    }

    /// The response to request `id` on `topic`, skipping whatever else the relay kept there
    /// (settlement, acks, …).
    pub(crate) async fn next_response(
        &mut self,
        topic: &Topic,
        key: &SymKey,
        id: u64,
    ) -> Result<Value, wallet_connect::rpc::ErrorObject> {
        loop {
            if let Payload::Response(r) = self.next_on(topic, key).await
                && r.id == id
            {
                return r.outcome;
            }
        }
    }

    /// Publish a `wc_sessionRequest` on a session as its dapp would — with any id and expiry.
    pub(crate) async fn inject_request(
        &mut self,
        session: &Topic,
        key: &SymKey,
        id: u64,
        chain_id: u64,
        request: Value,
    ) {
        let payload = Request::with_id(
            id,
            "wc_sessionRequest",
            json!({ "request": request, "chainId": caip2(chain_id) }),
        );
        let payload = serde_json::to_value(payload).expect("request serializes");
        self.publish(session, key, &payload, 1108).await;
    }
}

/// `personal_sign` params for `address` (hex-encoded UTF-8 message, strict [data, address] order).
pub(crate) fn personal_sign_params(message: &str, address: Address) -> Value {
    json!([
        format!("0x{}", alloy::hex::encode(message.as_bytes())),
        address.to_checksum(None)
    ])
}

/// The hand-built personal_sign `Admitted` (for tests that must not depend on `request::validate`).
pub(crate) fn admitted_personal(address: Address, chain_id: u64, message: &str) -> Admitted {
    Admitted {
        chain_id,
        call: WcCall::PersonalSign(PersonalSign {
            from: address,
            message: alloy::primitives::Bytes::copy_from_slice(message.as_bytes()),
            shape: MessageShape::Text {
                lines: vec![message.to_string()],
            },
            siwe: None,
        }),
        summary: "Sign message".into(),
    }
}
