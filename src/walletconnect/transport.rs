//! The relay socket: route selection (direct only for a loopback relay, SOCKS5h whenever a proxy is
//! installed, fail closed), an explicit ring + webpki-roots TLS config, the WebSocket handshake over
//! Kao's own stream, and the frame pump that bridges it to the crate's [`Connection`].
//!
//! Why Kao has its own transport: `wallet-connect` is built with `default-features = false`, which
//! drops its bundled WebSocket connector. That connector resolves the relay host locally and dials it
//! directly (bypassing `ALL_PROXY`), installs a process-wide rustls provider, never pings and never
//! notices a half-open socket. Everything here exists to close one of those gaps:
//!
//! - [`route_for`] is the single, pure routing decision. With a proxy installed the relay is reached
//!   only through a SOCKS5h tunnel; an unusable proxy value, or proxy *intent* that this launch didn't
//!   install, refuses rather than going direct. Only a relay on this machine is dialled directly.
//! - [`socks5h_connect`] speaks RFC 1928 itself: no-auth only, the host sent as a name (ATYP 0x03) so
//!   DNS happens at the proxy, every reply byte checked.
//! - [`tls_config`] builds rustls on an explicit ring provider with the bundled Mozilla roots. It
//!   never touches the process-level default provider, which reqwest consults for every client it
//!   builds.
//! - [`KaoConnector`] signs a fresh relay JWT per (re)connect, bounds the whole dial with a timeout,
//!   backs off on connections that die young ([`FlapGuard`]), and hands the socket to a pump that
//!   pings and drops a silent relay so the crate reconnects.
//!
//! The connection URL carries the JWT and the project id. It is never logged or `Display`ed; every
//! error string leaving this module goes through [`redact_transport_error`].

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, info};
use wallet_connect::auth::{DEFAULT_JWT_TTL, IdentityKey};
use wallet_connect::relay::{BoxFuture, Connection, Connector};

use super::types::{Route, RouteError, RouteKind};

/// Fixed relay `ua`: keeps the crate's 4-part shape, leaks no OS/arch.
const RELAY_UA: &str = "wc-2/rust-0.1.0/unknown/kao-wallet";
const WS_MAX_MESSAGE: usize = 2 << 20;
const WS_MAX_FRAME: usize = 1 << 20;

/// Whole-dial budget (TCP + SOCKS + TLS + WebSocket upgrade). A Tor circuit build can take a while,
/// so the proxied path gets twice the direct one. The crate never races a reconnect against
/// shutdown, so this is also the longest a hung dial can hold its driver task.
const PROXIED_CONNECT_BUDGET: Duration = Duration::from_secs(30);
const DIRECT_CONNECT_BUDGET: Duration = Duration::from_secs(15);
/// Kao pings the relay this often (the crate's own client never pings)…
const PING_EVERY: Duration = Duration::from_secs(20);
/// …and gives up on a socket that has carried no frame at all — not even the Pong — for this long.
/// Three missed pings: long enough to ride out a slow Tor circuit, short enough that a half-open
/// socket can't stall every publish behind the crate's 30 s request timeout for minutes.
const IDLE_LIMIT: Duration = Duration::from_secs(60);

/// A connection that dies sooner than this after the upgrade counts as a flap (typically a relay
/// that accepts the upgrade and then closes on a bad project id).
const FLAP_MIN_LIFETIME: Duration = Duration::from_secs(5);
const FLAP_FIRST_PENALTY: Duration = Duration::from_secs(1);
const FLAP_MAX_PENALTY: Duration = Duration::from_secs(30);

// RFC 1928 wire constants.
const SOCKS_VERSION: u8 = 0x05;
const SOCKS_CMD_CONNECT: u8 = 0x01;
const SOCKS_RSV: u8 = 0x00;
const SOCKS_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS_METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const SOCKS_ATYP_IPV4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_IPV6: u8 = 0x04;
const SOCKS_REPLY_SUCCEEDED: u8 = 0x00;

// ───────────────────────────── routing ─────────────────────────────

/// Pure. Loopback relay host → Direct (net.rs precedent). `ws://` to a non-loopback host → Err.
/// Installed proxy → Socks5h, failing closed on any parse/scheme problem (only `socks5h://`).
/// Proxy intent without an installed proxy → Err(RestartPending). Never Direct for a non-loopback
/// host while `installed_proxy` is Some.
///
/// `installed_proxy` is `proxy_env::installed_url()` — what this launch actually put in
/// `ALL_PROXY`, never the stored setting (the two differ after a mid-session settings save, or when
/// `main` fell back to the Tor default for an invalid stored address). `proxy_intent` is
/// `settings::proxy_enabled()`.
///
/// A relay on this machine is dialled directly whatever the proxy says: a remote proxy can't reach
/// the user's loopback, and loopback traffic never leaves the machine (the rule
/// `net::provider_for_url` applies to local RPC nodes). Anything other than `wss://`, or `ws://` to
/// loopback, is refused — plaintext would hand the connect JWT and project id to every hop.
pub fn route_for(
    relay: &url::Url,
    installed_proxy: Option<&str>,
    proxy_intent: bool,
) -> Result<Route, RouteError> {
    let host = relay
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or(RouteError::NoHost)?;
    let loopback = crate::net::is_loopback_host(Some(host));
    match relay.scheme() {
        "wss" => {}
        "ws" if loopback => {}
        // Plain ws:// off this machine, or a scheme that isn't a WebSocket at all. Settings never
        // store either (`parse_walletconnect_relay_input`); refusing here keeps route_for the one
        // place that decides what gets dialled.
        _ => return Err(RouteError::WsNotLoopback),
    }
    if loopback {
        return Ok(Route::Direct);
    }
    match installed_proxy {
        Some(proxy_url) => {
            installed_proxy_authority(proxy_url).map(|proxy| Route::Socks5h { proxy })
        }
        // The user asked for a proxy but this launch didn't install it (toggled mid-session).
        // The rest of Kao goes direct until a restart; a relay session would expose the user's IP
        // to the relay operator for its whole lifetime, so WalletConnect refuses instead.
        None if proxy_intent => Err(RouteError::RestartPending),
        None => Ok(Route::Direct),
    }
}

/// The `host:port` to tunnel through, from the URL `main` installed (`socks5h://{addr}`). Parsed
/// with `http::Uri` — the parser reqwest/hyper-util use for `ALL_PROXY` — so Kao's SOCKS tunnel goes
/// exactly where the rest of the process goes. Anything else fails closed:
/// - a scheme other than `socks5h` (`socks5` would resolve the relay locally; `http`/`https`
///   proxies aren't SOCKS at all);
/// - no explicit port, a path, a query, or embedded credentials (Kao's tunnel is no-auth only, so a
///   proxy that wants a login could never be satisfied — refuse up front rather than fail later).
fn installed_proxy_authority(proxy_url: &str) -> Result<String, RouteError> {
    let uri: http::Uri = proxy_url
        .parse()
        .map_err(|_| RouteError::ProxyUnparseable)?;
    match uri.scheme_str() {
        Some(s) if s.eq_ignore_ascii_case("socks5h") => {}
        Some(_) => return Err(RouteError::ProxyScheme),
        None => return Err(RouteError::ProxyUnparseable),
    }
    let authority = uri.authority().ok_or(RouteError::ProxyUnparseable)?;
    let plain_authority = !authority.as_str().contains('@')
        && !authority.host().is_empty()
        && authority.port_u16().is_some();
    let nothing_after = matches!(uri.path(), "" | "/") && uri.query().is_none();
    if !(plain_authority && nothing_after) {
        return Err(RouteError::ProxyUnparseable);
    }
    Ok(authority.as_str().to_owned())
}

pub fn route_kind(relay: &url::Url, route: &Route) -> RouteKind {
    match route {
        Route::Socks5h { .. } => RouteKind::Proxied,
        Route::Direct if crate::net::is_loopback_host(relay.host_str()) => RouteKind::Loopback,
        Route::Direct => RouteKind::Direct,
    }
}

/// `relay?auth=<jwt>&ua=<RELAY_UA>[&projectId=<id>]`; aud = relay without query, trailing '/'
/// trimmed; fresh JWT per call (`IdentityKey::sign_jwt(aud, DEFAULT_JWT_TTL)`). NEVER log or Display it.
///
/// Mirrors the crate's (compiled-out) WebSocket connector — same key order, same audience rule,
/// `append_pair` percent-encoding — except that any query or fragment already on `relay` is dropped
/// first (settings never store one), so the result carries exactly the pairs Kao chose. An empty
/// project id is treated as absent.
fn relay_connect_url(
    relay: &url::Url,
    identity: &IdentityKey,
    project_id: Option<&str>,
) -> url::Url {
    let mut url = relay.clone();
    url.set_query(None);
    url.set_fragment(None);
    let aud = url.as_str().trim_end_matches('/').to_owned();
    let jwt = identity.sign_jwt(&aud, DEFAULT_JWT_TTL);
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("auth", &jwt);
        query.append_pair("ua", RELAY_UA);
        if let Some(id) = project_id.filter(|id| !id.is_empty()) {
            query.append_pair("projectId", id);
        }
    }
    url
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    pub connect_total: Duration,
    pub ping_every: Duration,
    pub idle: Duration,
}

impl Timeouts {
    /// Proxied: 30 s connect; direct/loopback: 15 s. Ping 20 s, idle 60 s.
    pub fn for_route(route: &Route) -> Self {
        let connect_total = match route {
            Route::Socks5h { .. } => PROXIED_CONNECT_BUDGET,
            Route::Direct => DIRECT_CONNECT_BUDGET,
        };
        Self {
            connect_total,
            ping_every: PING_EVERY,
            idle: IDLE_LIMIT,
        }
    }
}

// ───────────────────────────── TLS & WebSocket config ─────────────────────────────

/// `ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
/// .with_safe_default_protocol_versions()?.with_root_certificates(webpki roots).with_no_client_auth()`,
/// cached in a OnceLock. Never the provider-less builder, never a process-default install.
///
/// Both ring and aws-lc-rs are compiled into rustls here (reqwest 0.12 vs 0.13/alloy), so rustls
/// can't pick a process default on its own — the provider-less builder would panic — and installing
/// one would silently re-point every reqwest client built afterwards. An explicit provider avoids
/// both. ring is the one Kao's own reqwest 0.12 uses. Roots are the Mozilla set reqwest and
/// hyper-rustls bundle; no ALPN (tokio-tungstenite's own default). TLS 1.2 + 1.3.
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                // Static: ring's default provider ships suites for both safe versions.
                .expect("ring provider supports TLS 1.2 and 1.3")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// tungstenite's defaults accept 64 MiB messages / 16 MiB frames — a free memory-exhaustion lever
/// for a hostile relay. WalletConnect frames are encrypted JSON envelopes a few KiB long (Kao's own
/// payload caps top out at 256 KiB of typed data, before base64), so 2 MiB / 1 MiB leaves ample
/// room.
fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(WS_MAX_MESSAGE))
        .max_frame_size(Some(WS_MAX_FRAME))
}

// ───────────────────────────── SOCKS5h ─────────────────────────────

/// RFC 1928 CONNECT request bytes: VER 5, CMD 1, RSV 0, ATYP 0x03 (+len) for names, 0x01/0x04 for IPs, port BE.
///
/// A name always goes as ATYP 0x03, so the proxy resolves it (the "h" in socks5h: no local DNS
/// query reveals which relay Kao talks to). `url` has already IDNA-encoded and lowercased it.
fn encode_connect_request(host: &url::Host<&str>, port: u16) -> io::Result<Vec<u8>> {
    let mut request = vec![SOCKS_VERSION, SOCKS_CMD_CONNECT, SOCKS_RSV];
    match host {
        url::Host::Domain(name) => {
            let len = u8::try_from(name.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "the relay host name must be 1–255 bytes to send through SOCKS5",
                    )
                })?;
            request.push(SOCKS_ATYP_DOMAIN);
            request.push(len);
            request.extend_from_slice(name.as_bytes());
        }
        url::Host::Ipv4(ip) => {
            request.push(SOCKS_ATYP_IPV4);
            request.extend_from_slice(&ip.octets());
        }
        url::Host::Ipv6(ip) => {
            request.push(SOCKS_ATYP_IPV6);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

/// No-auth method only; strict replies; drains BND.ADDR/PORT for every ATYP. Any failure is final
/// (callers never fall back to a direct dial).
///
/// `proxy` is the installed authority (`127.0.0.1:9050`, `[::1]:9050`, `proxy.lan:1080`); resolving
/// the *proxy's* own name locally is expected. The reply is read with exact-length reads, so not one
/// byte of the tunnelled stream (the TLS ServerHello) is consumed. Error text never names the proxy
/// address (the settings trace treats it as identifying) or the relay URL. No timeout of its own:
/// [`KaoConnector`] bounds the whole dial with [`Timeouts::connect_total`].
async fn socks5h_connect(proxy: &str, host: url::Host<&str>, port: u16) -> io::Result<TcpStream> {
    // Encode first: a host the proxy can't be asked for never opens a socket.
    let request = encode_connect_request(&host, port)?;
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("SOCKS5 proxy unreachable: {e}")))?;
    stream.set_nodelay(true)?;

    // Greeting: one method offered, "no authentication".
    stream
        .write_all(&[SOCKS_VERSION, 1, SOCKS_METHOD_NO_AUTH])
        .await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await.map_err(socks_eof)?;
    match choice {
        [SOCKS_VERSION, SOCKS_METHOD_NO_AUTH] => {}
        [SOCKS_VERSION, SOCKS_METHOD_NONE_ACCEPTABLE] => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the SOCKS5 proxy requires a login; Kao connects to it without one",
            ));
        }
        [SOCKS_VERSION, _] => {
            return Err(malformed(
                "the SOCKS5 proxy chose a method Kao didn't offer",
            ));
        }
        _ => return Err(malformed("the proxy didn't answer as a SOCKS5 server")),
    }

    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(socks_eof)?;
    let [version, reply, reserved, atyp] = head;
    if version != SOCKS_VERSION {
        return Err(malformed("the proxy didn't answer as a SOCKS5 server"));
    }
    if reply != SOCKS_REPLY_SUCCEEDED {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!(
                "the SOCKS5 proxy couldn't reach the relay: {}",
                socks_reply_text(reply)
            ),
        ));
    }
    if reserved != SOCKS_RSV {
        return Err(malformed("malformed SOCKS5 reply"));
    }
    // BND.ADDR + BND.PORT: drained, never used (the tunnel is the stream itself).
    let addr_len = match atyp {
        SOCKS_ATYP_IPV4 => 4,
        SOCKS_ATYP_IPV6 => 16,
        SOCKS_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(socks_eof)?;
            usize::from(len[0])
        }
        _ => return Err(malformed("malformed SOCKS5 reply (unknown address type)")),
    };
    let mut bound = vec![0u8; addr_len + 2];
    stream.read_exact(&mut bound).await.map_err(socks_eof)?;
    Ok(stream)
}

fn malformed(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// A proxy that hangs up mid-handshake surfaces as a bare "early eof"; say what was going on.
fn socks_eof(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::UnexpectedEof {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the SOCKS5 proxy closed the connection during the handshake",
        )
    } else {
        e
    }
}

fn socks_reply_text(reply: u8) -> String {
    match reply {
        0x01 => "general failure".into(),
        0x02 => "connection not allowed by its rules".into(),
        0x03 => "network unreachable".into(),
        0x04 => "host unreachable".into(),
        0x05 => "connection refused".into(),
        0x06 => "TTL expired".into(),
        0x07 => "command not supported".into(),
        0x08 => "address type not supported".into(),
        other => format!("error {other:#04x}"),
    }
}

// ───────────────────────────── error hygiene ─────────────────────────────

/// `net::redact_urls` + strip any `auth=`/`projectId=` query remnants.
///
/// `redact_urls` already cuts every `scheme://host/…` down to its host. This additionally blanks the
/// value of any `auth=` / `projectId=` pair that survived without a scheme in front of it, and any
/// bare JWT (`eyJ….….…`), so neither the connect token nor the project id can reach a log line, a
/// pane notice, or the crate's own `relay reconnect failed: {e}` warning.
pub(crate) fn redact_transport_error(e: &str) -> String {
    let mut out = crate::net::redact_urls(e);
    for key in ["auth=", "projectid="] {
        out = blank_param_values(&out, key);
    }
    blank_jwts(&out)
}

/// Replace the value after every (ASCII case-insensitive) `key` with `…`. The value runs to the
/// next `&`, `#`, quote, bracket, separator or whitespace.
fn blank_param_values(s: &str, key: &str) -> String {
    let lower = s.to_ascii_lowercase(); // same byte offsets: only ASCII bytes change
    let mut out = String::with_capacity(s.len());
    let mut from = 0;
    while let Some(found) = lower.get(from..).and_then(|rest| rest.find(key)) {
        let value_start = from + found + key.len();
        let value_len = s
            .get(value_start..)
            .and_then(|rest| rest.find(is_value_terminator))
            .unwrap_or_else(|| s.len().saturating_sub(value_start));
        out.push_str(s.get(from..value_start).unwrap_or_default());
        if value_len > 0 {
            out.push('…');
        }
        from = value_start + value_len;
    }
    out.push_str(s.get(from..).unwrap_or_default());
    out
}

fn is_value_terminator(c: char) -> bool {
    matches!(c, '&' | '#' | '"' | '\'' | ')' | ']' | '>' | ';' | ',') || c.is_whitespace()
}

/// Replace every compact JWT (`eyJ` + base64url, two dots) with `<jwt>`.
fn blank_jwts(s: &str) -> String {
    let is_token_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    let mut out = String::with_capacity(s.len());
    let mut from = 0;
    while let Some(found) = s.get(from..).and_then(|rest| rest.find("eyJ")) {
        let start = from + found;
        let len = s
            .get(start..)
            .and_then(|rest| rest.find(|c: char| !is_token_char(c)))
            .unwrap_or_else(|| s.len().saturating_sub(start));
        let token = s.get(start..start + len).unwrap_or_default();
        out.push_str(s.get(from..start).unwrap_or_default());
        if token.matches('.').count() >= 2 {
            out.push_str("<jwt>");
        } else {
            out.push_str(token);
        }
        from = start + len;
    }
    out.push_str(s.get(from..).unwrap_or_default());
    out
}

/// Blank literal secrets (the JWT this connect signed, the project id) out of `msg`, then run the
/// generic redaction. Belt and braces: no error path is known to echo either, but an upstream
/// library's message format is not something to bet a credential on.
fn scrub_connect_error(msg: &str, url: &url::Url, project_id: Option<&str>) -> String {
    let mut out = msg.to_owned();
    let jwt = url
        .query_pairs()
        .find(|(k, _)| k == "auth")
        .map(|(_, v)| v.into_owned());
    for secret in [jwt.as_deref(), project_id].into_iter().flatten() {
        if !secret.is_empty() {
            out = out.replace(secret, "<redacted>");
        }
    }
    redact_transport_error(&out)
}

// ───────────────────────────── flap guard ─────────────────────────────

/// Extra back-off for connections that die right after the upgrade.
///
/// The crate restarts its own reconnect delay at 250 ms after *every* disconnect, so a relay that
/// accepts the upgrade and then closes (a rejected project id, a misbehaving front) makes it redial
/// four times a second forever — each time a fresh JWT and a fresh Tor stream. The guard adds a
/// penalty that doubles per short-lived connection (1, 2, 4 … 30 s) and resets once a connection
/// survives [`FLAP_MIN_LIFETIME`]. Dial *failures* don't count: the crate already backs those off.
#[derive(Debug, Default)]
struct FlapGuard {
    last_up: Option<Instant>,
    penalty: Duration,
}

impl FlapGuard {
    /// 0, or the current penalty (1, 2, 4 … 30 s).
    pub fn delay_before_connect(&self) -> Duration {
        self.penalty
    }

    pub fn connected(&mut self, now: Instant) {
        self.last_up = Some(now);
    }

    /// A connection that lived < 5 s grows the penalty; a healthy one resets it.
    pub fn disconnected(&mut self, now: Instant) {
        // Only a connection we saw come up has a lifetime to judge.
        let Some(up) = self.last_up.take() else {
            return;
        };
        if now.saturating_duration_since(up) < FLAP_MIN_LIFETIME {
            self.penalty = if self.penalty.is_zero() {
                FLAP_FIRST_PENALTY
            } else {
                self.penalty.saturating_mul(2).min(FLAP_MAX_PENALTY)
            };
        } else {
            self.penalty = Duration::ZERO;
        }
    }
}

/// The guard holds two plain values with no invariant a panicking holder could break, so a
/// poisoned lock is simply taken over.
fn lock_flap(flap: &Mutex<FlapGuard>) -> MutexGuard<'_, FlapGuard> {
    flap.lock().unwrap_or_else(PoisonError::into_inner)
}

// ───────────────────────────── connector ─────────────────────────────

/// What every (re)connect needs; fixed for the runtime's lifetime (a settings change applies the
/// next time WalletConnect starts).
struct ConnectorConfig {
    relay: url::Url,
    project_id: Option<String>,
    /// Kao's relay identity: one per runtime, never persisted, so unlocks aren't linkable.
    identity: IdentityKey,
    route: Route,
    timeouts: Timeouts,
}

/// Cloneable "this connector is finished" switch.
///
/// The crate never races a reconnect against its own shutdown: a dial (or a flap back-off) already
/// under way when Kao locks or quits would otherwise run to completion — one more upgrade, with a
/// fresh JWT for this runtime's relay identity, up to a minute after the user locked. Once closed,
/// [`KaoConnector::connect`] refuses without dialling, a back-off in progress ends at once, a dial
/// in progress is abandoned, and a socket that opened anyway is dropped instead of returned.
#[derive(Clone, Default)]
pub struct ConnectorShutdown(Arc<ShutdownState>);

#[derive(Default)]
struct ShutdownState {
    closed: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl ConnectorShutdown {
    /// Idempotent; wakes every connect waiting on it.
    pub fn close(&self) {
        self.0
            .closed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    pub fn is_closed(&self) -> bool {
        self.0.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Resolves once closed (at once if it already is).
    async fn closed(&self) {
        loop {
            // Registered before the flag is read, so a `close` in between can't be missed.
            let notified = self.0.notify.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            if self.is_closed() {
                return;
            }
            notified.await;
        }
    }
}

const SHUT_DOWN: &str = "WalletConnect is shut down";

/// The crate's [`Connector`] for Kao: dials exactly per its [`Route`] and nothing else.
pub struct KaoConnector {
    config: Arc<ConnectorConfig>,
    flap: Arc<Mutex<FlapGuard>>,
    shutdown: ConnectorShutdown,
}

impl KaoConnector {
    pub fn new(
        relay: url::Url,
        project_id: Option<String>,
        identity: IdentityKey,
        route: Route,
        timeouts: Timeouts,
    ) -> Self {
        Self {
            config: Arc::new(ConnectorConfig {
                relay,
                project_id,
                identity,
                route,
                timeouts,
            }),
            flap: Arc::new(Mutex::new(FlapGuard::default())),
            shutdown: ConnectorShutdown::default(),
        }
    }

    /// The switch the runtime closes on lock / quit / retire, so a reconnect the crate has in
    /// flight can't reach the relay afterwards.
    pub fn shutdown_handle(&self) -> ConnectorShutdown {
        self.shutdown.clone()
    }
}

impl Connector for KaoConnector {
    /// delay → fresh JWT URL → timeout(connect_total){ TCP per Route (Direct only for loopback) →
    /// client_async_tls_with_config(url.as_str(), tcp, Some(ws_config()),
    /// Some(Connector::Rustls(tls_config()) | Connector::Plain for ws-loopback)) } → Connection::pair →
    /// tokio::spawn(pump). HTTP 401/403 at upgrade ⇒ Transport("relay rejected the connection (HTTP 401)
    /// — check the WalletConnect project ID"). All error text via redact_transport_error.
    fn connect(&self) -> BoxFuture<wallet_connect::Result<Connection>> {
        let config = Arc::clone(&self.config);
        let flap = Arc::clone(&self.flap);
        let shutdown = self.shutdown.clone();
        Box::pin(async move { connect_once(&config, flap, &shutdown).await })
    }
}

async fn connect_once(
    config: &ConnectorConfig,
    flap: Arc<Mutex<FlapGuard>>,
    shutdown: &ConnectorShutdown,
) -> wallet_connect::Result<Connection> {
    let shut_down = || {
        debug!("relay connect refused: WalletConnect is shut down");
        Err(wallet_connect::Error::Transport(SHUT_DOWN.to_owned()))
    };
    if shutdown.is_closed() {
        return shut_down();
    }
    let delay = lock_flap(&flap).delay_before_connect();
    if !delay.is_zero() {
        info!(
            delay_secs = delay.as_secs(),
            "relay keeps closing right after connecting; waiting before the next attempt"
        );
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = shutdown.closed() => return shut_down(),
        }
    }
    if shutdown.is_closed() {
        return shut_down();
    }

    // Fresh JWT every time: the crate calls this on every reconnect.
    let url = relay_connect_url(
        &config.relay,
        &config.identity,
        config.project_id.as_deref(),
    );
    let kind = route_kind(&config.relay, &config.route);
    let budget = config.timeouts.connect_total;
    let dial = tokio::select! {
        r = tokio::time::timeout(budget, open_socket(config, &url)) => r,
        // Dropping the dial abandons it mid-handshake.
        () = shutdown.closed() => return shut_down(),
    };
    let ws = match dial {
        Ok(Ok(ws)) => ws,
        Ok(Err(msg)) => {
            let msg = scrub_connect_error(&msg, &url, config.project_id.as_deref());
            debug!(route = ?kind, error = %msg, "relay connect failed");
            return Err(wallet_connect::Error::Transport(msg));
        }
        Err(_) => {
            debug!(route = ?kind, budget_ms = budget.as_millis() as u64, "relay connect timed out");
            let msg = match kind {
                RouteKind::Proxied => {
                    "timed out reaching the WalletConnect relay through your proxy — is it running?"
                }
                RouteKind::Direct | RouteKind::Loopback => {
                    "timed out reaching the WalletConnect relay"
                }
            };
            return Err(wallet_connect::Error::Transport(msg.to_owned()));
        }
    };
    drop(url);
    if shutdown.is_closed() {
        // Opened in the instant the switch closed: never handed to the crate.
        drop(ws);
        return shut_down();
    }

    let (app_end, io_end) = Connection::pair();
    lock_flap(&flap).connected(Instant::now());
    debug!(route = ?kind, "relay socket open");
    tokio::spawn(pump(ws, io_end, config.timeouts, flap));
    Ok(app_end)
}

/// TCP per route, then TLS (wss) or plain (ws) and the WebSocket upgrade. Errors are user-facing
/// text that may still contain secrets — the caller scrubs them.
async fn open_socket(
    config: &ConnectorConfig,
    url: &url::Url,
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
    let host = url
        .host()
        .ok_or("the WalletConnect relay URL has no host")?;
    let port = url
        .port_or_known_default()
        .ok_or("the WalletConnect relay URL has no port")?;
    let loopback = crate::net::is_loopback_host(url.host_str());
    let tls = match url.scheme() {
        "wss" => tokio_tungstenite::Connector::Rustls(tls_config()),
        "ws" => tokio_tungstenite::Connector::Plain,
        _ => return Err("the WalletConnect relay URL must be wss://".into()),
    };

    let tcp = match &config.route {
        Route::Direct => {
            // `route_for` is the decision; these re-checks only keep its two direct-dial
            // invariants true even if a caller hands over a Route it didn't produce.
            if !loopback && proxy_env::installed_url().is_some() {
                return Err(
                    "refusing to reach the WalletConnect relay directly while a proxy is installed"
                        .into(),
                );
            }
            if !loopback && url.scheme() == "ws" {
                return Err("plain ws:// is only allowed for a relay on this computer".into());
            }
            dial_direct(&host, port)
                .await
                .map_err(|e| format!("couldn't reach the WalletConnect relay: {e}"))?
        }
        Route::Socks5h { proxy } => socks5h_connect(proxy, host, port).await.map_err(|e| {
            format!("couldn't reach the WalletConnect relay through your proxy: {e}")
        })?,
    };

    // TLS server name and certificate check come from the URL's host, not the socket, so they are
    // end-to-end to the relay even inside a SOCKS tunnel.
    let (ws, _response) = tokio_tungstenite::client_async_tls_with_config(
        url.as_str(),
        tcp,
        Some(ws_config()),
        Some(tls),
    )
    .await
    .map_err(handshake_error)?;
    Ok(ws)
}

/// A direct TCP dial: a loopback relay, or a public one when no proxy is configured at all.
async fn dial_direct(host: &url::Host<&str>, port: u16) -> io::Result<TcpStream> {
    let stream = match host {
        url::Host::Domain(name) => TcpStream::connect((*name, port)).await?,
        url::Host::Ipv4(ip) => TcpStream::connect(SocketAddr::from((*ip, port))).await?,
        url::Host::Ipv6(ip) => TcpStream::connect(SocketAddr::from((*ip, port))).await?,
    };
    stream.set_nodelay(true)?;
    Ok(stream)
}

fn handshake_error(e: tokio_tungstenite::tungstenite::Error) -> String {
    match &e {
        tokio_tungstenite::tungstenite::Error::Http(response) => {
            let code = response.status().as_u16();
            if matches!(code, 401 | 403) {
                format!(
                    "relay rejected the connection (HTTP {code}) — check the WalletConnect project ID"
                )
            } else {
                format!("relay refused the WebSocket upgrade (HTTP {code})")
            }
        }
        other => format!("relay handshake failed: {other}"),
    }
}

// ───────────────────────────── pump ─────────────────────────────

/// Shuttle frames between the relay socket and the crate's channel end until either side stops.
///
/// - outbound `io.receiver` → `Message::text`; `None` (the client shut down or was dropped) → a
///   Close frame, then return;
/// - inbound Text, or Binary that is valid UTF-8 → `io.sender`; *any* frame, Pong included, proves
///   the relay alive and resets the idle timer (tungstenite answers the relay's pings itself);
/// - a Ping every `ping_every`;
/// - idle expiry, a Close, a socket error or the end of the stream → return.
///
/// Returning drops `io.sender`, which is the crate's "connection died" signal: its receiver yields
/// `None` and it reconnects through [`KaoConnector`]. Every write is bounded by `idle` too, so a
/// socket whose send buffer never drains (half-open behind a proxy) can't wedge the loop past the
/// idle timer.
async fn pump<S>(
    ws: WebSocketStream<MaybeTlsStream<S>>,
    io: Connection,
    timeouts: Timeouts,
    flap: Arc<Mutex<FlapGuard>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Connection {
        sender,
        mut receiver,
    } = io;
    let (mut sink, mut stream) = ws.split();
    let start = tokio::time::Instant::now();
    // `interval_at` rejects a zero period; `Timeouts` is plain data, so clamp rather than trust it.
    let ping_every = timeouts.ping_every.max(Duration::from_millis(1));
    let mut ping = tokio::time::interval_at(start + ping_every, ping_every);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let idle = tokio::time::sleep_until(start + timeouts.idle);
    tokio::pin!(idle);

    let ended: &'static str = loop {
        tokio::select! {
            outgoing = receiver.recv() => match outgoing {
                Some(text) => {
                    if !send_bounded(&mut sink, Message::text(text), timeouts.idle).await {
                        break "send failed";
                    }
                }
                None => {
                    let _ = send_bounded(&mut sink, Message::Close(None), timeouts.idle).await;
                    break "client closed";
                }
            },
            incoming = stream.next() => {
                let frame = match incoming {
                    Some(Ok(frame)) => frame,
                    Some(Err(e)) => {
                        // An oversized frame lands here too (`ws_config` limits).
                        debug!(error = %redact_transport_error(&e.to_string()), "relay socket error");
                        break "socket error";
                    }
                    None => break "socket closed",
                };
                idle.as_mut().reset(tokio::time::Instant::now() + timeouts.idle);
                let text = match frame {
                    Message::Text(text) => Some(text.as_str().to_owned()),
                    Message::Binary(bytes) => match std::str::from_utf8(&bytes) {
                        Ok(text) => Some(text.to_owned()),
                        Err(_) => {
                            debug!("dropping a non-UTF-8 binary relay frame");
                            None
                        }
                    },
                    Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => None,
                    Message::Close(_) => break "relay closed",
                };
                if let Some(text) = text
                    && sender.send(text).is_err()
                {
                    // The client's end is gone; nobody will read this socket again.
                    let _ = send_bounded(&mut sink, Message::Close(None), timeouts.idle).await;
                    break "client closed";
                }
            }
            _ = ping.tick() => {
                if !send_bounded(&mut sink, Message::Ping(Default::default()), timeouts.idle).await {
                    break "ping failed";
                }
            }
            () = &mut idle => break "relay silent",
        }
    };

    lock_flap(&flap).disconnected(Instant::now());
    debug!(reason = ended, "relay socket closed");
    // Explicit: dropping our sender is what tells the crate to reconnect.
    drop(sender);
}

/// `sink.send` with an upper bound; `false` on error or timeout.
async fn send_bounded<K>(sink: &mut K, message: Message, limit: Duration) -> bool
where
    K: futures::Sink<Message> + Unpin,
{
    matches!(
        tokio::time::timeout(limit, sink.send(message)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use alloy::primitives::Signature;
    use alloy::signers::SignerSync;
    use alloy::signers::local::PrivateKeySigner;
    use serde_json::json;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
    use tokio_tungstenite::tungstenite::http::StatusCode;
    use wallet_connect::auth::{decode_jwt, verify_jwt};
    use wallet_connect::relay::RelayServer;
    use wallet_connect::sign::{
        ConnectParams, Metadata, ProposalNamespace, SessionRequest, SignClient, SignEvent,
        SignEvents, SupportedNamespace, build_approved_namespaces,
    };

    use super::*;

    const WAIT: Duration = Duration::from_secs(10);
    const PROJECT_ID: &str = "0123456789abcdef0123456789abcdef";

    fn url(s: &str) -> url::Url {
        url::Url::parse(s).unwrap()
    }

    fn quick(connect_total: Duration) -> Timeouts {
        Timeouts {
            connect_total,
            ..Timeouts::for_route(&Route::Direct)
        }
    }

    fn query_pairs(u: &url::Url) -> Vec<(String, String)> {
        u.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn transport_error(r: wallet_connect::Result<Connection>) -> String {
        match r {
            Err(wallet_connect::Error::Transport(msg)) => msg,
            Err(other) => panic!("expected a transport error, got {other}"),
            Ok(_) => panic!("expected the connect to fail"),
        }
    }

    // ── route_for / route_kind ─────────────────────────────────────

    #[test]
    fn route_proxied_when_installed() {
        let relay = url("wss://relay.walletconnect.org");
        for (installed, authority) in [
            ("socks5h://127.0.0.1:9050", "127.0.0.1:9050"),
            ("socks5h://[::1]:9050", "[::1]:9050"),
            ("socks5h://proxy.lan:1080", "proxy.lan:1080"),
            ("SOCKS5H://127.0.0.1:9150", "127.0.0.1:9150"),
        ] {
            for intent in [false, true] {
                assert_eq!(
                    route_for(&relay, Some(installed), intent),
                    Ok(Route::Socks5h {
                        proxy: authority.into()
                    }),
                    "{installed} (intent {intent})"
                );
            }
        }
    }

    #[test]
    fn route_never_direct_for_public_host_when_installed() {
        let relays = [
            "wss://relay.walletconnect.org",
            "wss://relay.walletconnect.com/",
            "wss://relay.example.org:8443/ws",
            "wss://203.0.113.7",
            "wss://[2001:db8::1]:443",
            "wss://192.168.1.20",
            "ws://relay.example.org",
            "https://relay.example.org",
        ];
        let proxies = [
            "socks5h://127.0.0.1:9050",
            "socks5://127.0.0.1:9050",
            "http://127.0.0.1:8080",
            "socks5h://127.0.0.1",
            "socks5h://u:p@127.0.0.1:9050",
            "",
            "not a url",
        ];
        for relay in relays {
            for proxy in proxies {
                for intent in [false, true] {
                    let route = route_for(&url(relay), Some(proxy), intent);
                    assert_ne!(route, Ok(Route::Direct), "{relay} via {proxy:?}");
                }
            }
        }
    }

    #[test]
    fn route_fails_closed_on_unparseable_proxy() {
        let relay = url("wss://relay.walletconnect.org");
        for proxy in [
            "",
            "not a url",
            "socks5h://",
            "socks5h://127.0.0.1",
            "socks5h://127.0.0.1:notaport",
            "socks5h://127.0.0.1:9050/path",
            "socks5h://127.0.0.1:9050/?x=1",
            "socks5h://user:pass@127.0.0.1:9050",
            "socks5h://user@127.0.0.1:9050",
            "127.0.0.1:9050",
        ] {
            assert_eq!(
                route_for(&relay, Some(proxy), false),
                Err(RouteError::ProxyUnparseable),
                "{proxy:?}"
            );
        }
    }

    #[test]
    fn route_fails_closed_on_non_socks5h() {
        let relay = url("wss://relay.walletconnect.org");
        for proxy in [
            "socks5://127.0.0.1:9050",
            "socks4a://127.0.0.1:9050",
            "http://127.0.0.1:8080",
            "https://proxy.example:443",
        ] {
            assert_eq!(
                route_for(&relay, Some(proxy), true),
                Err(RouteError::ProxyScheme),
                "{proxy}"
            );
        }
    }

    #[test]
    fn route_refuses_restart_pending() {
        assert_eq!(
            route_for(&url("wss://relay.walletconnect.org"), None, true),
            Err(RouteError::RestartPending)
        );
        // No proxy wanted, none installed: the only legitimate public direct dial.
        assert_eq!(
            route_for(&url("wss://relay.walletconnect.org"), None, false),
            Ok(Route::Direct)
        );
    }

    #[test]
    fn route_loopback_is_direct() {
        for relay in [
            "ws://127.0.0.1:8080",
            "ws://127.0.0.2:8080",
            "wss://localhost",
            "ws://LOCALHOST:9000/relay",
            "ws://[::1]:9000",
            "wss://[::1]",
        ] {
            for proxy in [None, Some("socks5h://127.0.0.1:9050"), Some("garbage")] {
                for intent in [false, true] {
                    assert_eq!(
                        route_for(&url(relay), proxy, intent),
                        Ok(Route::Direct),
                        "{relay} with {proxy:?} (intent {intent})"
                    );
                }
            }
        }
    }

    #[test]
    fn route_ws_public_refused() {
        for relay in [
            "ws://relay.walletconnect.org",
            "ws://192.168.1.10:8080",
            "ws://10.0.0.1",
            "https://relay.walletconnect.org",
            "http://127.0.0.1:8080",
        ] {
            for proxy in [None, Some("socks5h://127.0.0.1:9050")] {
                assert_eq!(
                    route_for(&url(relay), proxy, false),
                    Err(RouteError::WsNotLoopback),
                    "{relay} with {proxy:?}"
                );
            }
        }
        assert_eq!(
            route_for(&url("mailto:relay@example.org"), None, false),
            Err(RouteError::NoHost)
        );
    }

    #[test]
    fn route_kind_matrix() {
        let socks = Route::Socks5h {
            proxy: "127.0.0.1:9050".into(),
        };
        assert_eq!(
            route_kind(&url("wss://relay.walletconnect.org"), &socks),
            RouteKind::Proxied
        );
        assert_eq!(
            route_kind(&url("wss://relay.walletconnect.org"), &Route::Direct),
            RouteKind::Direct
        );
        for local in [
            "ws://127.0.0.1:8080",
            "ws://[::1]:8080",
            "ws://localhost:8080",
        ] {
            assert_eq!(
                route_kind(&url(local), &Route::Direct),
                RouteKind::Loopback,
                "{local}"
            );
        }
        // A tunnel is a tunnel, whatever the host.
        assert_eq!(
            route_kind(&url("ws://127.0.0.1:8080"), &socks),
            RouteKind::Proxied
        );
        // Consistent with route_for for every route it hands out.
        for (relay, proxy, kind) in [
            (
                "wss://relay.walletconnect.org",
                Some("socks5h://127.0.0.1:9050"),
                RouteKind::Proxied,
            ),
            ("wss://relay.walletconnect.org", None, RouteKind::Direct),
            (
                "ws://127.0.0.1:1",
                Some("socks5h://127.0.0.1:9050"),
                RouteKind::Loopback,
            ),
        ] {
            let relay = url(relay);
            let route = route_for(&relay, proxy, false).unwrap();
            assert_eq!(route_kind(&relay, &route), kind);
        }
    }

    // ── connect URL, timeouts, configs ─────────────────────────────

    #[test]
    fn relay_connect_url_query_order_and_aud() {
        let identity = IdentityKey::generate();
        let relay = url("wss://relay.walletconnect.org");
        let u = relay_connect_url(&relay, &identity, Some(PROJECT_ID));
        let pairs = query_pairs(&u);
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["auth", "ua", "projectId"]);
        assert_eq!(pairs[1].1, RELAY_UA);
        assert_eq!(pairs[2].1, PROJECT_ID);
        assert_eq!(u.scheme(), "wss");
        assert_eq!(u.host_str(), Some("relay.walletconnect.org"));
        // Percent-encoded by append_pair, exactly like the crate's connector.
        let raw = u.query().unwrap();
        assert!(
            raw.contains("&ua=wc-2%2Frust-0.1.0%2Funknown%2Fkao-wallet&"),
            "{raw}"
        );

        // The JWT verifies against this identity, for the query-less, slash-trimmed relay.
        let claims = verify_jwt(&pairs[0].1).unwrap();
        assert_eq!(claims.iss, identity.client_id());
        assert_eq!(claims.aud, "wss://relay.walletconnect.org");
        assert_eq!(claims.exp - claims.iat, DEFAULT_JWT_TTL.as_secs());

        // No project id → no key at all (an empty one counts as absent).
        for project in [None, Some("")] {
            let u = relay_connect_url(&relay, &identity, project);
            let keys: Vec<String> = query_pairs(&u).into_iter().map(|(k, _)| k).collect();
            assert_eq!(keys, ["auth", "ua"]);
        }

        // A path stays in the audience; a trailing slash is trimmed; a stray query/fragment never
        // leaks in.
        let u = relay_connect_url(
            &url("wss://relay.example.org/v2/?projectId=evil#frag"),
            &identity,
            None,
        );
        let pairs = query_pairs(&u);
        assert_eq!(pairs.len(), 2);
        assert_eq!(u.fragment(), None);
        assert_eq!(u.path(), "/v2/");
        assert_eq!(
            decode_jwt(&pairs[0].1).unwrap().aud,
            "wss://relay.example.org/v2"
        );

        // Fresh credentials per call.
        let a = relay_connect_url(&relay, &identity, None);
        let b = relay_connect_url(&relay, &identity, None);
        assert_ne!(query_pairs(&a)[0].1, query_pairs(&b)[0].1);
    }

    #[test]
    fn timeouts_for_route() {
        let direct = Timeouts::for_route(&Route::Direct);
        let proxied = Timeouts::for_route(&Route::Socks5h {
            proxy: "127.0.0.1:9050".into(),
        });
        assert_eq!(direct.connect_total, Duration::from_secs(15));
        assert_eq!(proxied.connect_total, Duration::from_secs(30));
        for t in [direct, proxied] {
            assert_eq!(t.ping_every, Duration::from_secs(20));
            assert_eq!(t.idle, Duration::from_secs(60));
            // The relay gets a few pings' worth of chances before it's declared dead.
            assert!(t.idle >= t.ping_every * 2);
        }
    }

    #[test]
    fn ws_config_limits() {
        let c = ws_config();
        assert_eq!(c.max_message_size, Some(2 * 1024 * 1024));
        assert_eq!(c.max_frame_size, Some(1024 * 1024));
        assert!(c.max_frame_size <= c.max_message_size);
        // Everything else stays tungstenite's (masked-frame enforcement included).
        assert!(!c.accept_unmasked_frames);
    }

    #[test]
    fn tls_config_builds_without_process_default() {
        let a = tls_config();
        let b = tls_config();
        assert!(Arc::ptr_eq(&a, &b), "built once, then cached");
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_none(),
            "building the relay's TLS config must not install a process-wide provider"
        );
        // The explicit provider is ring's (same suites), not whatever a default would have been.
        let ring = rustls::crypto::ring::default_provider();
        let suites = |p: &rustls::crypto::CryptoProvider| {
            p.cipher_suites
                .iter()
                .map(|s| s.suite())
                .collect::<Vec<_>>()
        };
        assert_eq!(suites(a.crypto_provider()), suites(&ring));
        assert!(a.alpn_protocols.is_empty());
        assert!(a.enable_sni);
    }

    /// The review-checklist grep as a test: no code under `src/` may reach for rustls'
    /// provider-less builder, install a process-wide provider, or use tokio-tungstenite's
    /// self-dialling helpers (local DNS + direct TCP) or its connector-less TLS entry point.
    /// Comment lines may name them.
    #[test]
    fn src_never_uses_process_default_tls_or_self_dialling_websockets() {
        let banned = [
            concat!("install", "_default"),
            concat!("ClientConfig::", "builder()"),
            concat!("connect", "_async"),
            concat!("client_async", "_tls("),
            concat!("connector", ": None"),
        ];
        let mut stack = vec![std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src"
        ))];
        let mut hits = Vec::new();
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    for (n, line) in text.lines().enumerate() {
                        if line.trim_start().starts_with("//") {
                            continue;
                        }
                        for b in banned {
                            if line.contains(b) {
                                hits.push(format!("{}:{}: {b}", path.display(), n + 1));
                            }
                        }
                    }
                }
            }
        }
        assert!(
            hits.is_empty(),
            "banned TLS/WebSocket APIs in src/: {hits:#?}"
        );
    }

    // ── SOCKS5h ────────────────────────────────────────────────────

    #[test]
    fn encode_connect_request_domain_atyp3() {
        let bytes = encode_connect_request(&url::Host::Domain("relay.test"), 443).unwrap();
        let mut expected = vec![0x05, 0x01, 0x00, 0x03, 10];
        expected.extend_from_slice(b"relay.test");
        expected.extend_from_slice(&[0x01, 0xbb]);
        assert_eq!(bytes, expected);

        let v4 = encode_connect_request(&url::Host::Ipv4([203, 0, 113, 7].into()), 8080).unwrap();
        assert_eq!(v4, [0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x1f, 0x90]);

        // The URL parser has already turned a name into its IDNA/lowercase form.
        let idn = url("wss://Relay.BÜCHER.example");
        let req = encode_connect_request(&idn.host().unwrap(), 443).unwrap();
        assert_eq!(req[3], 0x03);
        assert!(req[5..].starts_with(b"relay.xn--bcher-kva.example"));

        let too_long = "a".repeat(256);
        assert!(encode_connect_request(&url::Host::Domain(too_long.as_str()), 443).is_err());
        assert!(encode_connect_request(&url::Host::Domain(""), 443).is_err());
        let max = "a".repeat(255);
        assert_eq!(
            encode_connect_request(&url::Host::Domain(max.as_str()), 1).unwrap()[4],
            255
        );
    }

    /// What a scripted fake proxy does after reading the greeting.
    enum Script {
        /// Accept no-auth, read the CONNECT request, answer with `reply`, then send `payload`.
        Answer { reply: Vec<u8>, payload: Vec<u8> },
        /// Answer the greeting with these two bytes and stop.
        Method([u8; 2]),
    }

    /// Everything a fake proxy saw on one connection.
    #[derive(Debug, Default)]
    struct Seen {
        greeting: Vec<u8>,
        request: Vec<u8>,
        trailing: Vec<u8>,
    }

    /// A one-connection SOCKS5 server on loopback that follows `script` and reports what it read.
    async fn fake_socks(script: Script) -> (String, JoinHandle<Seen>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut seen = Seen::default();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            seen.greeting = greeting.to_vec();
            match script {
                Script::Method(m) => {
                    s.write_all(&m).await.unwrap();
                    // Whatever the client sends next (it should send nothing) until it hangs up.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(2),
                        s.read_to_end(&mut seen.trailing),
                    )
                    .await;
                }
                Script::Answer { reply, payload } => {
                    s.write_all(&[0x05, 0x00]).await.unwrap();
                    seen.request = read_connect_request(&mut s).await;
                    s.write_all(&reply).await.unwrap();
                    s.write_all(&payload).await.unwrap();
                    // Hold the socket until the client is done with it.
                    let mut rest = Vec::new();
                    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut rest))
                        .await;
                }
            }
            seen
        });
        (addr, task)
    }

    async fn read_connect_request(s: &mut TcpStream) -> Vec<u8> {
        let mut head = [0u8; 4];
        s.read_exact(&mut head).await.unwrap();
        let mut req = head.to_vec();
        let addr_len = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                s.read_exact(&mut len).await.unwrap();
                req.push(len[0]);
                usize::from(len[0])
            }
            other => panic!("unexpected ATYP {other}"),
        };
        let mut rest = vec![0u8; addr_len + 2];
        s.read_exact(&mut rest).await.unwrap();
        req.extend_from_slice(&rest);
        req
    }

    const OK_REPLY_V4: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];

    async fn read_some(s: &mut TcpStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(WAIT, s.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        buf
    }

    #[tokio::test]
    async fn socks5h_sends_domain_atyp_and_port_be() {
        let (proxy, seen) = fake_socks(Script::Answer {
            reply: OK_REPLY_V4.to_vec(),
            payload: b"hello".to_vec(),
        })
        .await;
        let mut s = socks5h_connect(&proxy, url::Host::Domain("relay.test"), 443)
            .await
            .unwrap();
        // The tunnel is usable straight after the reply.
        assert_eq!(read_some(&mut s, 5).await, b"hello");
        drop(s);
        let seen = seen.await.unwrap();
        assert_eq!(seen.greeting, [0x05, 0x01, 0x00]);
        let mut expected = vec![0x05, 0x01, 0x00, 0x03, 10];
        expected.extend_from_slice(b"relay.test");
        expected.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(seen.request, expected);
    }

    #[tokio::test]
    async fn socks5h_ipv6_literal_uses_atyp4() {
        let (proxy, seen) = fake_socks(Script::Answer {
            reply: OK_REPLY_V4.to_vec(),
            payload: Vec::new(),
        })
        .await;
        let relay = url("wss://[2001:db8::7]:8443");
        let s = socks5h_connect(&proxy, relay.host().unwrap(), 8443)
            .await
            .unwrap();
        drop(s);
        let seen = seen.await.unwrap();
        let mut expected = vec![0x05, 0x01, 0x00, 0x04];
        expected.extend_from_slice(
            &"2001:db8::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        expected.extend_from_slice(&8443u16.to_be_bytes());
        assert_eq!(seen.request, expected);
    }

    #[tokio::test]
    async fn socks5h_rejects_auth_required_proxy() {
        let (proxy, seen) = fake_socks(Script::Method([0x05, 0xFF])).await;
        let err = socks5h_connect(&proxy, url::Host::Domain("relay.test"), 443)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("login"), "{err}");
        let seen = seen.await.unwrap();
        // It offered no-auth only, and never sent the CONNECT after the refusal.
        assert_eq!(seen.greeting, [0x05, 0x01, 0x00]);
        assert!(seen.trailing.is_empty(), "{:?}", seen.trailing);

        // A method Kao didn't offer (USER/PASS) is refused the same way, as is a non-SOCKS5 reply.
        for method in [[0x05, 0x02], [0x04, 0x00]] {
            let (proxy, seen) = fake_socks(Script::Method(method)).await;
            assert!(
                socks5h_connect(&proxy, url::Host::Domain("relay.test"), 443)
                    .await
                    .is_err()
            );
            assert!(seen.await.unwrap().trailing.is_empty());
        }
    }

    #[tokio::test]
    async fn socks5h_rejects_failure_reply() {
        for (rep, words) in [
            (0x05u8, "connection refused"),
            (0x04, "host unreachable"),
            (0x01, "general failure"),
            (0x2a, "0x2a"),
        ] {
            let (proxy, _seen) = fake_socks(Script::Answer {
                reply: vec![0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
                payload: Vec::new(),
            })
            .await;
            let err = socks5h_connect(&proxy, url::Host::Domain("relay.test"), 443)
                .await
                .unwrap_err();
            assert!(err.to_string().contains(words), "{err}");
            assert!(!err.to_string().contains("127.0.0.1"), "{err}");
        }
        // Strict framing: a wrong version, a non-zero RSV or an unknown ATYP all fail.
        for reply in [
            vec![0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0],
            vec![0x05, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0],
            vec![0x05, 0x00, 0x00, 0x09, 0, 0, 0, 0, 0, 0],
        ] {
            let (proxy, _seen) = fake_socks(Script::Answer {
                reply,
                payload: Vec::new(),
            })
            .await;
            let err = socks5h_connect(&proxy, url::Host::Domain("relay.test"), 443)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        }
        // A proxy that hangs up mid-reply.
        let (proxy, seen) = fake_socks(Script::Answer {
            reply: vec![0x05, 0x00],
            payload: Vec::new(),
        })
        .await;
        let pending = socks5h_connect(&proxy, url::Host::Domain("relay.test"), 443);
        // The fake holds the socket open for 2 s before hanging up.
        let err = tokio::time::timeout(WAIT, pending)
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "{err}");
        drop(seen);
    }

    #[tokio::test]
    async fn socks5h_drains_bound_address_all_atyps() {
        let mut domain_reply = vec![0x05, 0x00, 0x00, 0x03, 9];
        domain_reply.extend_from_slice(b"localhost");
        domain_reply.extend_from_slice(&[0x23, 0x82]);
        let mut v6_reply = vec![0x05, 0x00, 0x00, 0x04];
        v6_reply.extend_from_slice(&[0u8; 16]);
        v6_reply.extend_from_slice(&[0x01, 0xbb]);
        let empty_domain = vec![0x05, 0x00, 0x00, 0x03, 0, 0x00, 0x50];
        for reply in [OK_REPLY_V4.to_vec(), domain_reply, v6_reply, empty_domain] {
            let (proxy, _seen) = fake_socks(Script::Answer {
                reply: reply.clone(),
                payload: b"TLS!".to_vec(),
            })
            .await;
            let mut s = socks5h_connect(&proxy, url::Host::Domain("relay.test"), 443)
                .await
                .unwrap();
            // Exactly the reply was consumed: the first tunnelled bytes are intact.
            assert_eq!(read_some(&mut s, 4).await, b"TLS!", "reply {reply:?}");
        }
    }

    // ── error hygiene ──────────────────────────────────────────────

    #[test]
    fn redact_transport_error_strips_credentials() {
        let jwt = "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJkaWQ6a2V5In0.c2lnbmF0dXJl";
        let cases = [
            format!(
                "websocket connect: error for wss://relay.walletconnect.org/?auth={jwt}&ua=x&projectId={PROJECT_ID}"
            ),
            format!("bad request: auth={jwt}&ua=wc-2&projectId={PROJECT_ID} (400)"),
            format!("token {jwt} rejected; PROJECTID={PROJECT_ID}"),
        ];
        for case in cases {
            let out = redact_transport_error(&case);
            assert!(!out.contains(jwt), "{out}");
            assert!(!out.contains("eyJ"), "{out}");
            assert!(!out.contains(PROJECT_ID), "{out}");
        }
        // Hosts and harmless text survive, so the error still says what failed.
        let out = redact_transport_error(
            "relay handshake failed for wss://relay.walletconnect.org/?auth=x: HTTP error: 500",
        );
        assert!(out.contains("wss://relay.walletconnect.org"), "{out}");
        assert!(out.contains("HTTP error: 500"), "{out}");
        assert_eq!(redact_transport_error("plain message"), "plain message");
        // Multi-byte text around a key doesn't trip the byte-offset arithmetic.
        let out = redact_transport_error("é auth=sécret ü projectId=x");
        assert!(!out.contains("sécret"), "{out}");
        assert!(out.starts_with("é auth=…"), "{out}");
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite dictates the handshake callback's error type
    async fn connect_error_strings_never_contain_auth_query() {
        // 1. The relay refuses the upgrade with 401 (what a bad project id looks like).
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let reject = |_: &Request, _: Response| -> Result<Response, ErrorResponse> {
                        let mut e = ErrorResponse::new(Some("project id not found".into()));
                        *e.status_mut() = StatusCode::UNAUTHORIZED;
                        Err(e)
                    };
                    let _ = tokio_tungstenite::accept_hdr_async(tcp, reject).await;
                });
            }
        });
        // 2. Something that isn't a WebSocket server at all.
        let plain = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plain_port = plain.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = plain.accept().await {
                let mut buf = [0u8; 1024];
                let _ = tcp.read(&mut buf).await;
                let _ = tcp
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });
        // 3. A proxy that's down.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap().to_string();
        drop(dead);

        let identity = IdentityKey::generate();
        let attempts = [
            (format!("ws://127.0.0.1:{port}"), Route::Direct, "HTTP 401"),
            (
                format!("ws://127.0.0.1:{plain_port}"),
                Route::Direct,
                "HTTP 200",
            ),
            (
                "wss://relay.walletconnect.org".to_owned(),
                Route::Socks5h { proxy: dead_addr },
                "proxy",
            ),
        ];
        for (relay, route, expect) in attempts {
            let c = KaoConnector::new(
                url(&relay),
                Some(PROJECT_ID.into()),
                identity.clone(),
                route,
                quick(WAIT),
            );
            let msg = transport_error(c.connect().await);
            assert!(msg.contains(expect), "{msg}");
            for leak in ["auth=", "projectId=", "eyJ", PROJECT_ID, "kao-wallet"] {
                assert!(!msg.contains(leak), "{leak} leaked: {msg}");
            }
            if expect == "HTTP 401" {
                assert!(msg.contains("project ID"), "{msg}");
            }
        }
    }

    // ── connector: routing, timeouts, flaps ────────────────────────

    /// A TCP listener that counts connections, holds them open, and otherwise says nothing.
    async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let count = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&count);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((tcp, _)) = listener.accept().await {
                c.fetch_add(1, Ordering::SeqCst);
                held.push(tcp);
            }
        });
        (port, count)
    }

    #[tokio::test]
    async fn connector_has_no_direct_fallback_when_proxy_down() {
        let (ws_port, connections) = counting_listener().await;
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap().to_string();
        drop(dead);
        // The relay is reachable directly, but the route says "through the proxy" — so it must
        // not be reached at all.
        let c = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{ws_port}")),
            None,
            IdentityKey::generate(),
            Route::Socks5h { proxy: dead_addr },
            quick(WAIT),
        );
        for _ in 0..2 {
            let msg = transport_error(c.connect().await);
            assert!(msg.contains("through your proxy"), "{msg}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn connector_refuses_plain_ws_direct_to_public_host() {
        // Fails before any socket or DNS lookup (`.invalid` never resolves anyway).
        let c = KaoConnector::new(
            url("ws://relay.invalid"),
            None,
            IdentityKey::generate(),
            Route::Direct,
            quick(WAIT),
        );
        let msg = transport_error(c.connect().await);
        assert!(msg.contains("ws://"), "{msg}");
        let c = KaoConnector::new(
            url("https://127.0.0.1:1"),
            None,
            IdentityKey::generate(),
            Route::Direct,
            quick(WAIT),
        );
        assert!(transport_error(c.connect().await).contains("wss://"));
    }

    #[tokio::test]
    async fn connect_times_out_on_blackholed_proxy() {
        // Accepts TCP, then never says a word.
        let (proxy_port, accepted) = counting_listener().await;
        let c = KaoConnector::new(
            url("wss://relay.walletconnect.org"),
            Some(PROJECT_ID.into()),
            IdentityKey::generate(),
            Route::Socks5h {
                proxy: format!("127.0.0.1:{proxy_port}"),
            },
            quick(Duration::from_millis(200)),
        );
        let started = Instant::now();
        let msg = transport_error(c.connect().await);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(msg.contains("timed out"), "{msg}");
        assert!(msg.contains("proxy"), "{msg}");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn flap_guard_backs_off_short_lived_connections() {
        let mut g = FlapGuard::default();
        let t0 = Instant::now();
        assert_eq!(g.delay_before_connect(), Duration::ZERO);

        let mut at = t0;
        let mut seen = Vec::new();
        for _ in 0..8 {
            g.connected(at);
            at += Duration::from_secs(1);
            g.disconnected(at);
            seen.push(g.delay_before_connect().as_secs());
            at += g.delay_before_connect();
        }
        assert_eq!(seen, [1, 2, 4, 8, 16, 30, 30, 30]);

        // A connection that survives the grace period clears the penalty.
        g.connected(at);
        g.disconnected(at + FLAP_MIN_LIFETIME);
        assert_eq!(g.delay_before_connect(), Duration::ZERO);

        // A disconnect without a matching connect never happens; it must not grow anything.
        g.disconnected(at + Duration::from_secs(60));
        assert_eq!(g.delay_before_connect(), Duration::ZERO);
    }

    // ── WebSocket servers for the pump / end-to-end tests ──────────

    /// Accept WebSocket upgrades on loopback and hand each socket to `serve`.
    async fn ws_server<F, Fut>(serve: F) -> u16
    where
        F: Fn(WebSocketStream<TcpStream>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let serve = Arc::new(serve);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let serve = Arc::clone(&serve);
                tokio::spawn(async move {
                    if let Ok(ws) = tokio_tungstenite::accept_async(tcp).await {
                        serve(ws).await;
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn pump_drops_silent_connection_after_idle() {
        // Completes the upgrade, then never reads (so never pongs) and never writes.
        let port = ws_server(|ws| async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(ws);
        })
        .await;
        let c = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{port}")),
            None,
            IdentityKey::generate(),
            Route::Direct,
            Timeouts {
                connect_total: WAIT,
                ping_every: Duration::from_millis(50),
                idle: Duration::from_millis(200),
            },
        );
        let started = Instant::now();
        let mut conn = c.connect().await.unwrap();
        let next = tokio::time::timeout(Duration::from_secs(5), conn.receiver.recv()).await;
        assert!(matches!(next, Ok(None)), "the pump must drop its sender");
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[tokio::test]
    async fn pump_keeps_a_relay_that_answers_pings() {
        // A relay that reads (so tungstenite pongs) but never sends data of its own.
        let port =
            ws_server(|mut ws| async move { while let Some(Ok(_)) = ws.next().await {} }).await;
        let c = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{port}")),
            None,
            IdentityKey::generate(),
            Route::Direct,
            Timeouts {
                connect_total: WAIT,
                ping_every: Duration::from_millis(50),
                idle: Duration::from_secs(1),
            },
        );
        let mut conn = c.connect().await.unwrap();
        // Well past the idle limit (about 50 pings): Pongs alone keep it alive.
        let next = tokio::time::timeout(Duration::from_millis(2500), conn.receiver.recv()).await;
        assert!(
            next.is_err(),
            "a ponging relay must not be dropped: {next:?}"
        );
    }

    #[tokio::test]
    async fn pump_closes_socket_when_client_drops() {
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel::<&'static str>();
        let port = ws_server(move |mut ws| {
            let seen_tx = seen_tx.clone();
            async move {
                let what = match ws.next().await {
                    Some(Ok(Message::Close(_))) => "close",
                    Some(Ok(_)) => "data",
                    Some(Err(_)) => "error",
                    None => "eof",
                };
                let _ = seen_tx.send(what);
            }
        })
        .await;
        let c = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{port}")),
            None,
            IdentityKey::generate(),
            Route::Direct,
            quick(WAIT),
        );
        let conn = c.connect().await.unwrap();
        drop(conn);
        let what = tokio::time::timeout(WAIT, seen_rx.recv()).await.unwrap();
        assert_eq!(what, Some("close"));
    }

    #[tokio::test]
    async fn pump_moves_text_and_utf8_binary_and_enforces_frame_limit() {
        let port = ws_server(|mut ws| async move {
            // Echo the client's first message, then a binary UTF-8 frame, a non-UTF-8 one
            // (dropped), and finally a frame over WS_MAX_FRAME, which must end the connection.
            if let Some(Ok(Message::Text(t))) = ws.next().await {
                let _ = ws.send(Message::text(format!("echo:{}", t.as_str()))).await;
            }
            let _ = ws.send(Message::binary(b"bin".to_vec())).await;
            let _ = ws.send(Message::binary(vec![0xff, 0xfe])).await;
            let _ = ws.send(Message::text("after")).await;
            let _ = ws.send(Message::binary(vec![b'x'; WS_MAX_FRAME + 1])).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        })
        .await;
        let c = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{port}")),
            None,
            IdentityKey::generate(),
            Route::Direct,
            quick(WAIT),
        );
        let mut conn = c.connect().await.unwrap();
        conn.sender.send("ping-me".into()).unwrap();
        let mut got = Vec::new();
        while let Ok(Some(text)) = tokio::time::timeout(WAIT, conn.receiver.recv()).await {
            got.push(text);
        }
        assert_eq!(got, ["echo:ping-me", "bin", "after"]);
    }

    #[tokio::test]
    async fn connector_backs_off_after_a_short_lived_connection() {
        // Upgrades, then hangs up at once — the shape of a relay rejecting the project id late.
        let port = ws_server(|mut ws| async move {
            let _ = ws.close(None).await;
        })
        .await;
        let c = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{port}")),
            None,
            IdentityKey::generate(),
            Route::Direct,
            quick(WAIT),
        );
        let mut first = c.connect().await.unwrap();
        assert!(
            tokio::time::timeout(WAIT, first.receiver.recv())
                .await
                .unwrap()
                .is_none()
        );
        let started = Instant::now();
        let _second = c.connect().await.unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(900),
            "a reconnect after a flap must wait out the penalty ({:?})",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn connector_refuses_to_dial_once_shut_down() {
        let (port, connections) = counting_listener().await;
        let c = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{port}")),
            None,
            IdentityKey::generate(),
            Route::Direct,
            quick(WAIT),
        );
        let off = c.shutdown_handle();
        assert!(!off.is_closed());
        off.close();
        off.close(); // idempotent
        assert!(off.is_closed());
        for _ in 0..2 {
            let msg = transport_error(c.connect().await);
            assert!(msg.contains("shut down"), "{msg}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 0, "nothing was dialled");
    }

    #[tokio::test]
    async fn shutdown_abandons_a_dial_in_flight() {
        // Accepts TCP, then never answers the upgrade: the dial would hang for its whole budget.
        let (port, connections) = counting_listener().await;
        let c = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{port}")),
            None,
            IdentityKey::generate(),
            Route::Direct,
            quick(WAIT),
        );
        let off = c.shutdown_handle();
        let dial = tokio::spawn(c.connect());
        wait_until(|| connections.load(Ordering::SeqCst) == 1).await;
        let started = Instant::now();
        off.close();
        let msg = transport_error(dial.await.unwrap());
        assert!(msg.contains("shut down"), "{msg}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "not the 10 s budget"
        );
    }

    #[tokio::test]
    async fn shutdown_ends_a_flap_back_off() {
        let port = ws_server(|mut ws| async move {
            let _ = ws.close(None).await;
        })
        .await;
        let c = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{port}")),
            None,
            IdentityKey::generate(),
            Route::Direct,
            quick(WAIT),
        );
        let mut first = c.connect().await.unwrap();
        assert!(
            tokio::time::timeout(WAIT, first.receiver.recv())
                .await
                .unwrap()
                .is_none()
        );
        // The next connect now owes a ≥ 1 s flap penalty; closing cuts it short.
        let off = c.shutdown_handle();
        let started = Instant::now();
        let second = tokio::spawn(c.connect());
        tokio::time::sleep(Duration::from_millis(100)).await;
        off.close();
        let msg = transport_error(second.await.unwrap());
        assert!(msg.contains("shut down"), "{msg}");
        assert!(
            started.elapsed() < Duration::from_millis(900),
            "woke before the penalty ran out ({:?})",
            started.elapsed()
        );
    }

    /// Poll `cond` until it holds (≤ 2 s).
    async fn wait_until(cond: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !cond() {
            assert!(Instant::now() < deadline, "condition never held");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // ── end to end: a real SignClient over Kao's transport ─────────

    /// Bridge a WebSocket to an in-process relay endpoint until either side closes.
    async fn bridge<S>(ws: WebSocketStream<S>, endpoint: Connection)
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Connection {
            sender,
            mut receiver,
        } = endpoint;
        let (mut sink, mut stream) = ws.split();
        loop {
            tokio::select! {
                out = receiver.recv() => match out {
                    Some(text) => {
                        if sink.send(Message::text(text)).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        let _ = sink.send(Message::Close(None)).await;
                        break;
                    }
                },
                inc = stream.next() => match inc {
                    Some(Ok(Message::Text(text))) => {
                        if sender.send(text.as_str().to_owned()).is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
            }
        }
    }

    /// A loopback WebSocket front for an in-process `RelayServer`, standing in for the public
    /// relay: it authenticates the connect JWT (the token's `iss` becomes the client id, as on the
    /// real relay), records every upgrade's query string, and bridges frames to `relay.accept(iss)`.
    #[allow(clippy::result_large_err)] // tungstenite dictates the handshake callback's error type
    async fn ws_relay_front(relay: RelayServer) -> (u16, Arc<Mutex<Vec<String>>>) {
        let queries = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&queries);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let relay = relay.clone();
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut query = String::new();
                    let capture =
                        |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                            query = req.uri().query().unwrap_or_default().to_owned();
                            Ok(resp)
                        };
                    let Ok(ws) = tokio_tungstenite::accept_hdr_async(tcp, capture).await else {
                        return;
                    };
                    recorded.lock().unwrap().push(query.clone());
                    let jwt = url::form_urlencoded::parse(query.as_bytes())
                        .find(|(k, _)| k == "auth")
                        .map(|(_, v)| v.into_owned())
                        .unwrap_or_default();
                    let Ok(claims) = verify_jwt(&jwt) else {
                        return;
                    };
                    bridge(ws, relay.accept(claims.iss)).await;
                });
            }
        });
        (port, queries)
    }

    async fn next_event(events: &mut SignEvents) -> SignEvent {
        tokio::time::timeout(WAIT, events.recv())
            .await
            .expect("no wallet event in time")
            .expect("event stream closed")
    }

    /// Pair a dapp (attached straight to `relay`) with a Kao `SignClient` built on `connector`,
    /// then have the dapp ask for a personal_sign that Kao signs with a fresh key; the dapp checks
    /// the signature recovers to the session's account.
    async fn pair_and_personal_sign(relay: &RelayServer, connector: KaoConnector) {
        let signer = PrivateKeySigner::random();
        let address = signer.address().to_checksum(None);

        let (dapp, _dapp_events) = SignClient::builder(Metadata::new(
            "dapp",
            "transport test dapp",
            "https://dapp.example",
        ))
        .connector(relay.connector("dapp"))
        .build()
        .await
        .unwrap();
        let (kao, mut kao_events) = SignClient::builder(crate::walletconnect::kao_metadata())
            .connector(connector)
            .build()
            .await
            .unwrap();

        let required = BTreeMap::from([(
            "eip155".to_owned(),
            ProposalNamespace::new(["eip155:1"], ["personal_sign"], ["chainChanged"]),
        )]);
        let connect = dapp
            .connect(ConnectParams {
                required_namespaces: required,
                ..Default::default()
            })
            .await
            .unwrap();
        let uri = connect.uri.expect("a fresh pairing has a URI");
        kao.pair(&uri.to_string()).await.unwrap();
        let proposal = loop {
            if let SignEvent::SessionProposal(p) = next_event(&mut kao_events).await {
                break p;
            }
        };
        let supported = BTreeMap::from([(
            "eip155".to_owned(),
            SupportedNamespace {
                chains: vec!["eip155:1".into()],
                methods: vec!["personal_sign".into()],
                events: vec!["chainChanged".into()],
                accounts: vec![format!("eip155:1:{address}")],
            },
        )]);
        let namespaces = build_approved_namespaces(
            &proposal.required_namespaces,
            &proposal.optional_namespaces,
            &supported,
        )
        .unwrap();
        kao.approve(proposal.id, namespaces).await.unwrap();
        let session = tokio::time::timeout(WAIT, connect.approval)
            .await
            .unwrap()
            .unwrap();

        let message = b"Sign in to dapp.example over Kao's own transport";
        let request = {
            let dapp = dapp.clone();
            let topic = session.topic.clone();
            let params = json!([format!("0x{}", alloy::hex::encode(message)), address]);
            tokio::spawn(async move {
                dapp.request(
                    &topic,
                    "eip155:1",
                    SessionRequest::new("personal_sign", params),
                )
                .await
            })
        };
        let pending = loop {
            if let SignEvent::SessionRequest(p) = next_event(&mut kao_events).await {
                break p;
            }
        };
        assert_eq!(pending.request.method, "personal_sign");
        let asked = pending.request.params[0].as_str().unwrap();
        let bytes = alloy::hex::decode(asked).unwrap();
        assert_eq!(bytes, message);
        let signature = signer.sign_message_sync(&bytes).unwrap();
        kao.respond(
            &pending.topic,
            pending.id,
            Ok(json!(format!(
                "0x{}",
                alloy::hex::encode(signature.as_bytes())
            ))),
        )
        .await
        .unwrap();

        let answer = tokio::time::timeout(WAIT, request)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let returned: Signature = answer.as_str().unwrap().parse().unwrap();
        assert_eq!(
            returned.recover_address_from_msg(message).unwrap(),
            signer.address()
        );
        kao.shutdown();
        dapp.shutdown();
    }

    #[tokio::test]
    async fn kao_ws_transport_round_trip_over_loopback() {
        let relay = RelayServer::new();
        let (port, queries) = ws_relay_front(relay.clone()).await;
        let identity = IdentityKey::generate();
        let client_id = identity.client_id();
        let connector = KaoConnector::new(
            url(&format!("ws://127.0.0.1:{port}")),
            Some(PROJECT_ID.into()),
            identity,
            Route::Direct,
            Timeouts::for_route(&Route::Direct),
        );
        pair_and_personal_sign(&relay, connector).await;

        // What actually crossed the wire on the upgrade.
        let queries = queries.lock().unwrap().clone();
        assert_eq!(queries.len(), 1, "one connection, no reconnects");
        let pairs: Vec<(String, String)> = url::form_urlencoded::parse(queries[0].as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["auth", "ua", "projectId"]);
        assert_eq!(pairs[1].1, RELAY_UA);
        assert_eq!(pairs[2].1, PROJECT_ID);
        let claims = verify_jwt(&pairs[0].1).unwrap();
        assert_eq!(claims.iss, client_id);
        assert_eq!(claims.aud, format!("ws://127.0.0.1:{port}"));
    }

    #[tokio::test]
    async fn kao_ws_transport_through_fake_socks5() {
        let relay = RelayServer::new();
        let (ws_port, queries) = ws_relay_front(relay.clone()).await;

        // A SOCKS5 proxy that records the handshake, "resolves" relay.test itself, and splices the
        // tunnel to the WebSocket front.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap().to_string();
        // (greeting, CONNECT request) per tunnel.
        type Handshakes = Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>;
        let seen: Handshakes = Arc::default();
        let record = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut client, _)) = proxy.accept().await {
                let record = Arc::clone(&record);
                tokio::spawn(async move {
                    let mut greeting = [0u8; 3];
                    if client.read_exact(&mut greeting).await.is_err()
                        || client.write_all(&[0x05, 0x00]).await.is_err()
                    {
                        return;
                    }
                    let request = read_connect_request(&mut client).await;
                    record.lock().unwrap().push((greeting.to_vec(), request));
                    let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", ws_port)).await else {
                        return;
                    };
                    if client.write_all(&OK_REPLY_V4).await.is_err() {
                        return;
                    }
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });

        let route = Route::Socks5h { proxy: proxy_addr };
        let connector = KaoConnector::new(
            url(&format!("ws://relay.test:{ws_port}")),
            Some(PROJECT_ID.into()),
            IdentityKey::generate(),
            route.clone(),
            Timeouts::for_route(&route),
        );
        pair_and_personal_sign(&relay, connector).await;

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "one tunnel, no reconnects");
        let (greeting, request) = &seen[0];
        assert_eq!(greeting, &[0x05, 0x01, 0x00]);
        let mut expected = vec![0x05, 0x01, 0x00, 0x03, 10];
        expected.extend_from_slice(b"relay.test");
        expected.extend_from_slice(&ws_port.to_be_bytes());
        assert_eq!(request, &expected);
        // The relay front saw the authenticated upgrade come through the tunnel.
        let queries = queries.lock().unwrap();
        assert_eq!(queries.len(), 1);
        let aud = url::form_urlencoded::parse(queries[0].as_bytes())
            .find(|(k, _)| k == "auth")
            .map(|(_, jwt)| verify_jwt(&jwt).unwrap().aud)
            .unwrap();
        assert_eq!(aud, format!("ws://relay.test:{ws_port}"));
    }
}
