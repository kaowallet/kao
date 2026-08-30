//! Verified-contract ABI lookup: Sourcify first (no key), then Etherscan V2
//! `getsourcecode` when a free API key is set.
//!
//! This is what an explorer page shows: the JSON ABI published for *this
//! address*, with declared parameter names. It is not a selector database —
//! a hit for `transfer` on USDC is USDC's `transfer(to, amount)`, not a
//! global guess that `0xa9059cbb` means `transfer(address,uint256)`.
//!
//! Etherscan's contract ABI endpoint is a community (free-key) call, not
//! Pro. Sourcify needs nothing. Unit tests never hit the network.

use alloy::primitives::Address;
use serde::Deserialize;

use crate::indexer::{http_client_or_err, redact_url_in_err};

const ETHERSCAN: &str = "https://api.etherscan.io/v2/api";
const SOURCIFY: &str = "https://sourcify.dev/server/v2/contract";

/// Where a [`VerifiedAbi`] was published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiOrigin {
    Sourcify,
    Etherscan,
}

/// A verified JSON ABI for the address the user typed.
///
/// `implementation` is set when the explorer (or our proxy walk) says the
/// address is a proxy: the ABI came from that implementation, but calls
/// still go to the user's address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAbi {
    pub json: String,
    pub contract_name: String,
    pub implementation: Option<Address>,
    pub origin: AbiOrigin,
}

/// Verified ABI for `address` on `chain_id`, or `Ok(None)` when there isn't
/// one we can use.
///
/// Sourcify is tried first (no key). Etherscan is the fallback when a free
/// API key is configured. `walked_implementation` is the address our own
/// proxy walker landed on (when it differs from `address`): used as a
/// fallback when the explorer has not tagged the proxy, and as the ABI
/// source when it has.
pub async fn fetch_verified_abi(
    chain_id: u64,
    address: Address,
    walked_implementation: Option<Address>,
) -> Result<Option<VerifiedAbi>, String> {
    if cfg!(test) {
        return Ok(None);
    }
    let mut last_err = None;
    match fetch_from(
        Provider::Sourcify,
        chain_id,
        address,
        walked_implementation,
        None,
    )
    .await
    {
        Ok(Some(v)) => return Ok(Some(v)),
        Ok(None) => {}
        Err(e) => last_err = Some(e),
    }
    if let Some(api_key) = crate::settings::etherscan_api_key() {
        match fetch_from(
            Provider::Etherscan,
            chain_id,
            address,
            walked_implementation,
            Some(&api_key),
        )
        .await
        {
            Ok(Some(v)) => return Ok(Some(v)),
            Ok(None) => {}
            Err(e) => last_err = Some(e),
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

#[derive(Clone, Copy)]
enum Provider {
    Sourcify,
    Etherscan,
}

async fn fetch_from(
    provider: Provider,
    chain_id: u64,
    address: Address,
    walked_implementation: Option<Address>,
    api_key: Option<&str>,
) -> Result<Option<VerifiedAbi>, String> {
    let page = lookup(provider, chain_id, address, api_key).await?;
    let impl_addr = page
        .as_ref()
        .and_then(|p| {
            p.implementation
                .filter(|i| *i != address)
                .or_else(|| walked_implementation.filter(|i| *i != address))
        })
        .or_else(|| walked_implementation.filter(|i| *i != address));
    let follow = page
        .as_ref()
        .is_none_or(|p| p.is_proxy || p.abi_json.is_none());
    let impl_page = if let Some(impl_addr) = impl_addr.filter(|_| follow) {
        lookup(provider, chain_id, impl_addr, api_key)
            .await
            .ok()
            .flatten()
    } else {
        None
    };
    let origin = match provider {
        Provider::Sourcify => AbiOrigin::Sourcify,
        Provider::Etherscan => AbiOrigin::Etherscan,
    };
    Ok(assemble(page, address, impl_addr, impl_page, origin))
}

fn assemble(
    page: Option<SourcePage>,
    address: Address,
    impl_addr: Option<Address>,
    impl_page: Option<SourcePage>,
    origin: AbiOrigin,
) -> Option<VerifiedAbi> {
    if let Some(impl_addr) = impl_addr
        && let Some(impl_page) = impl_page
        && let Some(json) = impl_page.abi_json
    {
        let contract_name = match &page {
            Some(p) if impl_page.contract_name.is_empty() => p.contract_name.clone(),
            _ => impl_page.contract_name,
        };
        return Some(VerifiedAbi {
            json,
            contract_name,
            implementation: Some(impl_addr),
            origin,
        });
    }
    let page = page?;
    page.abi_json.map(|json| VerifiedAbi {
        json,
        contract_name: page.contract_name,
        implementation: impl_addr.filter(|i| *i != address),
        origin,
    })
}

async fn lookup(
    provider: Provider,
    chain_id: u64,
    address: Address,
    api_key: Option<&str>,
) -> Result<Option<SourcePage>, String> {
    match provider {
        Provider::Sourcify => sourcify_contract(chain_id, address).await,
        Provider::Etherscan => {
            let key = api_key.ok_or_else(|| "etherscan: missing API key".to_string())?;
            getsourcecode(chain_id, address, key).await.map(Some)
        }
    }
}

#[derive(Debug)]
struct SourcePage {
    abi_json: Option<String>,
    contract_name: String,
    implementation: Option<Address>,
    is_proxy: bool,
}

async fn sourcify_contract(chain_id: u64, address: Address) -> Result<Option<SourcePage>, String> {
    let url = format!("{SOURCIFY}/{chain_id}/{address}?fields=abi,compilation,proxyResolution");
    let resp = http_client_or_err()?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("sourcify GET: {}", redact_url_in_err(e)))?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    let resp = resp
        .error_for_status()
        .map_err(|e| format!("sourcify status: {}", redact_url_in_err(e)))?;
    let body = resp
        .text()
        .await
        .map_err(|e| format!("sourcify body: {}", redact_url_in_err(e)))?;
    parse_sourcify_body(&body)
}

fn parse_sourcify_body(body: &str) -> Result<Option<SourcePage>, String> {
    let row: SourcifyContract =
        serde_json::from_str(body).map_err(|e| format!("sourcify decode: {e}"))?;
    let abi_json = row.abi.as_ref().and_then(json_array);
    Ok(Some(SourcePage {
        abi_json,
        contract_name: row.compilation.and_then(|c| c.name).unwrap_or_default(),
        implementation: row
            .proxy
            .as_ref()
            .and_then(|p| p.implementations.first())
            .and_then(|i| parse_impl(&i.address)),
        is_proxy: row.proxy.is_some_and(|p| p.is_proxy),
    }))
}

fn json_array(v: &serde_json::Value) -> Option<String> {
    v.is_array().then(|| v.to_string())
}

async fn getsourcecode(
    chain_id: u64,
    address: Address,
    api_key: &str,
) -> Result<SourcePage, String> {
    let url = format!(
        "{ETHERSCAN}?chainid={chain_id}&module=contract&action=getsourcecode&address={}&apikey={}",
        urlencode(&format!("{address}")),
        urlencode(api_key),
    );
    let resp = http_client_or_err()?
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("etherscan GET: {}", redact_url_in_err(e)))?
        .error_for_status()
        .map_err(|e| format!("etherscan status: {}", redact_url_in_err(e)))?;
    let body = resp
        .text()
        .await
        .map_err(|e| format!("etherscan body: {}", redact_url_in_err(e)))?;
    parse_source_envelope(&body)
}

fn parse_source_envelope(body: &str) -> Result<SourcePage, String> {
    let env: Envelope = serde_json::from_str(body).map_err(|e| format!("etherscan decode: {e}"))?;
    let row = match env.result {
        EnvelopeResult::Rows(mut rows) if env.status == "1" => rows
            .pop()
            .ok_or_else(|| "etherscan: empty getsourcecode result".to_string())?,
        EnvelopeResult::Rows(_) => {
            return Err(format!(
                "etherscan: getsourcecode rejected ({})",
                env.status
            ));
        }
        EnvelopeResult::Err(msg) => {
            // Unverified contracts sometimes arrive as status=0 with this
            // sentence instead of status=1 plus the same text in `ABI`.
            if msg.to_ascii_lowercase().contains("not verified") {
                return Ok(SourcePage {
                    abi_json: None,
                    contract_name: String::new(),
                    implementation: None,
                    is_proxy: false,
                });
            }
            return Err(format!("etherscan: {msg}"));
        }
    };
    Ok(SourcePage {
        abi_json: verified_abi_json(&row.abi),
        contract_name: row.contract_name,
        implementation: parse_impl(&row.implementation),
        is_proxy: row.proxy == "1",
    })
}

/// Keep the ABI field only when it is a JSON array — Etherscan puts the
/// sentence `"Contract source code not verified"` in the same slot.
fn verified_abi_json(abi: &str) -> Option<String> {
    let t = abi.trim();
    if t.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(t).ok()?;
    v.is_array().then(|| t.to_string())
}

fn parse_impl(s: &str) -> Option<Address> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let addr: Address = s.parse().ok()?;
    (!addr.is_zero()).then_some(addr)
}

/// Minimal RFC 3986 percent-encoder, same grammar as the indexer clients.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[derive(Deserialize)]
struct Envelope {
    status: String,
    result: EnvelopeResult,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum EnvelopeResult {
    Rows(Vec<SourceRow>),
    Err(String),
}

#[derive(Deserialize)]
struct SourceRow {
    #[serde(rename = "ABI", default)]
    abi: String,
    #[serde(rename = "ContractName", default)]
    contract_name: String,
    #[serde(rename = "Proxy", default)]
    proxy: String,
    #[serde(rename = "Implementation", default)]
    implementation: String,
}

#[derive(Deserialize)]
struct SourcifyContract {
    abi: Option<serde_json::Value>,
    #[serde(default)]
    compilation: Option<SourcifyCompilation>,
    #[serde(rename = "proxyResolution", default)]
    proxy: Option<SourcifyProxy>,
}

#[derive(Deserialize)]
struct SourcifyCompilation {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct SourcifyProxy {
    #[serde(rename = "isProxy", default)]
    is_proxy: bool,
    #[serde(default)]
    implementations: Vec<SourcifyImpl>,
}

#[derive(Deserialize)]
struct SourcifyImpl {
    #[serde(default)]
    address: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Chain;

    const TRANSFER_ABI: &str = r#"[{"inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"name":"transfer","stateMutability":"nonpayable","type":"function"}]"#;

    #[test]
    fn verified_row_keeps_the_json_abi_and_name() {
        let body = format!(
            r#"{{"status":"1","message":"OK","result":[{{"SourceCode":"","ABI":{abi},"ContractName":"UsdC","CompilerVersion":"","Proxy":"0","Implementation":""}}]}}"#,
            abi = serde_json::to_string(TRANSFER_ABI).unwrap(),
        );
        let page = parse_source_envelope(&body).unwrap();
        assert_eq!(page.contract_name, "UsdC");
        assert_eq!(page.abi_json.as_deref(), Some(TRANSFER_ABI));
        assert!(page.implementation.is_none());
        assert!(!page.is_proxy);
    }

    #[test]
    fn unverified_sentence_is_not_an_abi() {
        let body = r#"{
            "status":"1","message":"OK","result":[{
                "SourceCode":"","ABI":"Contract source code not verified",
                "ContractName":"","Proxy":"0","Implementation":""
            }]
        }"#;
        let page = parse_source_envelope(body).unwrap();
        assert!(page.abi_json.is_none());
        assert!(page.contract_name.is_empty());
    }

    #[test]
    fn proxy_row_carries_the_implementation_address() {
        let impl_addr = "0xa2327a938FebF21FFE548b55E06C0aa8C020a6a1";
        let body = format!(
            r#"{{"status":"1","message":"OK","result":[{{"SourceCode":"","ABI":{abi},"ContractName":"FiatTokenProxy","Proxy":"1","Implementation":"{impl_addr}"}}]}}"#,
            abi = serde_json::to_string(TRANSFER_ABI).unwrap(),
        );
        let page = parse_source_envelope(&body).unwrap();
        assert!(page.is_proxy);
        assert_eq!(
            page.implementation,
            Some(impl_addr.parse().unwrap()),
            "the ABI on a verified proxy is the implementation's, and the pointer has to survive so calls still land on the proxy"
        );
        assert_eq!(page.abi_json.as_deref(), Some(TRANSFER_ABI));
    }

    #[test]
    fn a_zero_implementation_is_no_implementation() {
        assert!(parse_impl("").is_none());
        assert!(parse_impl("0x0000000000000000000000000000000000000000").is_none());
        assert!(parse_impl("not an address").is_none());
    }

    #[test]
    fn a_rejected_envelope_is_an_error() {
        let body = r#"{"status":"0","message":"NOTOK","result":"Invalid API Key"}"#;
        let err = parse_source_envelope(body).unwrap_err();
        assert!(err.contains("Invalid API Key"), "{err}");
    }

    #[test]
    fn unverified_as_a_top_level_error_is_not_an_abi() {
        let body =
            r#"{"status":"0","message":"NOTOK","result":"Contract source code not verified"}"#;
        let page = parse_source_envelope(body).unwrap();
        assert!(page.abi_json.is_none());
    }

    #[test]
    fn verified_abi_json_rejects_a_bare_object() {
        assert!(verified_abi_json(r#"{"name":"transfer"}"#).is_none());
        assert!(verified_abi_json("[]").is_some());
    }

    #[test]
    fn sourcify_body_keeps_abi_name_and_proxy() {
        let impl_addr = "0xa2327a938FebF21FFE548b55E06C0aa8C020a6a1";
        let body = format!(
            r#"{{"abi":{abi},"compilation":{{"name":"FiatTokenV2"}},"proxyResolution":{{"isProxy":true,"implementations":[{{"address":"{impl_addr}"}}]}}}}"#,
            abi = TRANSFER_ABI,
        );
        let page = parse_sourcify_body(&body).unwrap().unwrap();
        assert_eq!(page.contract_name, "FiatTokenV2");
        assert!(page.is_proxy);
        assert_eq!(page.implementation, Some(impl_addr.parse().unwrap()));
        assert!(page.abi_json.is_some());
    }

    #[test]
    fn sourcify_body_without_abi_is_empty_not_an_error() {
        let body = r#"{"match":"exact_match","compilation":{"name":"X"}}"#;
        let page = parse_sourcify_body(body).unwrap().unwrap();
        assert!(page.abi_json.is_none());
        assert_eq!(page.contract_name, "X");
    }

    #[tokio::test]
    async fn fetch_verified_abi_is_inert_in_unit_tests() {
        let got = fetch_verified_abi(Chain::Mainnet.chain_id(), Address::repeat_byte(0x11), None)
            .await
            .unwrap();
        assert!(got.is_none());
    }
}
