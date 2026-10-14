//! Payloads shaped the way real dapp libraries put them on the wire: the JSON a JS dapp sends, not
//! what Kao's own client would build. Each builder names the library whose output it mirrors, so a
//! test failing on one of them is a dapp Kao can't serve.

use alloy::primitives::{Address, U256, address};
use serde_json::{Map, Value, json};
use wallet_connect::crypto::{PublicKey, Topic};

use super::super::caip2;

/// The JS sign-client stamps every request with `expiryTimestamp = now + 5 min`.
pub(crate) const SDK_REQUEST_TTL_SECS: u64 = 300;

/// A `wc_sessionRequest`'s `request` object as the JS sign-client sends it.
pub(crate) fn sdk_request(method: &str, params: Value, now: u64) -> Value {
    json!({
        "method": method,
        "params": params,
        "expiryTimestamp": now + SDK_REQUEST_TTL_SECS,
    })
}

// ── Session proposal ──────────────────────────────────────────────────────────────────────────────

/// `@walletconnect/ethereum-provider`'s `OPTIONAL_METHODS`, in its order.
pub(crate) const ETHEREUM_PROVIDER_METHODS: &[&str] = &[
    "eth_accounts",
    "eth_requestAccounts",
    "eth_sendRawTransaction",
    "eth_sign",
    "eth_signTransaction",
    "eth_signTypedData",
    "eth_signTypedData_v3",
    "eth_signTypedData_v4",
    "eth_sendTransaction",
    "personal_sign",
    "wallet_switchEthereumChain",
    "wallet_addEthereumChain",
    "wallet_getPermissions",
    "wallet_requestPermissions",
    "wallet_registerOnboarding",
    "wallet_watchAsset",
    "wallet_scanQRCode",
    "wallet_sendCalls",
    "wallet_getCapabilities",
    "wallet_getCallsStatus",
    "wallet_showCallsStatus",
];

/// `@walletconnect/ethereum-provider`'s `OPTIONAL_EVENTS`.
pub(crate) const ETHEREUM_PROVIDER_EVENTS: &[&str] = &[
    "chainChanged",
    "accountsChanged",
    "message",
    "disconnect",
    "connect",
];

/// The dapp's chains in its order: Arbitrum and Polygon (which Kao doesn't serve) first.
pub(crate) const PROPOSAL_CHAINS: &[u64] = &[42_161, 137, 1, 8453, 10];

/// What a multichain AppKit dapp adds next to Ethereum.
const SOLANA_MAINNET: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const SOLANA_METHODS: &[&str] = &[
    "solana_signMessage",
    "solana_signTransaction",
    "solana_requestAccounts",
    "solana_getAccounts",
    "solana_signAllTransactions",
    "solana_signAndSendTransaction",
];

/// `wc_sessionPropose` params from a current ethereum-provider / AppKit dapp: nothing required,
/// every method and event optional, the chains Kao can't serve listed first, an `rpcMap` inside each
/// namespace (the SDK puts it there), a Solana namespace beside Ethereum, and dapp-defined
/// `sessionProperties`.
pub(crate) fn ethereum_provider_proposal(
    proposer: &PublicKey,
    pairing_topic: &Topic,
    now: u64,
) -> Value {
    let rpc = |chain: &str| {
        format!(
            "https://rpc.walletconnect.org/v1/?chainId={chain}&projectId=0123456789abcdef0123456789abcdef"
        )
    };
    let eip155_rpc: Map<String, Value> = PROPOSAL_CHAINS
        .iter()
        .map(|c| (c.to_string(), json!(rpc(&caip2(*c)))))
        .collect();
    json!({
        "relays": [{ "protocol": "irn" }],
        "proposer": {
            "publicKey": proposer,
            "metadata": {
                "name": "Fixture Dapp",
                "description": "A dapp built on AppKit",
                "url": "https://dapp.example",
                "icons": ["https://dapp.example/icon.png"],
                "redirect": { "universal": "https://dapp.example" }
            }
        },
        "requiredNamespaces": {},
        "optionalNamespaces": {
            "eip155": {
                "chains": PROPOSAL_CHAINS.iter().map(|c| caip2(*c)).collect::<Vec<_>>(),
                "methods": ETHEREUM_PROVIDER_METHODS,
                "events": ETHEREUM_PROVIDER_EVENTS,
                "rpcMap": eip155_rpc
            },
            "solana": {
                "chains": [SOLANA_MAINNET],
                "methods": SOLANA_METHODS,
                "events": [],
                "rpcMap": { "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp": rpc(SOLANA_MAINNET) }
            }
        },
        "sessionProperties": { "caip154-mandatory": "true" },
        "expiryTimestamp": now + SDK_REQUEST_TTL_SECS,
        "pairingTopic": pairing_topic
    })
}

// ── personal_sign ─────────────────────────────────────────────────────────────────────────────────

/// The libraries whose `personal_sign` params differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersonalSignLib {
    /// viem `signMessage`: `[toHex(message), address]`, the address as the wallet reported it.
    Viem,
    /// ethers v5 `JsonRpcSigner.signMessage`: `[hexlify(bytes), address.toLowerCase()]`.
    EthersV5,
    /// ethers v6 `JsonRpcSigner.signMessage`: the same shape as v5.
    EthersV6,
    /// web3.js 1.x `eth.personal.sign(data, address, password)`: three params, the address
    /// lowercased by its input formatter, the password usually `""`.
    Web3JsV1,
    /// web3.js 4.x `eth.personal.sign(data, address, passphrase)`: three params, the address as given.
    Web3JsV4,
    /// Pre-standard dapps and some wallets' examples: `[address, message]`.
    LegacyReversed,
}

/// `personal_sign` params for a UTF-8 `message` signed by `account`, as `lib` sends them.
pub(crate) fn personal_sign(lib: PersonalSignLib, message: &str, account: Address) -> Value {
    let data = format!("0x{}", alloy::hex::encode(message.as_bytes()));
    let checksummed = account.to_checksum(None);
    let lower = format!("{account:#x}");
    match lib {
        PersonalSignLib::Viem => json!([data, checksummed]),
        PersonalSignLib::EthersV5 | PersonalSignLib::EthersV6 => json!([data, lower]),
        PersonalSignLib::Web3JsV1 => json!([data, lower, ""]),
        PersonalSignLib::Web3JsV4 => json!([data, checksummed, ""]),
        PersonalSignLib::LegacyReversed => json!([lower, data]),
    }
}

// ── eth_sendTransaction ───────────────────────────────────────────────────────────────────────────

/// The libraries whose `eth_sendTransaction` objects differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SendTxLib {
    /// viem `sendTransaction` on a JSON-RPC account: checksummed addresses, `numberToHex`
    /// quantities, `chainId` included, no gas unless the caller set one.
    Viem,
    /// ethers v5 `JsonRpcSigner.sendUncheckedTransaction`: estimates `gasLimit` and sends it as
    /// `gas` (`hexlifyTransaction`), addresses lowercased by `hexlify`.
    EthersV5,
    /// ethers v6 `JsonRpcSigner.sendUncheckedTransaction` / `getRpcTransaction`: the same mapping.
    EthersV6,
}

impl SendTxLib {
    pub(crate) const ALL: [Self; 3] = [Self::Viem, Self::EthersV5, Self::EthersV6];
}

/// The gas ethers estimated for the fixture call (it always sends one).
pub(crate) const ETHERS_GAS: u64 = 46_109;

/// One `eth_sendTransaction` param object, as `lib` sends it.
pub(crate) fn send_transaction(
    lib: SendTxLib,
    from: Address,
    to: Address,
    value: U256,
    data: &[u8],
    chain_id: u64,
) -> Value {
    let data = format!("0x{}", alloy::hex::encode(data));
    match lib {
        SendTxLib::Viem => json!([{
            "chainId": format!("{chain_id:#x}"),
            "data": data,
            "from": from.to_checksum(None),
            "to": to.to_checksum(None),
            "value": format!("{value:#x}"),
        }]),
        SendTxLib::EthersV5 | SendTxLib::EthersV6 => json!([{
            "gas": format!("{ETHERS_GAS:#x}"),
            "value": format!("{value:#x}"),
            "from": format!("{from:#x}"),
            "to": format!("{to:#x}"),
            "data": data,
        }]),
    }
}

/// A hand-built transaction (a dapp calling `provider.request` itself) that names its gas limit with
/// ethers' property name `gasLimit` — alone, or beside a `gas` of its own.
pub(crate) fn send_transaction_gas_limit(
    from: Address,
    to: Address,
    data: &[u8],
    gas_limit: u64,
    gas: Option<u64>,
) -> Value {
    let mut tx = json!({
        "from": from.to_checksum(None),
        "to": to.to_checksum(None),
        "data": format!("0x{}", alloy::hex::encode(data)),
        "value": "0x0",
        "gasLimit": format!("{gas_limit:#x}"),
    });
    if let Some(g) = gas {
        tx["gas"] = json!(format!("{g:#x}"));
    }
    json!([tx])
}

// ── Typed data ────────────────────────────────────────────────────────────────────────────────────

pub(crate) const PERMIT2: Address = address!("000000000022D473030F116dDEE9F6B43aC78BA3");
pub(crate) const SEAPORT_1_6: Address = address!("0000000000000068F116a894984e2DB1123eB395");
pub(crate) const UNIVERSAL_ROUTER: Address = address!("3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD");
pub(crate) const USDC: Address = address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");
pub(crate) const BAYC: Address = address!("BC4CA0EdA7647A8aB7C2061c2E118A18a936f13D");
pub(crate) const OPENSEA_FEE: Address = address!("0000a26b00c1F0DF003000390027140000fAa719");
pub(crate) const CREATOR_ROYALTY: Address = address!("A858DDc0445d8131daC4d1DE01f834ffcbA52Ef1");
const OPENSEA_ZONE: Address = address!("000056F7000000EcE9003ca63978907a00FFD100");
const OPENSEA_CONDUIT_KEY: &str =
    "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000";
const ZERO_BYTES32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// One listing's price and fees, in wei.
pub(crate) const LIST_PRICE: u128 = 10_000_000_000_000_000_000;
pub(crate) const OPENSEA_FEE_WEI: u128 = 250_000_000_000_000_000;
pub(crate) const ROYALTY_WEI: u128 = 500_000_000_000_000_000;

/// The EIP-712 specification's "Mail" example on `chain_id`, as a dapp sends it.
pub(crate) fn mail(chain_id: u64) -> Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Person": [{"name": "name", "type": "string"}, {"name": "wallet", "type": "address"}],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail", "version": "1", "chainId": chain_id,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        }
    })
}

/// A Mainnet `SafeTx` on `safe` calling `to` with `data` (0x-hex), nonce 7, as Safe{Wallet} sends
/// it over WalletConnect for an owner to confirm.
pub(crate) fn safe_tx(safe: Address, to: Address, data: &str) -> Value {
    json!({
        "types": {
            "EIP712Domain": [
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "SafeTx": [
                {"name": "to", "type": "address"}, {"name": "value", "type": "uint256"},
                {"name": "data", "type": "bytes"}, {"name": "operation", "type": "uint8"},
                {"name": "safeTxGas", "type": "uint256"}, {"name": "baseGas", "type": "uint256"},
                {"name": "gasPrice", "type": "uint256"}, {"name": "gasToken", "type": "address"},
                {"name": "refundReceiver", "type": "address"}, {"name": "nonce", "type": "uint256"}
            ]
        },
        "primaryType": "SafeTx",
        "domain": {"chainId": 1, "verifyingContract": safe.to_checksum(None)},
        "message": {
            "to": to.to_checksum(None), "value": "0", "data": data, "operation": 0,
            "safeTxGas": "0", "baseGas": "0", "gasPrice": "0",
            "gasToken": "0x0000000000000000000000000000000000000000",
            "refundReceiver": "0x0000000000000000000000000000000000000000", "nonce": "7"
        }
    })
}

/// viem `signTypedData`: `[address, JSON.stringify(typedData)]`.
pub(crate) fn sign_typed_data_viem(account: Address, typed: &Value) -> Value {
    json!([account.to_checksum(None), typed.to_string()])
}

/// ethers v5 `_signTypedData` / v6 `signTypedData`: `[address.toLowerCase(), JSON.stringify(payload)]`.
pub(crate) fn sign_typed_data_ethers(account: Address, typed: &Value) -> Value {
    json!([format!("{account:#x}"), typed.to_string()])
}

/// Uniswap's Permit2 `PermitSingle` approving the Universal Router for an unlimited amount, as the
/// interface signs it through viem: bigints stringified, the uint48s left as JSON numbers.
pub(crate) fn permit2_permit_single(chain_id: u64) -> Value {
    let max_uint160 = (U256::from(1u8) << 160u32) - U256::from(1u8);
    json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" }
            ],
            "PermitSingle": [
                { "name": "details", "type": "PermitDetails" },
                { "name": "spender", "type": "address" },
                { "name": "sigDeadline", "type": "uint256" }
            ],
            "PermitDetails": [
                { "name": "token", "type": "address" },
                { "name": "amount", "type": "uint160" },
                { "name": "expiration", "type": "uint48" },
                { "name": "nonce", "type": "uint48" }
            ]
        },
        "domain": {
            "name": "Permit2",
            "chainId": chain_id,
            "verifyingContract": PERMIT2.to_checksum(None)
        },
        "primaryType": "PermitSingle",
        "message": {
            "details": {
                "token": USDC.to_checksum(None),
                "amount": max_uint160.to_string(),
                "expiration": 1_730_592_000u64,
                "nonce": 0
            },
            "spender": UNIVERSAL_ROUTER.to_checksum(None),
            "sigDeadline": "1728001800"
        }
    })
}

const SEAPORT_ORDER_TYPES: &str = r#"{
    "OrderComponents": [
        { "name": "offerer", "type": "address" },
        { "name": "zone", "type": "address" },
        { "name": "offer", "type": "OfferItem[]" },
        { "name": "consideration", "type": "ConsiderationItem[]" },
        { "name": "orderType", "type": "uint8" },
        { "name": "startTime", "type": "uint256" },
        { "name": "endTime", "type": "uint256" },
        { "name": "zoneHash", "type": "bytes32" },
        { "name": "salt", "type": "uint256" },
        { "name": "conduitKey", "type": "bytes32" },
        { "name": "counter", "type": "uint256" }
    ],
    "OfferItem": [
        { "name": "itemType", "type": "uint8" },
        { "name": "token", "type": "address" },
        { "name": "identifierOrCriteria", "type": "uint256" },
        { "name": "startAmount", "type": "uint256" },
        { "name": "endAmount", "type": "uint256" }
    ],
    "ConsiderationItem": [
        { "name": "itemType", "type": "uint8" },
        { "name": "token", "type": "address" },
        { "name": "identifierOrCriteria", "type": "uint256" },
        { "name": "startAmount", "type": "uint256" },
        { "name": "endAmount", "type": "uint256" },
        { "name": "recipient", "type": "address" }
    ]
}"#;

/// seaport-js's `EIP_712_ORDER_TYPE` plus ethers' derived `EIP712Domain`, and `extra` types.
fn seaport_types(extra: &[(&str, Value)]) -> Value {
    let mut types: Map<String, Value> =
        serde_json::from_str(SEAPORT_ORDER_TYPES).expect("the Seaport types are JSON");
    types.insert(
        "EIP712Domain".into(),
        json!([
            { "name": "name", "type": "string" },
            { "name": "version", "type": "string" },
            { "name": "chainId", "type": "uint256" },
            { "name": "verifyingContract", "type": "address" }
        ]),
    );
    for (name, def) in extra {
        types.insert((*name).to_string(), def.clone());
    }
    Value::Object(types)
}

/// ethers v6 `TypedDataEncoder.getPayload`'s domain: chainId a number, the contract lowercased.
fn seaport_domain(chain_id: u64) -> Value {
    json!({
        "name": "Seaport",
        "version": "1.6",
        "chainId": chain_id,
        "verifyingContract": format!("{SEAPORT_1_6:#x}")
    })
}

/// The `i`-th OpenSea listing of a BAYC token by `offerer`: the token for `LIST_PRICE` ETH, minus
/// OpenSea's fee and, with `royalty`, the creator's. ethers' payload spelling: every uint a decimal
/// string, bytes lowercase hex.
pub(crate) fn seaport_listing(offerer: Address, i: usize, royalty: bool) -> Value {
    let wei = |w: u128| w.to_string();
    let fees = OPENSEA_FEE_WEI + if royalty { ROYALTY_WEI } else { 0 };
    let native = |amount: u128, recipient: Address| {
        json!({
            "itemType": "0",
            "token": format!("{:#x}", Address::ZERO),
            "identifierOrCriteria": "0",
            "startAmount": wei(amount),
            "endAmount": wei(amount),
            "recipient": recipient.to_checksum(None)
        })
    };
    let mut consideration = vec![
        native(LIST_PRICE - fees, offerer),
        native(OPENSEA_FEE_WEI, OPENSEA_FEE),
    ];
    if royalty {
        consideration.push(native(ROYALTY_WEI, CREATOR_ROYALTY));
    }
    let salt = U256::from_str_radix(
        "360c6ebe0000000000000000000000000000000000000000a0e9cd8c4b2f6e0c",
        16,
    )
    .expect("a hex salt")
        + U256::from(i);
    json!({
        "offerer": offerer.to_checksum(None),
        "zone": OPENSEA_ZONE.to_checksum(None),
        "offer": [{
            "itemType": "2",
            "token": BAYC.to_checksum(None),
            "identifierOrCriteria": (1000 + i).to_string(),
            "startAmount": "1",
            "endAmount": "1"
        }],
        "consideration": consideration,
        "orderType": "0",
        "startTime": "1728000000",
        "endTime": "1730592000",
        "zoneHash": ZERO_BYTES32,
        "salt": salt.to_string(),
        "conduitKey": OPENSEA_CONDUIT_KEY,
        "counter": "0"
    })
}

/// seaport-js's default (padding) `OrderComponents`: every field zero or empty.
pub(crate) fn seaport_empty_order() -> Value {
    json!({
        "offerer": format!("{:#x}", Address::ZERO),
        "zone": format!("{:#x}", Address::ZERO),
        "offer": [],
        "consideration": [],
        "orderType": "0",
        "startTime": "0",
        "endTime": "0",
        "zoneHash": ZERO_BYTES32,
        "salt": "0",
        "conduitKey": ZERO_BYTES32,
        "counter": "0"
    })
}

/// A single Seaport 1.6 listing (seaport-js `createOrder` → ethers `signTypedData`).
pub(crate) fn seaport_order(offerer: Address, royalty: bool, chain_id: u64) -> Value {
    json!({
        "types": seaport_types(&[]),
        "domain": seaport_domain(chain_id),
        "primaryType": "OrderComponents",
        "message": seaport_listing(offerer, 0, royalty)
    })
}

/// The height seaport-js gives a bulk order of `n` listings: `max(ceil(log2 n), 1)`.
pub(crate) fn seaport_bulk_height(n: usize) -> usize {
    (usize::BITS - n.max(2).saturating_sub(1).leading_zeros()) as usize
}

/// `n` listings signed at once (seaport-js `createBulkOrders`): a `BulkOrder` whose `tree` is
/// `OrderComponents[2]…[2]` of the bulk height, the leaves past `n` padded with empty orders.
pub(crate) fn seaport_bulk_order(
    offerer: Address,
    n: usize,
    royalty: bool,
    chain_id: u64,
) -> Value {
    let height = seaport_bulk_height(n);
    let mut level: Vec<Value> = (0..1usize << height)
        .map(|i| {
            if i < n {
                seaport_listing(offerer, i, royalty)
            } else {
                seaport_empty_order()
            }
        })
        .collect();
    for _ in 0..height {
        level = level
            .chunks(2)
            .map(|pair| Value::Array(pair.to_vec()))
            .collect();
    }
    let tree = level.into_iter().next().unwrap_or(Value::Null);
    json!({
        "types": seaport_types(&[(
            "BulkOrder",
            json!([{ "name": "tree", "type": format!("OrderComponents{}", "[2]".repeat(height)) }])
        )]),
        "domain": seaport_domain(chain_id),
        "primaryType": "BulkOrder",
        "message": { "tree": tree }
    })
}
