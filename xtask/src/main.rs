#![forbid(unsafe_code)]

mod sync_4byte;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

const TOKENLIST_URL: &str = "https://static.optimism.io/optimism.tokenlist.json";
const CONCURRENCY: usize = 16;

const CHAINS: &[(u64, &str)] = &[(1, "ethereum"), (10, "optimism"), (8453, "base")];

// Tokens whose canonical Optimism-tokenlist `logoURI` is a PNG (and so
// gets dropped by the SVG filter) but which we want to ship a logo for
// anyway. Each entry is (chain_id, lowercase address, SVG url) and lands
// at the same `assets/<chain>/<address>/logo.svg` path the main loop
// uses.
const USDC_LOGO_URL: &str =
    "https://upload.wikimedia.org/wikipedia/commons/4/4a/Circle_USDC_Logo.svg";
const EXCEPTIONS: &[(u64, &str, &str)] = &[
    (
        1,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        USDC_LOGO_URL,
    ),
    (
        10,
        "0x0b2c639c533813f4aa9d7837caf62653d097ff85",
        USDC_LOGO_URL,
    ),
    (
        8453,
        "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        USDC_LOGO_URL,
    ),
];

#[derive(Deserialize, Serialize)]
struct TokenList {
    #[serde(flatten)]
    meta: Map<String, Value>,
    tokens: Vec<Map<String, Value>>,
}

fn chain_dir(chain_id: u64) -> Option<&'static str> {
    CHAINS
        .iter()
        .find(|(id, _)| *id == chain_id)
        .map(|(_, n)| *n)
}

#[tokio::main]
async fn main() -> Result<()> {
    match std::env::args().nth(1).as_deref() {
        Some("sync-tokens") => sync_tokens().await,
        Some("sync-4byte-db") => sync_4byte::sync_4byte_db().await,
        _ => {
            eprintln!("usage: cargo xtask <sync-tokens | sync-4byte-db>");
            std::process::exit(1);
        }
    }
}

async fn sync_tokens() -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("kao-xtask/sync-tokens")
        .build()?;

    println!("fetching {TOKENLIST_URL}");
    let list: TokenList = client
        .get(TOKENLIST_URL)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("loaded {} tokens", list.tokens.len());

    let tokens: Vec<Map<String, Value>> = list
        .tokens
        .into_iter()
        .filter(|t| {
            t.get("chainId")
                .and_then(Value::as_u64)
                .is_some_and(|id| chain_dir(id).is_some())
        })
        .collect();
    println!("filtered to {} tokens (chains 1/10/8453)", tokens.len());

    let assets = workspace_root()?.join("assets");
    let list_path = assets.join("tokenlist.json");
    let out = TokenList {
        meta: list.meta,
        tokens: tokens.clone(),
    };
    let json = serde_json::to_vec_pretty(&out)?;
    tokio::fs::write(&list_path, &json)
        .await
        .with_context(|| format!("write {}", list_path.display()))?;
    println!("wrote {}", list_path.display());

    let mut work: Vec<(u64, String, String)> = tokens
        .into_iter()
        .filter_map(|t| {
            let logo = t.get("logoURI").and_then(Value::as_str)?;
            if !logo.to_ascii_lowercase().ends_with(".svg") {
                return None;
            }
            let chain_id = t.get("chainId").and_then(Value::as_u64).expect("filtered");
            let address = t
                .get("address")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            Some((chain_id, address, logo.to_owned()))
        })
        .collect();
    work.extend(
        EXCEPTIONS
            .iter()
            .map(|(c, a, l)| (*c, (*a).to_owned(), (*l).to_owned())),
    );
    println!(
        "queued {} downloads ({} exceptions)",
        work.len(),
        EXCEPTIONS.len()
    );

    let mut iter = work.into_iter();
    let mut inflight = FuturesUnordered::new();
    let mut ok: u32 = 0;
    let mut err: u32 = 0;

    for _ in 0..CONCURRENCY {
        if let Some((c, a, l)) = iter.next() {
            inflight.push(download_logo(client.clone(), assets.clone(), c, a, l));
        }
    }
    while let Some(res) = inflight.next().await {
        match res {
            Ok(p) => {
                println!("  ok  {}", p.display());
                ok += 1;
            }
            Err(e) => {
                eprintln!("  err {e:#}");
                err += 1;
            }
        }
        if let Some((c, a, l)) = iter.next() {
            inflight.push(download_logo(client.clone(), assets.clone(), c, a, l));
        }
    }
    println!("done: {ok} ok, {err} err");
    Ok(())
}

async fn download_logo(
    client: reqwest::Client,
    assets: PathBuf,
    chain_id: u64,
    address: String,
    logo: String,
) -> Result<PathBuf> {
    let chain = chain_dir(chain_id).ok_or_else(|| anyhow!("unknown chain {chain_id}"))?;
    let dir = assets.join(chain).join(&address);
    let path = dir.join("logo.svg");
    tokio::fs::create_dir_all(&dir).await?;
    let bytes = client
        .get(&logo)
        .send()
        .await
        .map_err(|e| anyhow!("{}: {}", logo, e.without_url()))?
        .error_for_status()
        .map_err(|e| anyhow!("{}: {}", logo, e.without_url()))?
        .bytes()
        .await
        .map_err(|e| anyhow!("{}: {}", logo, e.without_url()))?;
    let simplified = simplify_svg(&bytes).with_context(|| format!("usvg simplify {logo}"))?;
    tokio::fs::write(&path, simplified.as_bytes()).await?;
    Ok(path)
}

fn simplify_svg(data: &[u8]) -> Result<String> {
    let opts = usvg::Options::default();
    let tree = usvg::Tree::from_data(data, &opts)?;
    Ok(tree.to_string(&usvg::WriteOptions::default()))
}

fn workspace_root() -> Result<PathBuf> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?;
    Path::new(&manifest)
        .parent()
        .map(Path::to_path_buf)
        .context("xtask must live one level below the workspace root")
}
