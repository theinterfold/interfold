// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The plugin's proposal list, from its `ProposalCreated` history.
//!
//! The second-heaviest read in both frontends after the delegate directory, and the same shape of
//! waste: the proposal list walks the plugin's logs from its deployment block on every page load,
//! and each proposal page then walks them AGAIN, filtered to one id, to recover the metadata URI.
//! Every client repeats both against logs this server already watches.
//!
//! Cheaper to serve than delegates, too. A directory's voting power changes with every delegation,
//! so it has to be recomputed per block; a proposal's creation event is immutable. The list only
//! ever grows, so it is extended to the head and never rebuilt.

use crate::server::app_data::AppData;
use crate::server::models::JsonResponse;
use crate::server::rate_limit::ChainRateLimiter;

use super::chain::{admit, is_allowed, parse_address, too_many_requests, upstream};
use super::scan::{coverage_for, scan_logs, Target};

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::sol;
use alloy::sol_types::SolEvent;
use log::error;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

pub fn setup_routes(config: &mut web::ServiceConfig) {
    config.service(
        web::scope("/proposals")
            .route("", web::post().to(proposals))
            .route("/votes", web::post().to(votes)),
    );
}

sol! {
    struct Action {
        address to;
        uint256 value;
        bytes data;
    }

    /// Aragon's `ProposalCreated`. `metadata` is the IPFS URI as bytes — the one field the
    /// proposal page cannot get from the contract's `getProposal`, which is why it scans logs at
    /// all.
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed creator,
        uint64 startDate,
        uint64 endDate,
        bytes metadata,
        Action[] actions,
        uint256 allowFailureMap
    );

    /// Emitted by every Aragon plugin family here — TokenVoting, SPP and CrispVoting all use the
    /// same one-argument shape.
    event ProposalExecuted(uint256 indexed proposalId);

    /// CrispVoting only: the fee escrow refund for a round that failed.
    event RefundClaimed(
        uint256 indexed proposalId,
        uint256 indexed e3Id,
        address indexed payer,
        uint256 amount
    );

    /// TokenVoting's ballot. `voteOption` and `votingPower` are unindexed, so unlike the flags
    /// above this one needs its data decoded.
    event VoteCast(
        uint256 indexed proposalId,
        address indexed voter,
        uint8 voteOption,
        uint256 votingPower
    );
}

/// Cost charged to the caller's read window: a cache hit is free, a cold scan is a handful of
/// windows.
const PROPOSALS_READ_COST: usize = 4;

#[derive(Debug, Deserialize)]
pub struct ProposalsRequest {
    /// The plugin whose proposals these are. Required, and must be a contract this server is
    /// configured to serve — this route is about a KNOWN plugin, not a way to scan any address.
    pub plugin: String,
    /// The block the caller needs history from — the plugin's deployment block. As with
    /// `/members/delegates`, the server cannot know it: its own coverage begins wherever it
    /// started indexing.
    #[serde(default)]
    pub from_block: Option<u64>,
    /// Narrow the answer to one proposal, for the per-proposal page. Filtered here rather than by
    /// the caller so the response stays small.
    #[serde(default)]
    pub proposal_id: Option<String>,
    /// Per-proposal flags to resolve as well: `"executed"`, `"refund_claimed"`.
    ///
    /// Opt-in because each is another topic to scan, and a caller that does not render the flag
    /// should not pay for it — on a range the index cannot cover, each one is another walk of the
    /// same window count. Both events carry `proposalId` as their first indexed argument, so
    /// resolving them is a set of topic words with no data to decode.
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Proposal {
    /// Decimal string: a `uint256` proposal id does not survive a JSON number.
    pub proposal_id: String,
    pub creator: String,
    pub start_date: u64,
    pub end_date: u64,
    /// The raw `metadata` bytes, hex-encoded. The client decodes it to the IPFS URI, as it does
    /// with the log today.
    pub metadata: String,
    pub block: u64,
    pub transaction_hash: Option<String>,
    /// `None` when the caller did not ask for the flag, so "not requested" and "not executed"
    /// stay distinguishable — a client that renders `false` for an unasked flag would be showing
    /// a fact nobody established.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_claimed: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProposalsResponse {
    pub plugin: String,
    /// The range actually scanned. `scanned_from` later than the plugin's deployment means
    /// proposals are missing, and nothing else in the response would show it.
    pub scanned_from: u64,
    pub scanned_to: u64,
    /// How far this server's own index reaches. Below `scanned_to` means the rest came from its
    /// upstream provider.
    pub indexed_head: u64,
    pub proposals: Vec<Proposal>,
}

/// Proposals accumulate and never change, so unlike the delegate directory this is extended to
/// the head rather than recomputed per block.
#[derive(Default)]
struct PluginCache {
    scanned: Option<(u64, u64)>,
    proposals: Vec<Proposal>,
}

static CACHE: once_cell::sync::Lazy<RwLock<HashMap<String, PluginCache>>> =
    once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

/// One in-flight scan per plugin, so a cold cache is not a thundering herd. See the same pattern
/// in `members`.
static SCANS: once_cell::sync::Lazy<
    RwLock<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
> = once_cell::sync::Lazy::new(|| RwLock::new(HashMap::new()));

async fn scan_lock(plugin_key: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    if let Some(existing) = SCANS.read().await.get(plugin_key) {
        return existing.clone();
    }
    SCANS
        .write()
        .await
        .entry(plugin_key.to_string())
        .or_default()
        .clone()
}

/// The cached list when it covers `[scan_from, block]`.
async fn cached_proposals(plugin_key: &str, scan_from: u64, block: u64) -> Option<Vec<Proposal>> {
    let cache = CACHE.read().await;
    let entry = cache.get(plugin_key)?;
    let (from, to) = entry.scanned?;
    (from <= scan_from && to >= block).then(|| entry.proposals.clone())
}

async fn proposals(
    http_request: HttpRequest,
    request: web::Json<ProposalsRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    if let Err((caller, cost)) = admit(&http_request, &limiter, PROPOSALS_READ_COST) {
        return too_many_requests(&caller, cost, "/proposals");
    }

    let Some(plugin) = parse_address(&request.plugin) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!("Invalid plugin address: {}", request.plugin),
        });
    };

    // The one bound this route needs. Without it, a `from_block` far enough back turns it into a
    // windowed log scanner for any contract on the chain — the general-purpose primitive these
    // typed routes exist to replace.
    if !is_allowed(&plugin) {
        return HttpResponse::NotFound().json(JsonResponse {
            response: format!("Plugin {plugin} is not served by this indexer"),
        });
    }

    let plugin_key = plugin.to_string().to_lowercase();
    let indexed = coverage_for(&store, &plugin_key).await;
    let indexed_head = indexed.map(|(_, head)| head).unwrap_or(0);

    let Some(scan_from) = request.from_block.or(indexed.map(|(from, _)| from)) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!(
                "from_block is required for {plugin}: this server does not index its logs, so it \
                 has no deployment block to scan from"
            ),
        });
    };

    let provider = match upstream().await {
        Ok(p) => p,
        Err(e) => {
            error!("proposals: provider unavailable: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Upstream RPC unavailable".to_string(),
            });
        }
    };

    let block = match provider.get_block_number().await {
        Ok(number) => number,
        Err(e) => {
            error!("proposals: could not read the head: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Upstream RPC unavailable".to_string(),
            });
        }
    };

    if let Some(hit) = cached_proposals(&plugin_key, scan_from, block).await {
        return flagged_response(
            &request,
            &store,
            provider,
            plugin,
            &plugin_key,
            indexed,
            scan_from,
            block,
            indexed_head,
            hit,
        )
        .await;
    }

    let lock = scan_lock(&plugin_key).await;
    let _scanning = lock.lock().await;

    if let Some(hit) = cached_proposals(&plugin_key, scan_from, block).await {
        return flagged_response(
            &request,
            &store,
            provider,
            plugin,
            &plugin_key,
            indexed,
            scan_from,
            block,
            indexed_head,
            hit,
        )
        .await;
    }

    // Extend what is already held rather than rescanning it: a creation event is immutable, so
    // the only thing that can have changed is that there are more of them.
    let reusable = CACHE.read().await.get(&plugin_key).and_then(|entry| {
        entry
            .scanned
            .filter(|(from, to)| *from <= scan_from && *to <= block)
            .map(|(from, to)| (from, to, entry.proposals.clone()))
    });

    let (known, scan_start, scanned_from) = match reusable {
        Some((from, to, known)) => (known, to + 1, from),
        None => (Vec::new(), scan_from, scan_from),
    };

    let logs = match scan_logs(
        &store,
        provider,
        &Target::any(
            plugin,
            &plugin_key,
            ProposalCreated::SIGNATURE_HASH,
            indexed,
        ),
        scan_start,
        block,
    )
    .await
    {
        Ok(found) => found,
        Err(e) => {
            error!("proposals: scanning ProposalCreated failed: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Failed to read the proposal history".to_string(),
            });
        }
    };

    let mut all = known;
    let mut seen: std::collections::HashSet<String> =
        all.iter().map(|p| p.proposal_id.clone()).collect();

    for log in logs {
        // A log that will not decode is skipped, not fatal: one unreadable event should cost that
        // proposal, not the whole list. It happens for real — an older plugin on the same address
        // with a different event shape would land here.
        let Ok(decoded) = ProposalCreated::decode_raw_log(log.topics.iter().copied(), &log.data)
        else {
            continue;
        };

        let proposal_id = decoded.proposalId.to_string();
        if !seen.insert(proposal_id.clone()) {
            continue;
        }

        all.push(Proposal {
            proposal_id,
            creator: decoded.creator.to_string(),
            start_date: decoded.startDate,
            end_date: decoded.endDate,
            metadata: format!("0x{}", hex::encode(&decoded.metadata)),
            block: log.block_number,
            transaction_hash: log.transaction_hash,
            executed: None,
            refund_claimed: None,
        });
    }

    // Newest first: every consumer renders them that way, and ordering here means the client does
    // not re-sort a list it just parsed.
    all.sort_by(|a, b| b.block.cmp(&a.block));

    // Cached WITHOUT flags: they are per-request (a caller may ask for none) and they change
    // after a proposal is created, so caching them alongside an immutable creation event would
    // make the list stale in a way the block-scoped range no longer describes.
    CACHE.write().await.insert(
        plugin_key.clone(),
        PluginCache {
            scanned: Some((scanned_from, block)),
            proposals: all.clone(),
        },
    );

    let all = match resolve_flags(
        &store,
        provider,
        plugin,
        &plugin_key,
        indexed,
        scanned_from,
        block,
        &request.flags,
        all,
    )
    .await
    {
        Ok(flagged) => flagged,
        Err(e) => {
            error!("proposals: resolving flags failed: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Failed to read proposal status".to_string(),
            });
        }
    };

    respond(&request, plugin, scanned_from, block, indexed_head, all)
}

#[derive(Debug, Deserialize)]
pub struct VotesRequest {
    pub plugin: String,
    /// Required: a vote list is always about one proposal, and scanning every proposal's ballots
    /// to return one proposal's is the waste this route exists to remove.
    pub proposal_id: String,
    #[serde(default)]
    pub from_block: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Vote {
    pub voter: String,
    /// Aragon's `VoteOption`: 0 none, 1 abstain, 2 yes, 3 no.
    pub vote_option: u8,
    pub voting_power: String,
    pub block: u64,
    pub transaction_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VotesResponse {
    pub plugin: String,
    pub proposal_id: String,
    pub scanned_from: u64,
    pub scanned_to: u64,
    pub indexed_head: u64,
    pub votes: Vec<Vote>,
}

/// Every ballot cast on one proposal.
///
/// Not cached: unlike a proposal list this is filtered to one id, so the scan is already narrow —
/// `proposalId` is the event's first indexed argument, pushed down to the node or the bucket read
/// rather than filtered after. The list also changes with every vote, so a cache would be stale
/// as often as it was useful.
async fn votes(
    http_request: HttpRequest,
    request: web::Json<VotesRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    if let Err((caller, cost)) = admit(&http_request, &limiter, PROPOSALS_READ_COST) {
        return too_many_requests(&caller, cost, "/proposals/votes");
    }

    let Some(plugin) = parse_address(&request.plugin) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!("Invalid plugin address: {}", request.plugin),
        });
    };

    if !is_allowed(&plugin) {
        return HttpResponse::NotFound().json(JsonResponse {
            response: format!("Plugin {plugin} is not served by this indexer"),
        });
    }

    let Ok(proposal_id) = U256::from_str_radix(request.proposal_id.trim(), 10) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!("Invalid proposal id: {}", request.proposal_id),
        });
    };

    let plugin_key = plugin.to_string().to_lowercase();
    let indexed = coverage_for(&store, &plugin_key).await;
    let indexed_head = indexed.map(|(_, head)| head).unwrap_or(0);

    let Some(scan_from) = request.from_block.or(indexed.map(|(from, _)| from)) else {
        return HttpResponse::BadRequest().json(JsonResponse {
            response: format!("from_block is required for {plugin}: its logs are not indexed here"),
        });
    };

    let provider = match upstream().await {
        Ok(p) => p,
        Err(e) => {
            error!("proposals/votes: provider unavailable: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Upstream RPC unavailable".to_string(),
            });
        }
    };

    let block = match provider.get_block_number().await {
        Ok(number) => number,
        Err(e) => {
            error!("proposals/votes: could not read the head: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Upstream RPC unavailable".to_string(),
            });
        }
    };

    let target = Target {
        address: plugin,
        key: &plugin_key,
        topic0: VoteCast::SIGNATURE_HASH,
        topics: [Some(proposal_id.into()), None, None],
        indexed,
    };

    let logs = match scan_logs(&store, provider, &target, scan_from, block).await {
        Ok(found) => found,
        Err(e) => {
            error!("proposals/votes: scanning VoteCast failed: {e}");
            return HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Failed to read the vote history".to_string(),
            });
        }
    };

    let mut votes = Vec::with_capacity(logs.len());
    for log in logs {
        let Ok(decoded) = VoteCast::decode_raw_log(log.topics.iter().copied(), &log.data) else {
            continue;
        };
        votes.push(Vote {
            voter: decoded.voter.to_string(),
            vote_option: decoded.voteOption,
            voting_power: decoded.votingPower.to_string(),
            block: log.block_number,
            transaction_hash: log.transaction_hash,
        });
    }

    HttpResponse::Ok().json(VotesResponse {
        plugin: plugin.to_string(),
        proposal_id: request.proposal_id.clone(),
        scanned_from: scan_from,
        scanned_to: block,
        indexed_head,
        votes,
    })
}

/// The set of proposal ids named by an event whose first indexed argument is `proposalId`.
///
/// `ProposalExecuted` and `RefundClaimed` are both read this way: the id is a topic word, so the
/// answer is a set of 32-byte values with no ABI decoding at all.
async fn proposals_named_by(
    store: &web::Data<AppData>,
    provider: &alloy::providers::DynProvider,
    target: &Target<'_>,
    from: u64,
    to: u64,
) -> eyre::Result<std::collections::HashSet<String>> {
    let logs = scan_logs(store, provider, target, from, to).await?;

    Ok(logs
        .into_iter()
        .filter_map(|log| {
            log.topics
                .get(1)
                .map(|id| U256::from_be_bytes(id.0).to_string())
        })
        .collect())
}

/// Fill in whichever of `executed` / `refund_claimed` the caller asked for.
///
/// An unrecognised flag name is ignored rather than refused: a newer client asking for a flag this
/// server does not know should get the rest of the answer, not a 400.
#[allow(clippy::too_many_arguments)]
async fn resolve_flags(
    store: &web::Data<AppData>,
    provider: &alloy::providers::DynProvider,
    plugin: Address,
    plugin_key: &str,
    indexed: super::scan::Coverage,
    from: u64,
    to: u64,
    flags: &[String],
    mut proposals: Vec<Proposal>,
) -> eyre::Result<Vec<Proposal>> {
    if flags.iter().any(|flag| flag == "executed") {
        let executed = proposals_named_by(
            store,
            provider,
            &Target::any(
                plugin,
                plugin_key,
                ProposalExecuted::SIGNATURE_HASH,
                indexed,
            ),
            from,
            to,
        )
        .await?;
        for proposal in &mut proposals {
            proposal.executed = Some(executed.contains(&proposal.proposal_id));
        }
    }

    if flags.iter().any(|flag| flag == "refund_claimed") {
        let claimed = proposals_named_by(
            store,
            provider,
            &Target::any(plugin, plugin_key, RefundClaimed::SIGNATURE_HASH, indexed),
            from,
            to,
        )
        .await?;
        for proposal in &mut proposals {
            proposal.refund_claimed = Some(claimed.contains(&proposal.proposal_id));
        }
    }

    Ok(proposals)
}

/// `respond`, with the requested flags resolved first. Used on the cache-hit paths, where the
/// list is already known but the flags are not cached with it.
#[allow(clippy::too_many_arguments)]
async fn flagged_response(
    request: &ProposalsRequest,
    store: &web::Data<AppData>,
    provider: &alloy::providers::DynProvider,
    plugin: Address,
    plugin_key: &str,
    indexed: super::scan::Coverage,
    scanned_from: u64,
    scanned_to: u64,
    indexed_head: u64,
    proposals: Vec<Proposal>,
) -> HttpResponse {
    match resolve_flags(
        store,
        provider,
        plugin,
        plugin_key,
        indexed,
        scanned_from,
        scanned_to,
        &request.flags,
        proposals,
    )
    .await
    {
        Ok(flagged) => respond(
            request,
            plugin,
            scanned_from,
            scanned_to,
            indexed_head,
            flagged,
        ),
        Err(e) => {
            error!("proposals: resolving flags failed: {e}");
            HttpResponse::ServiceUnavailable().json(JsonResponse {
                response: "Failed to read proposal status".to_string(),
            })
        }
    }
}

fn respond(
    request: &ProposalsRequest,
    plugin: Address,
    scanned_from: u64,
    scanned_to: u64,
    indexed_head: u64,
    proposals: Vec<Proposal>,
) -> HttpResponse {
    let proposals = match &request.proposal_id {
        Some(wanted) => proposals
            .into_iter()
            .filter(|proposal| &proposal.proposal_id == wanted)
            .collect(),
        None => proposals,
    };

    HttpResponse::Ok().json(ProposalsResponse {
        plugin: plugin.to_string(),
        scanned_from,
        scanned_to,
        indexed_head,
        proposals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_proposal_created_signature_matches_the_event_both_frontends_filter_on() {
        // keccak256 of the Aragon signature both clients pass to `getLogs`, cross-checked
        // against viem's `toEventSelector` for the same signature. If this drifts, the route
        // returns an empty list rather than failing — silence is the whole reason to pin it.
        assert_eq!(
            format!("{:#x}", ProposalCreated::SIGNATURE_HASH),
            "0xa6c1f8f4276dc3f243459e13b557c84e8f4e90b2e09070bad5f6909cee687c92"
        );
    }

    #[test]
    fn the_flag_and_vote_signatures_match_what_the_clients_filter_on() {
        // Cross-checked against viem's `toEventSelector` for the same signatures. A drift here
        // returns an empty list rather than an error, so it has to be pinned.
        assert_eq!(
            format!("{:#x}", VoteCast::SIGNATURE_HASH),
            "0xb83d25c6a5d258561330739951487acb4bd09ba5190b5d32c4f261817d906792"
        );
        // `ProposalExecuted(uint256)` and `RefundClaimed(uint256,uint256,address,uint256)`.
        assert_eq!(
            format!("{:#x}", ProposalExecuted::SIGNATURE_HASH),
            "0x712ae1383f79ac853f8d882153778e0260ef8f03b504e2866e0593e04d2b291f"
        );
        assert_eq!(
            format!("{:#x}", RefundClaimed::SIGNATURE_HASH),
            "0x2d86d2232710487ba4907f1e98cab42d8b08ab0342b39cbf17f42804d234f139"
        );
    }
}
