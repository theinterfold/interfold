// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The plugin's proposal list, from its `ProposalCreated` history.
//!
//! The proposal list walks the plugin's logs from its deployment block on every page load, and
//! each proposal page walks them again, filtered to one id, to recover the metadata URI. Every
//! client repeats both against logs this server already watches.
//!
//! A creation event is immutable, so unlike the delegate directory the list is extended to the
//! head and never rebuilt.

use crate::server::app_data::AppData;
use crate::server::rate_limit::ChainRateLimiter;

use super::chain::charge;
use super::json_message;
use super::scan::{
    scan_logs, served_address, unavailable, ScanCache, ScanCtx, Target, NOT_INDEXED, NO_BACKFILL,
};

use actix_web::http::StatusCode;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use alloy::primitives::{B256, U256};
use alloy::sol;
use alloy::sol_types::SolEvent;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::HashSet;
use std::sync::LazyLock;

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

    /// Aragon's `ProposalCreated`. `metadata` is the IPFS URI as bytes, the one field the proposal
    /// page cannot get from the contract's `getProposal`.
    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed creator,
        uint64 startDate,
        uint64 endDate,
        bytes metadata,
        Action[] actions,
        uint256 allowFailureMap
    );

    /// Emitted by every Aragon plugin family here (TokenVoting, SPP, CrispVoting) with the same
    /// one-argument shape.
    event ProposalExecuted(uint256 indexed proposalId);

    /// CrispVoting only: the fee escrow refund for a round that failed.
    event RefundClaimed(
        uint256 indexed proposalId,
        uint256 indexed e3Id,
        address indexed payer,
        uint256 amount
    );

    /// TokenVoting's ballot. `voteOption` and `votingPower` are unindexed, so this one needs its
    /// data decoded.
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

#[derive(Deserialize)]
struct ProposalsRequest {
    /// The plugin whose proposals these are. Must be a contract this server serves: this route is
    /// about a KNOWN plugin, not a way to scan any address.
    plugin: String,
    /// The plugin's deployment block. The server cannot know it: its own coverage begins wherever
    /// it started indexing.
    #[serde(default)]
    from_block: Option<u64>,
    /// Narrow the answer to one proposal, so the response stays small.
    #[serde(default)]
    proposal_id: Option<String>,
    /// Per-proposal flags to resolve as well: `"executed"`, `"refund_claimed"`. Opt-in because
    /// each is another topic to scan, and on a range the index cannot cover another walk of the
    /// same windows. An unrecognised flag is ignored, so a newer client still gets the rest.
    #[serde(default)]
    flags: Vec<String>,
}

#[derive(Clone, Serialize)]
struct Proposal {
    /// Decimal string: a `uint256` does not survive a JSON number.
    proposal_id: String,
    creator: String,
    start_date: u64,
    end_date: u64,
    /// The raw `metadata` bytes, hex-encoded; the client decodes the IPFS URI.
    metadata: String,
    block: u64,
    transaction_hash: Option<String>,
    /// `None` when the caller did not ask for the flag, so "not requested" and "not executed" stay
    /// distinguishable.
    #[serde(skip_serializing_if = "Option::is_none")]
    executed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refund_claimed: Option<bool>,
}

#[derive(Serialize)]
struct ProposalsResponse {
    plugin: String,
    /// The range actually scanned. A `scanned_from` later than the plugin's deployment means
    /// proposals are missing, and nothing else in the response shows it.
    scanned_from: u64,
    scanned_to: u64,
    /// How far this server's own index reaches. Below `scanned_to` means the rest came upstream.
    indexed_head: u64,
    proposals: Vec<Proposal>,
}

#[derive(Default)]
struct PluginCache {
    scanned: Option<(u64, u64)>,
    proposals: Vec<Proposal>,
}

/// Cached WITHOUT flags: they are per-request, and they change after a proposal is created, so
/// caching them beside an immutable creation event would make the list stale in a way the
/// block-scoped range no longer describes.
static CACHE: LazyLock<ScanCache<PluginCache>> = LazyLock::new(ScanCache::new);

/// The cached list and the block it was scanned from, when it covers `[scan_from, block]`. The
/// list can hold proposals older than `scan_from`, so flags must be resolved from its own start.
fn cached_proposals(key: &str, scan_from: u64, block: u64) -> Option<(u64, Vec<Proposal>)> {
    CACHE.peek(key, |entry| {
        let (from, to) = entry.scanned?;
        (from <= scan_from && to >= block).then(|| (from, entry.proposals.clone()))
    })
}

async fn proposals(
    http_request: HttpRequest,
    request: web::Json<ProposalsRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    list(&http_request, &request, &store, &limiter)
        .await
        .unwrap_or_else(|refusal| refusal)
}

async fn list(
    http_request: &HttpRequest,
    request: &ProposalsRequest,
    store: &web::Data<AppData>,
    limiter: &ChainRateLimiter,
) -> Result<HttpResponse, HttpResponse> {
    charge(http_request, limiter, PROPOSALS_READ_COST, "/proposals")?;

    let plugin = served_address(&request.plugin, "plugin", "Plugin")?;
    let ctx = ScanCtx::open(
        store,
        "/proposals",
        plugin,
        plugin,
        request.from_block,
        NO_BACKFILL,
    )
    .await?;

    let (scanned_from, mut proposals) = proposal_list(store, &ctx).await?;

    resolve_flags(store, &ctx, scanned_from, &request.flags, &mut proposals)
        .await
        .map_err(|e| {
            unavailable(
                "proposals: resolving flags failed",
                e,
                "Failed to read proposal status",
            )
        })?;

    if let Some(wanted) = &request.proposal_id {
        proposals.retain(|proposal| &proposal.proposal_id == wanted);
    }

    Ok(HttpResponse::Ok().json(ProposalsResponse {
        plugin: plugin.to_string(),
        scanned_from,
        scanned_to: ctx.block,
        indexed_head: ctx.indexed_head,
        proposals,
    }))
}

/// Every proposal created up to the head, newest first, and the block the list was scanned from.
/// Extends the cached list when it starts early enough; otherwise scans.
async fn proposal_list(
    store: &web::Data<AppData>,
    ctx: &ScanCtx,
) -> Result<(u64, Vec<Proposal>), HttpResponse> {
    if let Some(hit) = cached_proposals(&ctx.key, ctx.scan_from, ctx.block) {
        return Ok(hit);
    }

    // Whoever waited here almost certainly no longer needs to scan, so check again.
    let _scanning = CACHE.exclusive(&ctx.key).await;

    if let Some(hit) = cached_proposals(&ctx.key, ctx.scan_from, ctx.block) {
        return Ok(hit);
    }

    let reusable = CACHE.peek(&ctx.key, |entry| {
        entry
            .scanned
            .filter(|(from, to)| *from <= ctx.scan_from && *to <= ctx.block)
            .map(|(from, to)| (from, to, entry.proposals.clone()))
    });
    let (mut all, scanned_from, scan_start) = match reusable {
        Some((from, to, known)) => (known, from, to.saturating_add(1)),
        None => (Vec::new(), ctx.scan_from, ctx.scan_from),
    };

    let logs = scan_logs(
        store,
        ctx.provider,
        &ctx.target(ProposalCreated::SIGNATURE_HASH),
        scan_start,
        ctx.block,
    )
    .await
    .map_err(|e| {
        unavailable(
            "proposals: scanning ProposalCreated failed",
            e,
            "Failed to read the proposal history",
        )
    })?;

    let mut seen: HashSet<String> = all.iter().map(|p| p.proposal_id.clone()).collect();

    for log in logs {
        // A log that will not decode is skipped, not fatal: an older plugin on the same address
        // with a different event shape costs that proposal, not the list.
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

    // Newest first, as every consumer renders them.
    all.sort_by_key(|proposal| Reverse(proposal.block));

    CACHE.insert(
        ctx.key.clone(),
        PluginCache {
            scanned: Some((scanned_from, ctx.block)),
            proposals: all.clone(),
        },
    );

    Ok((scanned_from, all))
}

#[derive(Deserialize)]
struct VotesRequest {
    plugin: String,
    /// Required: a vote list is always about one proposal, and scanning every proposal's ballots
    /// to return one proposal's is the waste this route exists to remove.
    proposal_id: String,
    #[serde(default)]
    from_block: Option<u64>,
}

#[derive(Serialize)]
struct Vote {
    voter: String,
    /// Aragon's `VoteOption`: 0 none, 1 abstain, 2 yes, 3 no.
    vote_option: u8,
    voting_power: String,
    block: u64,
    transaction_hash: Option<String>,
}

#[derive(Serialize)]
struct VotesResponse {
    plugin: String,
    proposal_id: String,
    scanned_from: u64,
    scanned_to: u64,
    indexed_head: u64,
    votes: Vec<Vote>,
}

/// Every ballot cast on one proposal.
///
/// Not cached: `proposalId` is the event's first indexed argument, pushed down to the node or the
/// bucket read, so the scan is already narrow, and the list changes with every vote.
async fn votes(
    http_request: HttpRequest,
    request: web::Json<VotesRequest>,
    store: web::Data<AppData>,
    limiter: web::Data<ChainRateLimiter>,
) -> impl Responder {
    ballots(&http_request, &request, &store, &limiter)
        .await
        .unwrap_or_else(|refusal| refusal)
}

async fn ballots(
    http_request: &HttpRequest,
    request: &VotesRequest,
    store: &web::Data<AppData>,
    limiter: &ChainRateLimiter,
) -> Result<HttpResponse, HttpResponse> {
    charge(
        http_request,
        limiter,
        PROPOSALS_READ_COST,
        "/proposals/votes",
    )?;

    let plugin = served_address(&request.plugin, "plugin", "Plugin")?;

    let proposal_id = U256::from_str_radix(request.proposal_id.trim(), 10).map_err(|_| {
        json_message(
            StatusCode::BAD_REQUEST,
            format!("Invalid proposal id: {}", request.proposal_id),
        )
    })?;

    let ctx = ScanCtx::open(
        store,
        "/proposals/votes",
        plugin,
        plugin,
        request.from_block,
        NOT_INDEXED,
    )
    .await?;

    let target = Target {
        topics: [Some(proposal_id.into()), None, None],
        ..ctx.target(VoteCast::SIGNATURE_HASH)
    };
    let logs = scan_logs(store, ctx.provider, &target, ctx.scan_from, ctx.block)
        .await
        .map_err(|e| {
            unavailable(
                "proposals/votes: scanning VoteCast failed",
                e,
                "Failed to read the vote history",
            )
        })?;

    let votes = logs
        .into_iter()
        .filter_map(|log| {
            let decoded = VoteCast::decode_raw_log(log.topics.iter().copied(), &log.data).ok()?;
            Some(Vote {
                voter: decoded.voter.to_string(),
                vote_option: decoded.voteOption,
                voting_power: decoded.votingPower.to_string(),
                block: log.block_number,
                transaction_hash: log.transaction_hash,
            })
        })
        .collect();

    Ok(HttpResponse::Ok().json(VotesResponse {
        plugin: plugin.to_string(),
        proposal_id: request.proposal_id.clone(),
        scanned_from: ctx.scan_from,
        scanned_to: ctx.block,
        indexed_head: ctx.indexed_head,
        votes,
    }))
}

/// The set of proposal ids named by an event whose first indexed argument is `proposalId`. The id
/// is a topic word, so the answer needs no ABI decoding.
async fn proposals_named_by(
    store: &web::Data<AppData>,
    ctx: &ScanCtx,
    topic0: B256,
    from: u64,
) -> eyre::Result<HashSet<String>> {
    let logs = scan_logs(store, ctx.provider, &ctx.target(topic0), from, ctx.block).await?;

    Ok(logs
        .iter()
        .filter_map(|log| log.topics.get(1))
        .map(|id| U256::from_be_bytes(id.0).to_string())
        .collect())
}

/// Fill in whichever of `executed` / `refund_claimed` the caller asked for.
async fn resolve_flags(
    store: &web::Data<AppData>,
    ctx: &ScanCtx,
    from: u64,
    flags: &[String],
    proposals: &mut [Proposal],
) -> eyre::Result<()> {
    type Set = fn(&mut Proposal, bool);
    let flag_events: [(&str, B256, Set); 2] = [
        (
            "executed",
            ProposalExecuted::SIGNATURE_HASH,
            |proposal, value| proposal.executed = Some(value),
        ),
        (
            "refund_claimed",
            RefundClaimed::SIGNATURE_HASH,
            |proposal, value| proposal.refund_claimed = Some(value),
        ),
    ];

    for (name, topic0, set) in flag_events {
        if !flags.iter().any(|flag| flag == name) {
            continue;
        }
        let named = proposals_named_by(store, ctx, topic0, from).await?;
        for proposal in proposals.iter_mut() {
            set(proposal, named.contains(&proposal.proposal_id));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_event_signatures_match_what_both_frontends_filter_on() {
        // Cross-checked against viem's `toEventSelector`. A drifted `sol!` declaration returns an
        // empty list rather than an error, so the selectors have to be pinned.
        for (actual, expected) in [
            (
                ProposalCreated::SIGNATURE_HASH,
                "0xa6c1f8f4276dc3f243459e13b557c84e8f4e90b2e09070bad5f6909cee687c92",
            ),
            (
                VoteCast::SIGNATURE_HASH,
                "0xb83d25c6a5d258561330739951487acb4bd09ba5190b5d32c4f261817d906792",
            ),
            (
                ProposalExecuted::SIGNATURE_HASH,
                "0x712ae1383f79ac853f8d882153778e0260ef8f03b504e2866e0593e04d2b291f",
            ),
            (
                RefundClaimed::SIGNATURE_HASH,
                "0x2d86d2232710487ba4907f1e98cab42d8b08ab0342b39cbf17f42804d234f139",
            ),
        ] {
            assert_eq!(format!("{actual:#x}"), expected);
        }
    }
}
