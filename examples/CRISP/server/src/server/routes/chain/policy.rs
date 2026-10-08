// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What the chain routes will serve: the address allowlist, the address scope of a JSON-RPC call
//! (including Multicall3 unwrapping), the `eth_call` cache key, and the shape bounds for methods
//! that name no address.

use crate::config::CONFIG;

use alloy::primitives::{address, Address, Bytes};
use alloy::sol;
use alloy::sol_types::SolCall;
use serde_json::Value;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::LazyLock;

/// A hex quantity. The `0x` prefix is optional, and `trim_start_matches` strips a repeated one
/// too (`0x0x1f`). Callers that require the prefix call `strip_prefix("0x")` first, which accepts
/// the same strings as `starts_with("0x")` followed by this.
pub(super) fn hex_u64(value: &str) -> Option<u64> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

/// The cache key for an `eth_call`, or `None` when the shape is not one we can key on.
///
/// A call carrying `from`, `value` or a gas field is not keyed: those can change the result, and
/// a key that ignores them would serve one caller's answer to another. A call with a state
/// override never reaches here: `requested_addresses` refuses it.
pub(super) fn call_cache_key(params: &Value) -> Option<(String, String, Option<u64>)> {
    let tx = params.get(0)?.as_object()?;

    // An allowlist of the fields the key accounts for: any field this endpoint does not
    // understand may change the result.
    if tx
        .keys()
        .any(|field| !matches!(field.as_str(), "to" | "data" | "input"))
    {
        return None;
    }

    let address = tx.get("to")?.as_str()?.to_string();
    let data = tx
        .get("data")
        .or_else(|| tx.get("input"))?
        .as_str()?
        .to_string();

    let block = match params.get(1) {
        // Absent or null is `latest` by JSON-RPC default.
        None | Some(Value::Null) => None,
        Some(Value::String(tag)) if tag == "latest" => None,
        // Only a concrete height is keyed; `pending`, `safe` and `finalized` are left uncached.
        Some(Value::String(tag)) => Some(tag.strip_prefix("0x").and_then(hex_u64)?),
        // The EIP-1898 object form (`{"blockNumber":…}` / `{"blockHash":…}`) names an arbitrary
        // historical block. Keying it as `latest` would let a caller choose what every other
        // caller sees, so it is not keyed at all.
        Some(_) => return None,
    };

    Some((address, data, block))
}

/// Multicall3, at the same address on every chain it is deployed to.
///
/// It has to be allowlisted for the frontends to work (viem coalesces `eth_call`s into one
/// `aggregate3`), but it is the one allowlisted address whose `to` says nothing about what is read:
/// `aggregate3([{target, callData}])` reaches ANY contract behind a `to` the check waves through.
/// So a call to Multicall3 is decoded and its inner `target`s are checked instead.
pub const MULTICALL3: Address = address!("0xcA11bde05977b3631167028862bE2a173976CA11");

/// How many levels of Multicall3-inside-Multicall3 to unwrap before refusing. Nothing either
/// frontend sends nests at all; the cap bounds caller-chosen decode work.
const MAX_MULTICALL_DEPTH: usize = 2;

sol! {
    struct Multicall3Call {
        address target;
        bytes callData;
    }

    struct Multicall3Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct Multicall3Call3Value {
        address target;
        bool allowFailure;
        uint256 value;
        bytes callData;
    }

    struct Multicall3Result {
        bool success;
        bytes returnData;
    }

    function aggregate(Multicall3Call[] calls) returns (uint256 blockNumber, bytes[] returnData);
    function tryAggregate(bool requireSuccess, Multicall3Call[] calls) returns (bytes[] returnData);
    function blockAndAggregate(Multicall3Call[] calls)
        returns (uint256 blockNumber, bytes32 blockHash, bytes[] returnData);
    function tryBlockAndAggregate(bool requireSuccess, Multicall3Call[] calls)
        returns (uint256 blockNumber, bytes32 blockHash, bytes[] returnData);
    function aggregate3(Multicall3Call3[] calls) returns (Multicall3Result[] returnData);
    function aggregate3Value(Multicall3Call3Value[] calls) returns (Multicall3Result[] returnData);
}

/// `getEthBalance(address)`: a Multicall3 self-view over public state with no inner call, allowed
/// as-is like `eth_getBalance`.
const MULTICALL3_GET_ETH_BALANCE: [u8; 4] = [0x4d, 0x23, 0x01, 0xcc];

type InnerCalls = Option<Vec<(Address, Bytes)>>;
type CallListDecoder = ([u8; 4], &'static str, fn(&[u8]) -> InnerCalls);

/// Decoders for the Multicall3 functions that carry a call list: selector, refusal text, decode.
macro_rules! call_list_decoder {
    ($name:literal, $call:ident) => {
        (
            $call::SELECTOR,
            concat!("could not decode this Multicall3 ", $name, " payload"),
            (|calldata: &[u8]| -> InnerCalls {
                let decoded = $call::abi_decode(calldata).ok()?;
                Some(
                    decoded
                        .calls
                        .into_iter()
                        .map(|call| (call.target, call.callData))
                        .collect(),
                )
            }) as fn(&[u8]) -> InnerCalls,
        )
    };
}

static CALL_LIST_DECODERS: [CallListDecoder; 6] = [
    call_list_decoder!("aggregate3", aggregate3Call),
    call_list_decoder!("aggregate3Value", aggregate3ValueCall),
    call_list_decoder!("aggregate", aggregateCall),
    call_list_decoder!("blockAndAggregate", blockAndAggregateCall),
    call_list_decoder!("tryAggregate", tryAggregateCall),
    call_list_decoder!("tryBlockAndAggregate", tryBlockAndAggregateCall),
];

/// Every contract a call to Multicall3 would actually reach.
///
/// Fails closed: an unrecognised selector is refused rather than forwarded, because "we could not
/// tell what this reaches" and "this reaches nothing" are not the same answer.
fn multicall3_targets(calldata: &[u8], depth: usize) -> Result<Vec<Address>, &'static str> {
    if depth > MAX_MULTICALL_DEPTH {
        return Err("multicall nesting is too deep");
    }

    let Some(selector) = calldata
        .get(..4)
        .and_then(|head| <[u8; 4]>::try_from(head).ok())
    else {
        return Err("a call to Multicall3 must carry a function selector");
    };

    if selector == MULTICALL3_GET_ETH_BALANCE {
        return Ok(Vec::new());
    }

    let Some((_, refusal, decode)) = CALL_LIST_DECODERS
        .iter()
        .find(|(known, ..)| *known == selector)
    else {
        return Err("this Multicall3 function is not served by this indexer");
    };
    let inner = decode(calldata).ok_or(*refusal)?;

    let mut targets = Vec::with_capacity(inner.len());
    for (target, call_data) in inner {
        // A target of Multicall3 itself would pass the allowlist while hiding another call list
        // behind it.
        if target == MULTICALL3 {
            targets.extend(multicall3_targets(&call_data, depth + 1)?);
        } else {
            targets.push(target);
        }
    }

    Ok(targets)
}

/// The scope of an `eth_call`/`eth_estimateGas` whose `to` is Multicall3.
fn multicall3_scope(call: &Value) -> Scope {
    // viem sends `data`; some clients send `input`.
    let Some(hex) = call
        .get("data")
        .or_else(|| call.get("input"))
        .and_then(Value::as_str)
    else {
        return Scope::Unscoped("a call to Multicall3 must carry call data");
    };

    let Ok(calldata) = hex::decode(hex.trim().trim_start_matches("0x")) else {
        return Scope::Unscoped("call data must be hex");
    };

    match multicall3_targets(&calldata, 0) {
        Ok(targets) => Scope::Addresses(targets.iter().map(|target| target.to_string()).collect()),
        Err(reason) => Scope::Unscoped(reason),
    }
}

/// Which addresses a call is scoped to, so they can be checked against the allowlist.
///
/// A method that carries NO address by construction is a different case from one whose address
/// this function failed to find: the first is a global read the allowlist cannot bound, the second
/// is an unrecognised shape. Treating both as "nothing to check" is what makes an allowlist
/// decorative.
pub(super) enum Scope {
    /// Check every one of these against the allowlist before forwarding.
    Addresses(Vec<String>),
    /// The method takes no address; nothing to check by address.
    Global,
    /// The method should be address-scoped but this request is not. Refuse.
    Unscoped(&'static str),
}

/// Pull the address (or addresses) a request is scoped to out of its parameter list. Any shape
/// this does not recognise is a refusal, not a pass.
pub(super) fn requested_addresses(method: &str, params: &Value) -> Scope {
    // `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode` and `eth_getStorageAt` are NOT
    // allowlist-checked. They take an ACCOUNT, normally the caller's own EOA, which can never be
    // on a list of watched contracts; wallets need the sender's nonce and balance before signing
    // and connectors call `getCode` on the signer. They are O(1) point reads of public state, and
    // the read window in `admit` bounds how many one caller may ask for. The allowlist guards
    // `eth_call` (arbitrary EVM) and `eth_getLogs` (range scans that fan out upstream).
    let field = match method {
        // No `to` is a contract-creation simulation that runs caller-supplied initcode: a read of
        // any contract by another name.
        "eth_call" | "eth_estimateGas" => "to",
        // An absent, null or empty `address` means "every address" to a node.
        "eth_getLogs" => "address",
        _ => return Scope::Global,
    };

    let Some(first) = params.get(0) else {
        return Scope::Unscoped("this method requires a filter or call object");
    };

    // A state override can replace the code at an allowlisted `to`, which makes the call
    // arbitrary EVM again.
    if field == "to" && params.get(2).is_some_and(|v| !v.is_null()) {
        return Scope::Unscoped("state overrides are not served by this indexer");
    }

    // Only a call's `to`: an `eth_getLogs` naming Multicall3 asks for that contract's own logs.
    if field == "to"
        && first
            .get("to")
            .and_then(Value::as_str)
            .and_then(parse_address)
            == Some(MULTICALL3)
    {
        return multicall3_scope(first);
    }

    match first.get(field) {
        Some(Value::String(one)) => Scope::Addresses(vec![one.clone()]),
        Some(Value::Array(many)) if !many.is_empty() => {
            let mut addresses = Vec::with_capacity(many.len());
            for entry in many {
                match entry.as_str() {
                    Some(one) => addresses.push(one.to_string()),
                    None => return Scope::Unscoped("addresses must be strings"),
                }
            }
            Scope::Addresses(addresses)
        }
        _ => Scope::Unscoped("this method requires an explicit address"),
    }
}

/// Cap on `eth_feeHistory`'s block count, which is otherwise a caller-chosen fan-out.
const MAX_FEE_HISTORY_BLOCKS: u64 = 128;

/// Reject the shapes of an address-less method that would return an unbounded response.
///
/// Only a method whose size the CALLER chooses is worth bounding. A block with full transaction
/// bodies is served: viem's `waitForTransactionReceipt` requests one to detect a replaced
/// transaction, and a single block is one large response, not a fan-out.
pub(super) fn global_request_is_too_broad(method: &str, params: &Value) -> Option<&'static str> {
    match method {
        "eth_feeHistory" => {
            let count = params.get(0).and_then(|v| match v {
                Value::String(hex) => hex_u64(hex),
                Value::Number(n) => n.as_u64(),
                _ => None,
            })?;
            (count > MAX_FEE_HISTORY_BLOCKS).then_some("feeHistory block count is too large")
        }
        _ => None,
    }
}

/// Addresses these routes will serve: `INDEX_CONTRACTS` plus the contracts this server is itself
/// configured against.
///
/// The server's own contracts are implicit because refusing them is never the intended
/// configuration: the SDK's `getOnChainRoundData` reads the E3 program this server serves. An
/// empty list denies everything, so a misconfigured deployment fails closed.
static ALLOWED: LazyLock<HashSet<Address>> = LazyLock::new(|| {
    let configured = [
        CONFIG.e3_program_address.as_str(),
        CONFIG.interfold_address.as_str(),
        CONFIG.ciphernode_registry_address.as_str(),
        CONFIG.fee_token_address.as_str(),
        CONFIG.crisp_voting_token.as_deref().unwrap_or(""),
    ];

    configured
        .into_iter()
        .filter_map(|entry| Address::from_str(entry).ok())
        .chain(CONFIG.index_contracts())
        .collect()
});

/// Addresses whose logs are indexed right now, per `INDEX_LOG_CONTRACTS`.
static LOG_INDEXED: LazyLock<HashSet<Address>> =
    LazyLock::new(|| CONFIG.index_log_contracts().into_iter().collect());

pub fn is_allowed(address: &Address) -> bool {
    ALLOWED.contains(address)
}

pub fn parse_address(value: &str) -> Option<Address> {
    Address::from_str(value.trim()).ok()
}

/// Whether an address's logs are indexed RIGHT NOW, per the live configuration.
///
/// Checked in addition to the stored coverage record, which outlives the configuration that
/// created it: the store has no delete, so a contract removed from `INDEX_LOG_CONTRACTS` keeps its
/// record while the cursor advances. Every query would then be answered from a frozen index that
/// misses every event since the removal.
pub fn is_log_indexed(address: &str) -> bool {
    parse_address(address).is_some_and(|address| LOG_INDEXED.contains(&address))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use serde_json::json;

    fn encoded_aggregate3(targets: &[Address]) -> Vec<u8> {
        aggregate3Call {
            calls: targets
                .iter()
                .map(|target| Multicall3Call3 {
                    target: *target,
                    allowFailure: true,
                    callData: Bytes::from_static(&[0x70, 0xa0, 0x82, 0x31]),
                })
                .collect(),
        }
        .abi_encode()
    }

    #[test]
    fn every_multicall3_call_list_shape_reports_its_inner_targets() {
        let targets = [
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
        ];
        let plain = || {
            targets
                .iter()
                .map(|target| Multicall3Call {
                    target: *target,
                    callData: Bytes::new(),
                })
                .collect::<Vec<_>>()
        };
        let with_failure = || {
            targets
                .iter()
                .map(|target| Multicall3Call3 {
                    target: *target,
                    allowFailure: true,
                    callData: Bytes::new(),
                })
                .collect::<Vec<_>>()
        };
        let with_value = targets
            .iter()
            .map(|target| Multicall3Call3Value {
                target: *target,
                allowFailure: true,
                value: U256::ZERO,
                callData: Bytes::new(),
            })
            .collect::<Vec<_>>();

        let payloads = [
            aggregate3Call {
                calls: with_failure(),
            }
            .abi_encode(),
            aggregate3ValueCall { calls: with_value }.abi_encode(),
            aggregateCall { calls: plain() }.abi_encode(),
            blockAndAggregateCall { calls: plain() }.abi_encode(),
            tryAggregateCall {
                requireSuccess: false,
                calls: plain(),
            }
            .abi_encode(),
            tryBlockAndAggregateCall {
                requireSuccess: true,
                calls: plain(),
            }
            .abi_encode(),
        ];

        for payload in payloads {
            assert_eq!(multicall3_targets(&payload, 0).unwrap(), targets);
        }
    }

    #[test]
    fn nested_multicalls_are_unwrapped_rather_than_waved_through() {
        let hidden = address!("0x3333333333333333333333333333333333333333");

        let outer = aggregate3Call {
            calls: vec![Multicall3Call3 {
                target: MULTICALL3,
                allowFailure: true,
                callData: encoded_aggregate3(&[hidden]).into(),
            }],
        }
        .abi_encode();

        assert_eq!(multicall3_targets(&outer, 0).unwrap(), vec![hidden]);
    }

    #[test]
    fn nesting_past_the_cap_is_refused() {
        let mut payload =
            encoded_aggregate3(&[address!("0x4444444444444444444444444444444444444444")]);

        for _ in 0..=MAX_MULTICALL_DEPTH {
            payload = aggregate3Call {
                calls: vec![Multicall3Call3 {
                    target: MULTICALL3,
                    allowFailure: true,
                    callData: payload.into(),
                }],
            }
            .abi_encode();
        }

        assert!(multicall3_targets(&payload, 0).is_err());
    }

    #[test]
    fn get_eth_balance_reaches_no_other_contract() {
        let call_data = [MULTICALL3_GET_ETH_BALANCE.as_slice(), &[0u8; 32]].concat();

        assert!(multicall3_targets(&call_data, 0).unwrap().is_empty());
    }

    #[test]
    fn an_unknown_selector_on_multicall3_is_refused() {
        assert!(multicall3_targets(&[0xde, 0xad, 0xbe, 0xef], 0).is_err());
    }

    #[test]
    fn a_block_with_full_transaction_bodies_is_served() {
        // The shape viem's `waitForTransactionReceipt` sends to detect a replaced transaction.
        let params = json!(["0xb08cfe", true]);
        assert!(global_request_is_too_broad("eth_getBlockByNumber", &params).is_none());
        assert!(global_request_is_too_broad("eth_getBlockByHash", &params).is_none());
    }

    #[test]
    fn a_caller_chosen_fee_history_range_is_still_capped() {
        // Unlike a block, the caller picks how much work this is.
        let too_many = json!(["0x400", "latest", []]);
        assert!(global_request_is_too_broad("eth_feeHistory", &too_many).is_some());

        let reasonable = json!(["0x8", "latest", []]);
        assert!(global_request_is_too_broad("eth_feeHistory", &reasonable).is_none());
    }

    #[test]
    fn only_calls_and_log_queries_are_address_scoped() {
        // The caller's own EOA can never be on a list of watched contracts, so gating account
        // reads would gate every transaction in both apps.
        for method in [
            "eth_getBalance",
            "eth_getTransactionCount",
            "eth_getCode",
            "eth_getStorageAt",
        ] {
            let params = json!(["0x1111111111111111111111111111111111111111", "latest"]);
            assert!(
                matches!(requested_addresses(method, &params), Scope::Global),
                "{method} must not be address-scoped"
            );
        }

        let params = json!([{ "to": "0x1111111111111111111111111111111111111111" }]);
        assert!(matches!(
            requested_addresses("eth_call", &params),
            Scope::Addresses(_)
        ));

        // An `eth_call` with no `to` is arbitrary EVM, still refused.
        assert!(matches!(
            requested_addresses("eth_call", &json!([{}])),
            Scope::Unscoped(_)
        ));

        // A state override can replace the code at an allowlisted `to`.
        let overridden = json!([
            { "to": "0x1111111111111111111111111111111111111111" },
            "latest",
            { "0x1111111111111111111111111111111111111111": { "code": "0x00" } }
        ]);
        for method in ["eth_call", "eth_estimateGas"] {
            assert!(matches!(
                requested_addresses(method, &overridden),
                Scope::Unscoped(_)
            ));
        }
    }

    #[test]
    fn a_multicall_eth_call_is_scoped_to_its_inner_targets() {
        let one = address!("0x6666666666666666666666666666666666666666");
        let params = json!([{
            "to": "0xca11bde05977b3631167028862be2a173976ca11",
            "data": format!("0x{}", hex::encode(encoded_aggregate3(&[one]))),
        }]);

        match requested_addresses("eth_call", &params) {
            Scope::Addresses(addresses) => {
                assert_eq!(addresses, vec![one.to_string()]);
            }
            _ => panic!("a Multicall3 call must be address-scoped"),
        }
    }

    #[test]
    fn a_multicall_eth_call_without_data_is_refused() {
        let params = json!([{ "to": "0xca11bde05977b3631167028862be2a173976ca11" }]);

        assert!(matches!(
            requested_addresses("eth_call", &params),
            Scope::Unscoped(_)
        ));
    }
}
