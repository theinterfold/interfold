// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy::primitives::{keccak256, Address, U256};
use alloy::sol_types::SolValue;
use anyhow::{anyhow, Result};
use e3_events::{E3id, Seed};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// Represents a registered node, identified by its address,
/// and carrying a vector of tickets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisteredNode {
    pub address: Address,
    pub tickets: Vec<Ticket>,
}

/// A single ticket belonging to a node.
/// Ticket IDs are assumed to be globally unique.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ticket {
    pub ticket_id: u64,
}

/// A node's candidate for committee selection.
/// Chosen as the ticket with the lowest score among all of its tickets.
#[derive(Clone, Debug)]
pub struct WinnerTicket {
    pub address: Address,
    pub ticket_id: u64,
    /// Deterministic score, derived from hashing seed, address, and ticket ID.
    /// Lower is considered better.
    pub score: BigUint,
}

/// Compute a deterministic score for a ticket.
///
/// The score is defined as the Keccak-256 hash:
/// `keccak256(abi.encodePacked(node, ticketNumber, e3Id, seed))`
pub fn hash_to_score(address: Address, ticket_id: u64, e3_id: E3id, seed: Seed) -> BigUint {
    let e3_id_u256: U256 = e3_id.try_into().expect("E3id should be valid U256");
    let seed_u256 = U256::from_le_bytes(seed.into());

    // Format: address(20B) || ticketNumber(32B) || e3Id(32B) || seed(32B)
    let msg = (address, U256::from(ticket_id), e3_id_u256, seed_u256).abi_encode_packed();
    let digest = keccak256(&msg);
    BigUint::from_bytes_be(&digest.0)
}

/// For a given node, compute the score for each ticket and
/// return the ticket with the lowest score.
///
/// Ties are broken deterministically by selecting the ticket
/// with the smaller ticket ID.
///
/// # Errors
/// Returns an error if the node has no tickets.
pub fn calculate_best_ticket_for_node(
    e3_id: E3id,
    seed: Seed,
    registered_node: &RegisteredNode,
) -> Result<WinnerTicket> {
    if registered_node.tickets.is_empty() {
        return Err(anyhow!("no tickets in the registered node"));
    }

    let mut best: Option<WinnerTicket> = None;

    for ticket in &registered_node.tickets {
        let score = hash_to_score(
            registered_node.address,
            ticket.ticket_id,
            e3_id.clone(),
            seed,
        );

        match &best {
            None => {
                best = Some(WinnerTicket {
                    address: registered_node.address,
                    ticket_id: ticket.ticket_id,
                    score,
                });
            }
            Some(cur) => {
                if score < cur.score || (score == cur.score && ticket.ticket_id < cur.ticket_id) {
                    best = Some(WinnerTicket {
                        address: registered_node.address,
                        ticket_id: ticket.ticket_id,
                        score,
                    });
                }
            }
        }
    }
    // TODO: Add sign to the best ticket, so it can be verified

    best.ok_or_else(|| anyhow!("no winning ticket found"))
}
