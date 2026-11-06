// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The DKG at the node boundary: inputs in, effects and DKG state out. The committee is
//! Minimum: operators 1, 2, and ME, with H = 2.

mod keys;
mod shares;

use super::Dkg;
use crate::{
    node::{Effect, Node},
    testing::*,
    Machine,
};
use alloy_primitives::Address;

const NOW: u64 = 9_000;
const KEY_CUTOFF: u64 = 9_100;
const SHARE_CHECKPOINT: u64 = 9_750;

fn committee() -> Vec<Address> {
    [1, 2, ME].map(address).to_vec()
}

fn others(me: u64) -> Vec<u64> {
    [1, 2, ME].into_iter().filter(|n| *n != me).collect()
}

/// Operator `me`, a member whose committee was just finalized.
fn member(me: u64) -> Node {
    let mut node = Node::new(address(me));
    node.step(0, requested(10, e3(1)));
    node.step(NOW, finalized(11, e3(1), committee()));
    node
}

/// Operator `me`, a member that has made, signed, and sent its key.
fn with_its_key(me: u64) -> Node {
    let mut node = member(me);
    let effects = node.step(NOW, key_made(e3(1), own_key(0xee)));
    node.step(NOW, sign(me, signing(&effects)));
    node
}

fn add_valid_key(node: &mut Node, n: u64) -> Vec<Effect> {
    node.step(NOW, key_from(e3(1), n));
    node.step(NOW, key_checked(e3(1), n, true))
}

fn dkg(node: &Node) -> &Dkg {
    node.e3(&e3(1))
        .and_then(|state| state.dkg.as_ref())
        .expect("the DKG started")
}
