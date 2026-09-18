// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! CRISP's selection rule: the end of each slot's chain of usable entries.
//!
//! The rule lives here rather than in `e3-compute-provider` because it is CRISP's answer to CRISP's
//! problem — an append-only tree that anyone may write to. A program where every input counts wants
//! the crate's default instead.

use e3_compute_provider::policy::PublishedInput;
use e3_user_program::policy::chain_head_per_slot;

/// One published entry, as a test states it.
#[derive(Clone, Copy)]
struct Entry {
    slot: u8,
    /// Whether the bytes reproduce the commitment. A third party can publish an entry where they
    /// do not, and nobody can tell until here.
    usable: bool,
    /// The tree index this entry names as the one it extends, or `None` for nothing.
    parent: Option<usize>,
}

/// An honest entry extending `parent`.
fn good(slot: u8, parent: Option<usize>) -> Entry {
    Entry {
        slot,
        usable: true,
        parent,
    }
}

/// An entry whose published bytes do not reproduce its commitment.
fn poisoned(slot: u8, parent: Option<usize>) -> Entry {
    Entry {
        slot,
        usable: false,
        parent,
    }
}

fn slot_address(tag: u8) -> [u8; 20] {
    let mut address = [0u8; 20];
    address[19] = tag;
    address
}

/// `abi.encodePacked(address, uint40)`, which is what `CRISPProgram` publishes per input.
fn metadata(entry: &Entry) -> Vec<u8> {
    let parent_plus_one = entry.parent.map_or(0u64, |index| index as u64 + 1);

    let mut bytes = slot_address(entry.slot).to_vec();
    bytes.extend_from_slice(&parent_plus_one.to_be_bytes()[3..]);
    bytes
}

fn select(entries: &[Entry]) -> Vec<usize> {
    let stored: Vec<[u8; 32]> = (0..entries.len()).map(|i| [i as u8; 32]).collect();
    let metadatas: Vec<Vec<u8>> = entries.iter().map(metadata).collect();
    let bytes = vec![0u8];

    let inputs: Vec<PublishedInput> = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| PublishedInput {
            index,
            ciphertext: &bytes,
            commitment: Some(&stored[index]),
            metadata: &metadatas[index],
            recomputed: Some(if entry.usable {
                stored[index]
            } else {
                [0xff; 32]
            }),
        })
        .collect();

    chain_head_per_slot(&inputs)
}

/// A chain of honest entries resolves to its end.
#[test]
fn selection_follows_the_chain_to_its_end() {
    assert_eq!(select(&[good(1, None)]), vec![0], "a single entry");
    assert_eq!(
        select(&[good(1, None), good(1, Some(0))]),
        vec![1],
        "an entry extending the first replaces it"
    );
    assert_eq!(
        select(&[good(1, None), good(1, Some(0)), good(1, Some(1))]),
        vec![2],
        "a three-entry chain resolves to its end"
    );
}

/// A poisoned entry does not become the head, and the next honest input extends the same parent it
/// did. This is the whole point of naming the parent: a slot cannot be frozen against masking, and
/// a slot that cannot be masked is one where every later input is provably its owner voting again.
#[test]
fn a_poisoned_entry_does_not_freeze_the_slot() {
    assert_eq!(
        select(&[poisoned(1, None)]),
        Vec::<usize>::new(),
        "a single poisoned entry contributes nothing"
    );
    assert_eq!(
        select(&[good(1, None), poisoned(1, Some(0))]),
        vec![0],
        "a poisoned append leaves the head where it was"
    );
    assert_eq!(
        select(&[good(1, None), poisoned(1, Some(0)), good(1, Some(0))]),
        vec![2],
        "the next honest entry names the same parent and takes the head"
    );
    assert_eq!(
        select(&[
            good(1, None),
            poisoned(1, Some(0)),
            poisoned(1, Some(0)),
            good(1, Some(0)),
        ]),
        vec![3],
        "repeated poisoning does not exhaust the slot"
    );
    assert_eq!(
        select(&[poisoned(1, None), good(1, None)]),
        vec![1],
        "a slot poisoned before its first vote is still writable"
    );
}

/// The first usable sibling keeps the slot, so a stale sibling cannot restore an older ballot.
///
/// The attack this rules out: a voter casts A, re-votes B, and a third party then masks the
/// *original* entry rather than the re-vote. A mask adds zero, so its plaintext is whatever its
/// parent held — taking it would put A back in the slot and erase B. No signature is needed to
/// publish a mask, so anyone could do it to anyone.
///
/// The same sequence also represents a mask landing before a re-vote that was built against the
/// old parent. Entry labels are private circuit inputs, so selection can only apply one ordering
/// rule: the earlier usable sibling wins and the later sibling must be retried against that head.
#[test]
fn the_first_usable_sibling_keeps_the_slot() {
    // vote A at 0, re-vote B at 1, then a mask naming 0 instead of 1.
    assert_eq!(
        select(&[good(1, None), good(1, Some(0)), good(1, Some(0))]),
        vec![1],
        "the re-vote keeps the slot; the stale mask is dropped"
    );
    assert_eq!(
        select(&[good(1, None), good(1, Some(0)), good(1, None)]),
        vec![1],
        "naming no parent on an occupied slot does not restart the chain either"
    );
}

/// A poisoned entry does not shift the head, so the entry after it names the head as it stands.
#[test]
fn an_entry_after_a_poisoned_one_names_the_unchanged_head() {
    assert_eq!(
        select(&[
            good(1, None),
            good(1, Some(0)),
            poisoned(1, Some(0)),
            good(1, Some(1))
        ]),
        vec![3],
        "the head is still 1, so an entry naming 1 is taken"
    );
}

/// A parent belonging to another slot is not this slot's head, so it is dropped. `CRISPProgram`
/// refuses one as well, by keying its commitments on the slot.
#[test]
fn an_entry_naming_another_slots_parent_is_dropped() {
    assert_eq!(
        select(&[good(1, None), good(2, Some(0))]),
        vec![0],
        "slot 2 cannot extend slot 1's entry"
    );
}

/// Sequences interleaved across slots must not bleed into one another.
#[test]
fn interleaved_slots_resolve_independently() {
    let entries = [
        good(1, None),
        poisoned(2, None),
        poisoned(1, Some(0)),
        good(2, None),
    ];

    assert_eq!(
        select(&entries),
        vec![0, 3],
        "each slot resolves on its own entries, in tree order"
    );
}

/// An entry whose metadata is not a slot and a parent cannot be placed in a chain, so it is not
/// selected. It still contributes a leaf — that is the crate's guarantee, not the policy's.
#[test]
fn an_entry_without_valid_metadata_is_not_selected() {
    let stored = [7u8; 32];
    let bytes = vec![0u8];
    let malformed = [0u8; 4];

    let inputs = vec![PublishedInput {
        index: 0,
        ciphertext: &bytes,
        commitment: Some(&stored),
        metadata: &malformed,
        recomputed: Some(stored),
    }];

    assert!(chain_head_per_slot(&inputs).is_empty());
}
