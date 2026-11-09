// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! What a correct run must produce, checked over the [`Observations`] the runner returns: the key
//! and plaintext, the accepted DKG roster, the key submissions of the aggregator-role holders, the
//! shares the scenario's [`Expect`](super::scenario::Expect) owes, and the absence of faults.
//! Nothing here touches a live node, and nothing asserts how the nodes' actors order their events.

use super::history::collect_honest_run_faults;
use super::runner::Observations;
use super::scenario::{Scenario, VOTES_PER_VOTER};
use e3_bfv_client::decode_bytes_to_vec_u64;
use e3_events::{prelude::*, EventSource, InterfoldEvent, InterfoldEventData};
use e3_utils::utility_types::ArcBytes;
use fhe::bfv::BfvParameters;

/// Panics when the run's observations miss what its scenario expects.
pub fn check(scenario: &Scenario, observed: &Observations) {
    check_public_key(observed);
    check_plaintext(observed);
    check_roster(scenario, observed);
    check_standby_share(scenario, observed);
    check_restarted_share(scenario, observed);
    check_key_submissions(observed);
    check_no_faults(observed);
}

/// The key lists the honest committee and carries its attestation. The final DKG proof it must
/// carry is the runner's to take, since the registry's observation needs it.
fn check_public_key(observed: &Observations) {
    let h = observed.config.committee_h;
    assert_eq!(
        observed.key.nodes.len(),
        h,
        "PublicKeyAggregated must list H={h} honest nodes"
    );
    assert!(
        observed
            .key
            .dkg_attestation_bundle
            .as_ref()
            .is_some_and(|bundle| !bundle.is_empty()),
        "PublicKeyAggregated must always carry a non-empty DKG attestation payload"
    );
}

fn check_plaintext(observed: &Observations) {
    assert_eq!(
        observed.plaintext.decryption_aggregator_proofs.len(),
        VOTES_PER_VOTER,
        "PlaintextAggregated must carry one decryption proof per tally"
    );
    check_tally(
        &observed.params,
        &observed.plaintext.decrypted_output,
        &observed.votes,
    );
}

/// The decrypted tallies must equal the sum of every voter's votes.
fn check_tally(params: &BfvParameters, decrypted: &[ArcBytes], votes: &[Vec<u64>]) {
    let results: Vec<u64> = decrypted
        .iter()
        .map(|a| decode_bytes_to_vec_u64(&a.extract_bytes()).expect("error decoding bytes"))
        .map(|r| *r.first().unwrap())
        .collect();
    let plaintext_modulus = params.plaintext();
    let mut expected_result = [0u64; VOTES_PER_VOTER];
    for vals in votes {
        for (expected, vote) in expected_result.iter_mut().zip(vals) {
            *expected = (*expected + vote) % plaintext_modulus;
        }
    }
    assert_eq!(
        results.as_slice(),
        expected_result.as_slice(),
        "Threshold decryption must return every expected tally"
    );
    for (i, (res, exp)) in results.iter().zip(expected_result.iter()).enumerate() {
        println!("Tally {i} result = {res} / {exp}");
    }
}

fn check_roster(scenario: &Scenario, observed: &Observations) {
    if let Some(party) = scenario.expect.roster_excludes {
        assert!(
            !observed.roster.contains(&(party as u64)),
            "disconnected party was selected for the DKG roster"
        );
    }
}

/// The aggregator can publish before a standby party's share lands; the standby party still has
/// to deal it, since it replaces a roster member that drops out.
fn check_standby_share(scenario: &Scenario, observed: &Observations) {
    if !observed.config.standby_share_owed(&scenario.expect) {
        return;
    }
    let standby = observed
        .standby
        .as_ref()
        .expect("DKG roster has no standby party");
    assert!(
        standby.share_dealt,
        "standby party {} did not deal its C4 share",
        standby.party_id
    );
}

/// The restarted party must publish what its pending proof owed: its C4 share, or its C6
/// decryption share. It had not published it when it stopped, so the share is the restarted
/// node's own.
fn check_restarted_share(scenario: &Scenario, observed: &Observations) {
    let Some(owed) = scenario.expect.restarted_share else {
        return;
    };
    let restarted = observed
        .restarted
        .as_ref()
        .expect("the scenario expects a restart, and none ran");
    assert!(
        restarted.share_published,
        "restarted party {} did not publish its {owed:?} share",
        restarted.party_id
    );
}

/// The runtime lets a demoted holder finish and submit the key it computed, and the chain keeps
/// the first valid submission. Every submission must therefore be the key the committee goes on
/// to use, with the same committee, honest subset and commitment. A holder's own submission is
/// `Local`; peers forward copies. A better-ranked proposal can replace an accepted roster until
/// C4 fixes it, so each submitting holder's final roster must be the one the key lists.
fn check_key_submissions(observed: &Observations) {
    let key = &observed.key;
    let mut submissions = 0;
    for (node_index, history) in &observed.role_holders {
        let mut final_roster: Option<&Vec<u64>> = None;
        let mut submitted = false;
        for event in history.iter() {
            match (event.source(), event.get_data()) {
                (_, InterfoldEventData::CommitmentRosterSelected(data))
                    if data.e3_id == observed.e3_id =>
                {
                    final_roster = Some(&data.party_ids);
                }
                (EventSource::Local, InterfoldEventData::PublicKeyAggregated(data))
                    if data.e3_id == observed.e3_id =>
                {
                    submitted = true;
                    assert!(
                        data.pubkey == key.pubkey
                            && data.committee_addresses == key.committee_addresses
                            && data.honest_committee_addresses == key.honest_committee_addresses
                            && data.pk_commitment == key.pk_commitment,
                        "role holder {node_index} submitted a key that differs from the one the committee used"
                    );
                }
                _ => {}
            }
        }
        if submitted {
            submissions += 1;
            assert_eq!(
                final_roster.map(Vec::as_slice),
                Some(observed.roster.as_slice()),
                "role holder {node_index} submitted a key whose roster is not the one it selected"
            );
        }
    }
    assert!(submissions > 0, "no role holder submitted the public key");
}

/// No node may have accused, expelled, or failed anyone, or logged an actor error. The
/// disconnected node cannot collect its own DKG shares, so it can fail locally without failing the
/// E3: only what it logged before the disconnect is scanned.
fn check_no_faults(observed: &Observations) {
    let mut faults = Vec::new();
    for node in &observed.nodes {
        let history: &[InterfoldEvent] = match observed.offline {
            Some(offline) if offline.node_index == node.index => {
                &node.history[..offline.events_before_disconnect.min(node.history.len())]
            }
            _ => &node.history,
        };
        let context = if node.index == 0 {
            "observer node 0".to_string()
        } else {
            format!("participant node {} ({})", node.index, node.address)
        };
        faults.extend(collect_honest_run_faults(
            history,
            &observed.e3_id,
            &context,
        ));
    }
    assert!(
        faults.is_empty(),
        "honest-run safeguard failures:\n{}",
        faults.join("\n")
    );
}
