// SPDX-License-Identifier: LGPL-3.0-only

//! Replay-safe ZK worker result tallying.

use super::*;

impl ShareVerifier {
    /// Tally ZK verification results against the dispatched set: accumulate the
    /// dishonest party set (including parties missing from the response) and
    /// produce ordered per-party emission decisions. Pure: no event publishing.
    pub(crate) fn tally_zk_results(
        pre_dishonest: BTreeSet<u64>,
        ecdsa_dishonest: &HashSet<u64>,
        dispatched_party_ids: &HashSet<u64>,
        zk_results: &[PartyVerificationResult],
    ) -> ZkTallyOutcome {
        let mut dishonest: BTreeSet<u64> = pre_dishonest;
        dishonest.extend(ecdsa_dishonest);

        // Canonicalize the worker response before tallying. Exact duplicate responses are
        // harmless replays and are collapsed; conflicting responses for one party fail closed.
        // This also guarantees at most one Passed/Failed emission per canonical party.
        let mut unique_results: HashMap<u64, &PartyVerificationResult> = HashMap::new();
        let mut result_order = Vec::new();
        let mut conflicting_party_ids = HashSet::new();
        for result in zk_results {
            if !dispatched_party_ids.contains(&result.sender_party_id) {
                warn!(
                    "ZK result for party {} was not dispatched — ignoring",
                    result.sender_party_id
                );
                continue;
            }

            match unique_results.get(&result.sender_party_id).copied() {
                Some(existing) if existing == result => {
                    warn!(
                        "Duplicate ZK result replay for party {} ignored",
                        result.sender_party_id
                    );
                }
                Some(_) => {
                    warn!(
                        "Conflicting ZK results for party {} — treating as dishonest",
                        result.sender_party_id
                    );
                    conflicting_party_ids.insert(result.sender_party_id);
                }
                None => {
                    unique_results.insert(result.sender_party_id, result);
                    result_order.push(result.sender_party_id);
                }
            }
        }

        // Cross-check: every dispatched party must appear exactly once after replay collapse.
        for &dispatched_pid in dispatched_party_ids {
            if !unique_results.contains_key(&dispatched_pid) {
                warn!(
                    "Party {} was dispatched for ZK verification but missing from results — treating as dishonest",
                    dispatched_pid
                );
                dishonest.insert(dispatched_pid);
            }
        }

        let mut emissions = Vec::new();
        for party_id in result_order {
            if conflicting_party_ids.contains(&party_id) {
                dishonest.insert(party_id);
                continue;
            }
            let Some(result) = unique_results.get(&party_id) else {
                // `result_order` and `unique_results` are populated together above. Keep this
                // boundary panic-free if that implementation changes later.
                dishonest.insert(party_id);
                continue;
            };
            if !result.all_verified {
                dishonest.insert(result.sender_party_id);
                if let Some(ref signed) = result.failed_signed_payload {
                    emissions.push(ZkPartyEmission::Failed {
                        party_id: result.sender_party_id,
                        signed: signed.clone(),
                    });
                }
            } else {
                emissions.push(ZkPartyEmission::Passed {
                    party_id: result.sender_party_id,
                });
            }
        }

        ZkTallyOutcome {
            dishonest,
            emissions,
        }
    }
}
