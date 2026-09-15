// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

fn e3(chain_id: u64, id: &str) -> E3id {
    E3id::new(id, chain_id)
}

#[test]
fn add_and_remove_node() {
    let mut store = HashMap::new();
    NodeRegistry::add_node(&mut store, 1, "0xabc".into());
    assert!(store[&1].nodes.contains_key("0xabc"));

    NodeRegistry::remove_node(&mut store, 1, "0xabc");
    assert!(!store[&1].nodes.contains_key("0xabc"));

    // Removing an unknown node / chain is a no-op.
    NodeRegistry::remove_node(&mut store, 99, "0xdef");
}

#[test]
fn available_tickets_accounts_for_price_and_jobs() {
    let mut store = HashMap::new();
    NodeRegistry::set_ticket_price(&mut store, 1, U256::from(10));
    NodeRegistry::set_ticket_balance(&mut store, 1, "0xabc".into(), U256::from(55), 1);
    NodeRegistry::set_operator_active(&mut store, 1, "0xabc".into(), true, 1);

    // floor(55 / 10) = 5 tickets, no active jobs yet.
    assert_eq!(store[&1].available_tickets("0xabc"), 5);

    NodeRegistry::record_committee_published(&mut store, &e3(1, "7"), &["0xabc".into()]);
    // One active job now -> 4 available.
    assert_eq!(store[&1].available_tickets("0xabc"), 4);
    assert_eq!(store[&1].nodes["0xabc"].active_jobs, 1);
}

#[test]
fn zero_price_yields_no_tickets() {
    let mut store = HashMap::new();
    NodeRegistry::set_ticket_balance(&mut store, 1, "0xabc".into(), U256::from(100), 1);
    assert_eq!(store[&1].available_tickets("0xabc"), 0);
}

#[test]
fn operator_active_applies_only_to_the_event_chain() {
    let mut store = HashMap::new();
    NodeRegistry::add_node(&mut store, 1, "0xabc".into());
    NodeRegistry::add_node(&mut store, 2, "0xabc".into());
    NodeRegistry::set_operator_active(&mut store, 1, "0xabc".into(), true, 1);
    assert!(store[&1].nodes["0xabc"].active);
    assert!(!store[&2].nodes["0xabc"].active);
}

#[test]
fn eligibility_update_invalidates_only_the_target_chain() {
    let mut store = HashMap::new();
    NodeRegistry::add_node(&mut store, 1, "0xabc".into());
    NodeRegistry::add_node(&mut store, 2, "0xabc".into());
    NodeRegistry::set_operator_active(&mut store, 1, "0xabc".into(), true, 1);
    NodeRegistry::set_operator_active(&mut store, 2, "0xabc".into(), true, 1);

    NodeRegistry::invalidate_operator_activity(&mut store, 1, 2);

    assert!(!store[&1].nodes["0xabc"].active);
    assert!(store[&2].nodes["0xabc"].active);
}

#[test]
fn historical_state_excludes_changes_at_the_request_timestamp() {
    let mut store = HashMap::new();
    NodeRegistry::set_ticket_balance(&mut store, 1, "0xabc".into(), U256::from(30), 10);
    NodeRegistry::set_operator_active(&mut store, 1, "0xabc".into(), true, 10);
    NodeRegistry::set_ticket_balance(&mut store, 1, "0xabc".into(), U256::from(90), 20);
    NodeRegistry::set_operator_active(&mut store, 1, "0xabc".into(), false, 20);

    let node = &store[&1].nodes["0xabc"];
    assert_eq!(node.ticket_balance_at(19), U256::from(30));
    assert!(node.active_at(19));
    assert_eq!(node.ticket_balance_at(20), U256::from(90));
    assert!(!node.active_at(20));
}

#[test]
fn records_the_request_timepoint_and_price_together() {
    let mut store = HashMap::new();
    let e3_id = e3(1, "7");

    NodeRegistry::record_sortition_snapshot(&mut store, &e3_id, 100, U256::from(25));

    assert_eq!(
        store[&1].sortition_snapshot(&e3_id),
        Some(SortitionSnapshot {
            request_block: 100,
            ticket_price: U256::from(25),
        })
    );
}

#[test]
fn release_committee_jobs_is_idempotent() {
    let mut store = HashMap::new();
    let id = e3(1, "7");
    NodeRegistry::record_sortition_snapshot(&mut store, &id, 100, U256::from(25));
    NodeRegistry::record_committee_published(&mut store, &id, &["0xabc".into(), "0xdef".into()]);
    assert_eq!(store[&1].nodes["0xabc"].active_jobs, 1);
    assert_eq!(store[&1].nodes["0xdef"].active_jobs, 1);

    NodeRegistry::release_committee_jobs(&mut store, &id, "test");
    assert_eq!(store[&1].nodes["0xabc"].active_jobs, 0);
    assert_eq!(store[&1].nodes["0xdef"].active_jobs, 0);
    assert!(!store[&1].e3_committees.contains_key(&committee_key(&id)));
    assert!(store[&1].sortition_snapshot(&id).is_none());

    // Second release does not underflow.
    NodeRegistry::release_committee_jobs(&mut store, &id, "test-again");
    assert_eq!(store[&1].nodes["0xabc"].active_jobs, 0);
}

#[test]
fn duplicate_committee_publication_increments_jobs_once() {
    let mut store = HashMap::new();
    let id = e3(1, "17");
    let nodes = ["0xabc".into(), "0xdef".into()];

    NodeRegistry::record_committee_published(&mut store, &id, &nodes);
    NodeRegistry::record_committee_published(&mut store, &id, &nodes);

    assert_eq!(store[&1].nodes["0xabc"].active_jobs, 1);
    assert_eq!(store[&1].nodes["0xdef"].active_jobs, 1);
    assert_eq!(store[&1].e3_committees.len(), 1);
}

#[test]
fn conflicting_committee_replay_preserves_the_first_committee() {
    let mut store = HashMap::new();
    let id = e3(1, "18");

    NodeRegistry::record_committee_published(&mut store, &id, &["0xabc".into()]);
    NodeRegistry::record_committee_published(&mut store, &id, &["0xdef".into()]);

    assert_eq!(store[&1].nodes["0xabc"].active_jobs, 1);
    assert!(!store[&1].nodes.contains_key("0xdef"));
    assert_eq!(store[&1].e3_committees[&committee_key(&id)], vec!["0xabc"]);
}

#[test]
fn get_nodes_with_tickets_filters_inactive_and_empty() {
    let mut store = HashMap::new();
    NodeRegistry::set_ticket_price(&mut store, 1, U256::from(10));
    NodeRegistry::set_ticket_balance(&mut store, 1, "active".into(), U256::from(30), 1);
    NodeRegistry::set_operator_active(&mut store, 1, "active".into(), true, 1);
    // Inactive node with balance is excluded.
    NodeRegistry::set_ticket_balance(&mut store, 1, "inactive".into(), U256::from(30), 1);

    let with_tickets = store[&1].get_nodes_with_tickets();
    assert_eq!(with_tickets.len(), 1);
    assert_eq!(with_tickets[0].0, "active");
    assert_eq!(with_tickets[0].1, 3);
}

#[test]
fn open_committees_lists_only_unreleased() {
    let mut store = HashMap::new();
    let a = e3(1, "1");
    let b = e3(1, "2");
    NodeRegistry::record_committee_published(&mut store, &a, &["0xabc".into()]);
    NodeRegistry::record_committee_published(&mut store, &b, &["0xabc".into(), "0xdef".into()]);

    let open = NodeRegistry::open_committees(&store);
    assert_eq!(open.len(), 2);

    // Releasing one removes it from the open set.
    NodeRegistry::release_committee_jobs(&mut store, &a, "test");
    let open = NodeRegistry::open_committees(&store);
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].committee_key, committee_key(&b));
    assert_eq!(open[0].chain_id, 1);
    assert_eq!(
        open[0].members,
        vec!["0xabc".to_string(), "0xdef".to_string()]
    );

    // Fully drained -> empty.
    NodeRegistry::release_committee_jobs(&mut store, &b, "test");
    assert!(NodeRegistry::open_committees(&store).is_empty());
}
