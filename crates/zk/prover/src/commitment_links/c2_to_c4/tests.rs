// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::*;

fn make_field(val: u8) -> [u8; 32] {
    let mut f = [0u8; 32];
    f[31] = val;
    f
}

/// C2 inner signals: [expected_secret_commitment] + share commitments (row-major: party, mod).
fn c2_signals(share_commits: &[[u8; 32]]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&make_field(0xFF)); // expected_secret_commitment (skipped)
    for c in share_commits {
        v.extend_from_slice(c);
    }
    v
}

/// C4 signals: [expected_commitments row-major (party, mod)..., aggregated_commitment].
fn c4_signals(rows: &[Vec<[u8; 32]>], aggregated: [u8; 32]) -> Vec<u8> {
    let mut v = Vec::new();
    for row in rows {
        for c in row {
            v.extend_from_slice(c);
        }
    }
    v.extend_from_slice(&aggregated);
    v
}

#[test]
fn extract_share_commitments_from_c2() {
    let link = C2aToC4aShareCommitmentLink { l: 2 };
    // C2 with 3 parties × 2 moduli = 6 share commits
    let commits: Vec<[u8; 32]> = (1u8..=6).map(make_field).collect();
    let c2 = c2_signals(&commits);
    let values = link.extract_source_values(&c2);
    assert_eq!(values.len(), 6);
    assert_eq!(values[0], make_field(1));
    assert_eq!(values[5], make_field(6));
}

#[test]
fn extract_skips_secret_commitment() {
    let link = C2aToC4aShareCommitmentLink { l: 2 };
    let c2 = c2_signals(&[make_field(1), make_field(2)]);
    let values = link.extract_source_values(&c2);
    assert_eq!(values.len(), 2);
    assert!(!values.contains(&make_field(0xFF)));
}

/// 3 parties (N=3), 2 moduli (L=2), 2 honest parties (H=2).
/// C2 from party X=1, C4 for recipient R=1.
/// C2_X: [p0m0,p0m1, p1m0,p1m1, p2m0,p2m1]
/// C4_R=1: rows for party 0 and party 1 = [[p0m0,p0m1],[p1m0,p1m1]] + agg
/// check_consistency(src=1, tgt=1): C2 slot R=1 = [p1m0,p1m1] must equal C4 row X=1 = [p1m0,p1m1]
#[test]
fn consistency_passes_precise_l_way_check() {
    let l = 2;
    let link = C2aToC4aShareCommitmentLink { l };

    // C2 from sender X=1: 3 parties × 2 moduli
    let c2 = c2_signals(&[
        make_field(10),
        make_field(11), // party 0
        make_field(20),
        make_field(21), // party 1 (slot for tgt_party=1)
        make_field(30),
        make_field(31), // party 2
    ]);
    let source_values = link.extract_source_values(&c2);

    // C4 for recipient R=1: 2 honest parties (rows for X=0 and X=1)
    let c4 = c4_signals(
        &[
            vec![make_field(10), make_field(11)], // row X=0
            vec![make_field(20), make_field(21)], // row X=1 (sender's commits for this recipient)
        ],
        make_field(99), // aggregated output
    );

    // src_party_id=1 (sender X=1), tgt_party_id=1 (recipient R=1)
    assert!(link.check_consistency(&source_values, &c4, 1, 1));
}

#[test]
fn consistency_fails_when_wrong_modulus_commitment() {
    let l = 2;
    let link = C2aToC4aShareCommitmentLink { l };

    let c2 = c2_signals(&[
        make_field(10),
        make_field(11),
        make_field(20),
        make_field(21), // party 1 slot
        make_field(30),
        make_field(31),
    ]);
    let source_values = link.extract_source_values(&c2);

    // C4 has correct first modulus (20) but wrong second (99 instead of 21)
    let c4 = c4_signals(
        &[
            vec![make_field(10), make_field(11)],
            vec![make_field(20), make_field(99)], // second modulus wrong
        ],
        make_field(0),
    );

    assert!(!link.check_consistency(&source_values, &c4, 1, 1));
}

#[test]
fn consistency_fails_when_wrong_party_slot() {
    let l = 2;
    let link = C2aToC4aShareCommitmentLink { l };

    let c2 = c2_signals(&[
        make_field(10),
        make_field(11), // party 0
        make_field(20),
        make_field(21), // party 1
    ]);
    let source_values = link.extract_source_values(&c2);

    // C4 has party-0 commits in row 0 only
    let c4 = c4_signals(&[vec![make_field(10), make_field(11)]], make_field(0));

    // src=0, tgt=1: C2 slot 1 = [20,21], C4 row 0 = [10,11] — mismatch
    assert!(!link.check_consistency(&source_values, &c4, 0, 1));
}

#[test]
fn consistency_does_not_match_aggregated_output() {
    let l = 1;
    let link = C2aToC4aShareCommitmentLink { l };

    // C2: 1 party × 1 modulus = commit 99
    let c2 = c2_signals(&[make_field(99)]);
    let source_values = link.extract_source_values(&c2);

    // C4: row 0 = [5], aggregated output = 99
    // commit 99 is only in the tail — must not match
    let c4 = c4_signals(&[vec![make_field(5)]], make_field(99));

    assert!(!link.check_consistency(&source_values, &c4, 0, 0));
}

#[test]
fn short_or_empty_signals() {
    let link = C2aToC4aShareCommitmentLink { l: 2 };
    assert!(link.extract_source_values(&[0u8; 32]).is_empty());
    assert!(!link.check_consistency(&[], &[0u8; 256], 0, 0));
    assert!(!link.check_consistency(&[make_field(1)], &[0u8; 16], 0, 0));
}

#[test]
fn c2b_to_c4b_variant() {
    let l = 2;
    let link = C2bToC4bShareCommitmentLink { l };
    let c2 = c2_signals(&[make_field(7), make_field(8)]);
    let source_values = link.extract_source_values(&c2);

    let c4 = c4_signals(&[vec![make_field(7), make_field(8)]], make_field(0));
    assert!(link.check_consistency(&source_values, &c4, 0, 0));

    let c4_wrong = c4_signals(&[vec![make_field(7), make_field(9)]], make_field(0));
    assert!(!link.check_consistency(&source_values, &c4_wrong, 0, 0));
}
