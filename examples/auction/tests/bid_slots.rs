// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! The slot plaintexts of a bid, as the bid proof circuits (`circuits/bid`) read them.

use auction_designs::designs::slot_level;
use auction_designs::{Profile, Setup, Vickrey, VickreyCompact};

fn setup(bidders: usize, levels: usize) -> Setup {
    Setup::new(Profile::Toy.build(3), bidders, levels)
}

#[test]
fn every_slot_of_a_bid_depends_on_its_level_only() {
    // 3 bidders at 16 levels leave 16 slots beyond the last copy of 21: they hold 0.
    for (bidders, levels) in [(4, 16), (3, 16)] {
        let setup = setup(bidders, levels);
        let slots = (setup.params.degree() / (bidders * levels)) * bidders * levels;
        for bid in [0u64, 5, 15] {
            let thermometers = Vickrey.bid_slots(&setup, bid);
            let combined = VickreyCompact.bid_slots(&setup, bid);
            assert_eq!((thermometers.len(), combined.len()), (2, 1));
            for slot in 0..setup.params.degree() {
                let level = slot_level(&setup, slot);
                assert_eq!(level.is_some(), slot < slots);
                let (at_least, above) = match level {
                    Some(level) => (
                        u64::from(bid >= level as u64),
                        u64::from(bid > level as u64),
                    ),
                    None => (0, 0),
                };
                assert_eq!(thermometers[0][slot], at_least);
                assert_eq!(thermometers[1][slot], above);
                assert_eq!(combined[0][slot], 2 * at_least - above);
            }
        }
    }
}
