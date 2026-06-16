// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::SharedRng;
use alloy::primitives::Address;
use rand::Rng;

pub fn rand_eth_addr(rng: &SharedRng) -> String {
    {
        let rnum = &mut rng.lock().unwrap().random::<[u8; 20]>();
        Address::from_slice(rnum).to_string()
    }
}
