// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use super::threshold::GADGET_DIM;

pub mod crs;
pub mod urs;

pub use crate::configs::insecure::lbfv::crs::LBFV_CRS_GADGET_ROWS;
pub use crate::configs::insecure::lbfv::urs::LBFV_URS_GADGET_ROWS;

pub global G_GADGET_ROWS: [Field; GADGET_DIM] = [
    127637751993563524157370279156423903080857411468674,
    121548282937826867843993103447285854519735315562418,
    124958384225041632756555745681323624584772389138638,
];
