// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ckks_fedavg::server::start()
}
