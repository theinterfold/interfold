// SPDX-License-Identifier: LGPL-3.0-only

//! Development benchmark owner. This unpublished binary measures circuit leaf phases, protocol
//! integration, verifier gas, and saved-data replay. It is a development tool: its dependency on
//! `e3-zk-samples` is a normal dependency here and is allowed only for this crate.

mod circuit_benchmark;

fn main() -> anyhow::Result<()> {
    circuit_benchmark::main()
}
