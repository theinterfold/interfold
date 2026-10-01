// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crisp::server;

/// Without arguments, start the server. `compact-database FROM TO` copies a stopped server's
/// database into a new directory, without the old page copies that sled keeps on disk.
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => server::start(),
        [command, from, to] if command == "compact-database" => {
            // sled panics when the disk is full, and its handles then wait for a write that cannot
            // finish. Exit at the panic, so that the command stops instead of waiting.
            let report = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |panic| {
                report(panic);
                std::process::exit(1);
            }));
            server::compact_database(from, to).map_err(|error| error.to_string())?;
            println!("Compacted {from} into {to}");
            Ok(())
        }
        _ => Err("usage: server [compact-database FROM TO]".into()),
    }
}
