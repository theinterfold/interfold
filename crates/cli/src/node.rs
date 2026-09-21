// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Result};
use clap::Subcommand;
use e3_config::AppConfig;
use e3_console::{log, Console};
use e3_entrypoint::validate::validate_node;

#[derive(Subcommand, Clone, Debug)]
pub enum NodeCommands {
    /// Validate the on-disk state of a single node without starting it.
    ///
    /// Takes the node's exclusive process fence and checks that the schema is
    /// loadable by this binary, the event log is intact, the snapshot cursor is
    /// consistent, and there are no orphaned committee tickets ("loose ends").
    /// Safe to run while the node is stopped; intended as the pre-upgrade and
    /// post-crash health check. Exits non-zero on failure. Without `--repair`,
    /// no files are changed.
    Validate {
        /// Repair a safe log tail or rebuild a stale derived sortition projection
        #[arg(long)]
        repair: bool,
    },

    /// Delete durable protocol state but keep the operator identity.
    ///
    /// Use this when a release raises the storage schema and the binary refuses
    /// to load the existing data directory. The wallet key and libp2p keypair
    /// live in the same store as that state, so removing the directory by hand
    /// destroys the identity holding the bond. This command copies both out as
    /// ciphertext, removes the event log and the key/value store, then writes
    /// them back and reads them again to confirm.
    ///
    /// Takes the node's exclusive process fence, so it refuses while the node
    /// is running. Stop the node first.
    ResetData {
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,
    },
}

pub async fn execute(out: Console, command: NodeCommands, config: &AppConfig) -> Result<()> {
    match command {
        NodeCommands::Validate { repair } => {
            // Offline-only contract: hold the same cross-host fence `start` uses so the
            // validator cannot read state out from under a live node or race a concurrent
            // `interfold start`. Released when this scope ends.
            let _fence =
                e3_entrypoint::fence::ProcessFence::acquire(&config.db_file(), &config.name())?;
            let report = validate_node(config, repair).await?;
            log!(out, "{}", report.render());
            if report.has_failure() {
                bail!("node validation failed");
            }
        }
        NodeCommands::ResetData { yes } => {
            reset_data(out, config, yes).await?;
        }
    }
    Ok(())
}

/// Clear durable state for one node, keeping the operator identity.
async fn reset_data(out: Console, config: &AppConfig, yes: bool) -> Result<()> {
    if !yes {
        bail!(
            "This deletes the durable state for node '{}' at {}. The operator key and libp2p \
             identity are preserved and an encrypted backup is written first. Stop the node, \
             then re-run with --yes.",
            config.name(),
            config.db_file().display()
        );
    }

    // The fence is taken inside the entrypoint, which holds it across the whole
    // delete-and-restore so a concurrent start cannot interleave.
    let outcome = e3_entrypoint::nodes::reset_data::execute(config).await?;

    log!(out, "Removed {}", outcome.db_file.display());
    for path in &outcome.log_paths {
        log!(out, "Removed {}", path.display());
    }
    if outcome.log_paths.is_empty() {
        log!(out, "No event-log files were present.");
    }
    log!(out, "Identity backup: {}", outcome.backup_file.display());
    if outcome.identity_restored {
        log!(
            out,
            "The operator key and libp2p identity were preserved. Verify with: interfold wallet get --name {}",
            config.name()
        );
    } else {
        log!(
            out,
            "No identity was present, so none was restored. Set one with: interfold wallet set --name {}",
            config.name()
        );
    }
    Ok(())
}
