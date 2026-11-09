// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{
    keystore,
    node_state::{self, Plan},
};
use anyhow::{bail, Context, Result};
use clap::Subcommand;
use e3_ciphernode_config::NodeConfig;
use e3_console::{log, Console};
use e3_crypto::Cipher;
use e3_entrypoint::fence::{ProcessFence, LOCK_FILE_NAME};
use e3_node::dir::State;

#[derive(Subcommand, Clone, Debug)]
pub enum NodeCommands {
    /// Check a stopped node: its password and keys, the layout of its data, and the E3s it holds.
    /// Exits non-zero on failure. It creates nothing and changes no node state.
    Validate,

    /// Delete the node's data but keep its operator and network keys.
    ///
    /// Use this when a release changes the layout of the node's data and the node refuses to start
    /// on it. The keys live in the keystore, apart from the data, so they stay.
    ///
    /// Refuses while the node runs, and while it holds an E3 that has not ended: the chain cannot
    /// restore a deleted key share. Refuses too where it cannot tell: data in an older layout,
    /// which this binary cannot read, and another node's journal inside the folder.
    ResetData {
        /// Confirm the deletion.
        #[arg(long)]
        yes: bool,

        /// Delete the data even when the node holds an E3 that has not ended. The node gives up
        /// what it still owes each E3 the command lists: its key share, an open accusation, or
        /// settling a failure. A failed E3 can still owe these, so a failed E3 on chain is not
        /// enough: check what the command lists for it.
        #[arg(long)]
        allow_active_e3s: bool,

        /// Reset only when the data uses an older layout than this binary writes. Otherwise change
        /// nothing and exit with success. A package can run this before every start.
        #[arg(long)]
        if_schema_older: bool,
    },

    /// Print what the node noted for its operator, oldest first: DKG failures, Ready reports,
    /// rosters, and proofs that failed. Reads the node's feed and changes nothing, also while
    /// the node runs.
    Events {
        /// Only notes after this sequence number.
        #[arg(long, default_value_t = 0)]
        since: u64,

        /// At most this many notes.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

pub async fn execute(out: Console, command: NodeCommands, config: &NodeConfig) -> Result<()> {
    match command {
        NodeCommands::Validate => validate(out, config).await,
        NodeCommands::ResetData {
            yes,
            allow_active_e3s,
            if_schema_older,
        } => reset_data(out, config, yes, allow_active_e3s, if_schema_older).await,
        NodeCommands::Events { since, limit } => events(out, config, since, limit),
    }
}

fn events(out: Console, config: &NodeConfig, since: u64, limit: usize) -> Result<()> {
    for entry in e3_node::notes::read(&crate::node_state::dir(config).notes(), since, limit)? {
        log!(
            out,
            "{} {} E3 {}: {}",
            entry.sequence,
            entry.at,
            entry.note.e3,
            entry.note.event
        );
    }
    Ok(())
}

/// Reports on the node's keys and state, and writes nothing.
async fn validate(out: Console, config: &NodeConfig) -> Result<()> {
    let lock = config
        .db_file()
        .parent()
        .map(|dir| dir.join(LOCK_FILE_NAME));
    let _running = lock
        .filter(|lock| lock.exists())
        .map(|lock| ProcessFence::hold_existing(&lock))
        .transpose()?;
    if config.key_file().exists() && config.db_file().exists() {
        let cipher = Cipher::from_file(config.key_file()).await?;
        match keystore::read(&config.db_file(), &cipher)? {
            Some(keys) => log!(
                out,
                "keys: operator {}, peer {}",
                keys.address(),
                keys.peer_id()?
            ),
            None => log!(out, "keys: no wallet is set"),
        }
    } else {
        log!(out, "keys: no wallet is set");
    }
    let dir = node_state::dir(config);
    let folder = dir.path().display();
    match dir.state(None) {
        State::Absent => log!(out, "data: none yet"),
        State::Older(_) => {
            bail!("data: {folder} uses an older layout; reset it with `interfold node reset-data`")
        }
        State::Newer(_) => bail!("data: {folder} was written by a later release"),
        State::Foreign(_) => bail!("data: {folder} belongs to another node"),
        State::Unreadable(why) => bail!("data: {folder} cannot be read: {why}"),
        State::Current(manifest) => {
            let held = node_state::inspect_held(&dir, manifest.identity.operator)
                .with_context(|| format!("data: {folder}"))?;
            log!(out, "data: readable; the node holds {} E3(s)", held.len());
            for held in held {
                log!(out, "  {held}");
            }
        }
    }
    Ok(())
}

async fn reset_data(
    out: Console,
    config: &NodeConfig,
    yes: bool,
    allow_active_e3s: bool,
    if_schema_older: bool,
) -> Result<()> {
    let dir = node_state::dir(config);
    let folder = dir.path().to_path_buf();
    if !yes {
        bail!(
            "This deletes the data of node '{}' at {}. The operator and network keys stay. Stop \
             the node, then run this command again with --yes.",
            config.name(),
            folder.display()
        );
    }
    // Only an older layout is safe to reset unasked: a package runs this before every start, and
    // newer, foreign or unreadable state is not this binary's to delete.
    if if_schema_older && !matches!(dir.state(None), State::Older(_)) {
        log!(
            out,
            "The data does not use an older layout. Nothing to reset."
        );
        return Ok(());
    }
    let mut fences = vec![ProcessFence::acquire(&config.db_file(), &config.name())?];
    // Also what a volume that is not mounted looks like, so the list keeps naming the folder.
    if dir.state(None) == State::Absent {
        log!(out, "The node has no data. Nothing to reset.");
        return Ok(());
    }
    let mut plan = Plan::default();
    for (name, credential) in [("key", config.key_file()), ("keystore", config.db_file())] {
        let inside = credential.starts_with(&folder)
            || node_state::canonical(&credential).starts_with(node_state::canonical(&folder));
        if inside {
            plan.refusals.push(format!(
                "the node's {name} at {} is inside the folder this deletes; move it out first",
                credential.display()
            ));
        }
    }
    plan.check(&format!("node '{}'", config.name()), &dir);
    // Another node's `data_dir` may sit inside this folder: it is fenced, and its journal checked.
    let others = node_state::guard(&folder, &[config.node_data_dir()], &mut fences)?.unchecked;
    plan.blockers.extend(others.iter().map(|other| {
        format!(
            "{} holds the journal of another node, whose E3s this command cannot check; move it \
             out first",
            other.display()
        )
    }));
    plan.settle(&out, allow_active_e3s)?;
    std::fs::remove_dir_all(&folder)?;
    node_state::inventory(config).forget(&folder)?;
    log!(out, "Removed {}", folder.display());
    log!(
        out,
        "The operator and network keys stay. Verify with: interfold wallet get --name {}",
        config.name()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::reset_data;
    use crate::node_state;
    use anyhow::Result;
    use e3_ciphernode_config::NodeConfig;
    use e3_cli::app_config::load_config;
    use e3_console::Console;

    fn node(dir: &std::path::Path) -> Result<NodeConfig> {
        let config_file = dir.join("config.yaml");
        std::fs::write(&config_file, "node:\n  network: local\n")?;
        Ok(load_config(
            "_default",
            Some(config_file.to_string_lossy().into_owned()),
            None,
        )?
        .node)
    }

    async fn reset(config: &NodeConfig, allow_active_e3s: bool) -> Result<()> {
        let (out, _messages) = Console::channel();
        reset_data(out, config, true, allow_active_e3s, true).await
    }

    const IDENTITY: &str = r#""chain_id":1,"interfold":"0x0000000000000000000000000000000000000001","operator":"0x0000000000000000000000000000000000000002""#;

    /// A node folder whose manifest says `encoding`, `store`.
    fn folder_of(config: &NodeConfig, encoding: u32, store: u32) -> Result<std::path::PathBuf> {
        let folder = node_state::dir(config).path().to_path_buf();
        std::fs::create_dir_all(&folder)?;
        std::fs::write(
            folder.join("manifest.json"),
            format!(r#"{{"encoding":{encoding},"store":{store},{IDENTITY}}}"#),
        )?;
        Ok(folder)
    }

    fn older_folder(config: &NodeConfig) -> Result<std::path::PathBuf> {
        folder_of(config, 0, 0)
    }

    /// A package runs the reset before every start: after a rollback it must leave newer data
    /// alone, and then the node refuses to start on it.
    #[tokio::test]
    async fn newer_data_is_not_reset_by_a_package() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = node(dir.path())?;
        let folder = folder_of(&config, u32::MAX, 0)?;
        std::fs::write(folder.join("journal.redb"), b"data")?;
        reset(&config, false).await?;
        assert!(folder.join("journal.redb").exists());
        Ok(())
    }

    /// Asked directly, a reset still refuses state it cannot read.
    #[tokio::test]
    async fn state_this_binary_cannot_read_stops_a_direct_reset() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = node(dir.path())?;
        let folder = folder_of(&config, u32::MAX, 0)?;
        let (out, _messages) = Console::channel();
        let error = reset_data(out, &config, true, false, false)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("later release"), "{error:#}");
        assert!(folder.exists());
        Ok(())
    }

    /// The reset promises that the keys stay, so a key configured inside its folder stops it,
    /// override or not.
    #[tokio::test]
    async fn a_key_inside_the_folder_stops_the_reset_even_with_the_override() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let folder = dir.path().join(".interfold/data/_default/v2");
        let config_file = dir.path().join("config.yaml");
        std::fs::write(
            &config_file,
            format!(
                "node:\n  network: local\n  key_file: {}\n",
                folder.join("key").display()
            ),
        )?;
        let config = load_config(
            "_default",
            Some(config_file.to_string_lossy().into_owned()),
            None,
        )?
        .node;
        let folder = node_state::dir(&config).path().to_path_buf();
        if !config.key_file().starts_with(&folder) {
            return Ok(());
        }
        folder_of(&config, 0, 0)?;
        std::fs::write(config.key_file(), b"key")?;
        let error = reset(&config, true).await.unwrap_err();
        assert!(error.to_string().contains("inside the folder"), "{error:#}");
        assert!(config.key_file().exists());
        Ok(())
    }

    /// An empty folder the list names may be a volume that is not mounted.
    #[tokio::test]
    async fn an_empty_folder_stays_on_the_list() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = node(dir.path())?;
        let folder = node_state::dir(&config).path().to_path_buf();
        std::fs::create_dir_all(&folder)?;
        node_state::inventory(&config).record(&folder)?;
        let (out, _messages) = Console::channel();
        reset_data(out, &config, true, false, false).await?;
        assert_eq!(node_state::inventory(&config).read().folders, [folder]);
        Ok(())
    }

    /// The same key by another path: the node's folder is reached through a link.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_key_inside_the_folder_by_another_path_stops_the_reset() -> Result<()> {
        let (dir, physical) = (tempfile::tempdir()?, tempfile::tempdir()?);
        let config = node(dir.path())?;
        let folder = node_state::dir(&config).path().to_path_buf();
        std::fs::create_dir_all(folder.parent().unwrap())?;
        std::os::unix::fs::symlink(physical.path(), &folder)?;
        std::fs::write(
            physical.path().join("manifest.json"),
            format!(r#"{{"encoding":0,"store":0,{IDENTITY}}}"#),
        )?;
        std::fs::write(physical.path().join("key"), b"key")?;
        let config_file = dir.path().join("elsewhere.yaml");
        std::fs::write(
            &config_file,
            format!(
                "node:\n  network: local\n  key_file: {}\n",
                physical.path().join("key").display()
            ),
        )?;
        let config = load_config(
            "_default",
            Some(config_file.to_string_lossy().into_owned()),
            None,
        )?
        .node;
        assert_eq!(node_state::dir(&config).path(), folder);
        let error = reset(&config, true).await.unwrap_err();
        assert!(error.to_string().contains("inside the folder"), "{error:#}");
        assert!(physical.path().join("key").exists());
        Ok(())
    }

    /// `validate` promises to leave a stopped node as it is, its journal included.
    #[tokio::test]
    async fn validate_changes_no_byte_of_the_journal() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = node(dir.path())?;
        let state = node_state::dir(&config);
        state.open(&e3_node::dir::Identity {
            chain_id: 1,
            interfold: alloy::primitives::Address::repeat_byte(1),
            operator: alloy::primitives::Address::repeat_byte(2),
        })?;
        drop(e3_journal::Journal::open(state.journal())?);
        let before = std::fs::read(state.journal())?;
        let (out, _messages) = Console::channel();
        super::validate(out, &config).await?;
        assert_eq!(std::fs::read(state.journal())?, before);
        Ok(())
    }

    /// A journal in an older layout, which this binary cannot read, may hold E3s that have not
    /// ended: the reset refuses unless told to go ahead.
    #[tokio::test]
    async fn a_journal_in_an_older_layout_is_kept_unless_the_reset_is_told() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = node(dir.path())?;
        let folder = older_folder(&config)?;
        std::fs::write(folder.join("journal.redb"), b"")?;

        let error = reset(&config, false).await.unwrap_err();
        assert!(error.to_string().contains("older layout"), "{error:#}");
        assert!(folder.exists());

        reset(&config, true).await?;
        assert!(!folder.exists());
        Ok(())
    }

    /// Another node whose data folder sits inside this one's is not this command's to delete.
    #[tokio::test]
    async fn another_node_inside_the_folder_stops_the_reset() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = node(dir.path())?;
        let folder = older_folder(&config)?;
        let other = folder.join("other/v2/journal.redb");
        std::fs::create_dir_all(other.parent().unwrap())?;
        std::fs::write(&other, b"")?;

        let error = reset(&config, false).await.unwrap_err();
        assert!(error.to_string().contains("other"), "{error:#}");
        assert!(other.exists());
        Ok(())
    }
}
