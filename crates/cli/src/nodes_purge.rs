// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{anyhow, bail, Result};
use e3_config::AppConfig;
use e3_entrypoint::nodes::purge::PurgeTargets;
use std::env;
use std::path::Path;

/// Delete the data and configuration of the local node set.
pub async fn execute(
    config: &AppConfig,
    config_file: Option<String>,
    yes: bool,
    allow_active_e3s: bool,
) -> Result<()> {
    let dir = env::current_dir()?;
    require_confirmation(
        yes,
        &format!(".interfold/data and .interfold/config in {}", dir.display()),
    )?;
    purge(config, config_file, &dir, allow_active_e3s).await
}

/// Refuses unless `--yes` confirms the deletion of `folders`.
pub(crate) fn require_confirmation(yes: bool, folders: &str) -> Result<()> {
    if !yes {
        bail!(
            "The command deletes {folders}, including each node's operator key and libp2p key. \
             Nothing can restore them. To clear a node's state and keep its identity, use \
             `interfold node reset-data`. Stop the nodes, then run this command again with --yes."
        );
    }
    Ok(())
}

/// Deletes the `.interfold` data and configuration folders in `dir`, with the checks of
/// `e3_entrypoint::nodes::purge`.
pub(crate) async fn purge(
    config: &AppConfig,
    config_file: Option<String>,
    dir: &Path,
    allow_active_e3s: bool,
) -> Result<()> {
    let nodes = node_configs(config, config_file)?;
    e3_entrypoint::nodes::purge::execute(&PurgeTargets::in_dir(dir), &nodes, allow_active_e3s).await
}

/// The configuration of each node profile, including `_default` and the active one, loaded the
/// way `nodes up` starts them.
fn node_configs(config: &AppConfig, config_file: Option<String>) -> Result<Vec<AppConfig>> {
    let mut names: Vec<&String> = config.nodes().keys().collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            e3_config::load_config(name, config_file.clone(), None).map_err(|error| {
                anyhow!(
                    "Could not load node profile `{name}`: {error:#}. The command deleted nothing."
                )
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::node_configs;
    use anyhow::Result;

    /// The purge checks every node profile, not only the one the command runs as.
    #[test]
    fn node_configs_loads_every_profile() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config_file = dir.path().join("config.yaml");
        std::fs::write(
            &config_file,
            "node:\n  network: local\nnodes:\n  cn1:\n    network: local\n  cn2:\n    network: local\n",
        )?;
        let config_file = Some(config_file.to_string_lossy().into_owned());
        let config = e3_config::load_config("cn1", config_file.clone(), None)?;

        let names: Vec<String> = node_configs(&config, config_file)?
            .iter()
            .map(|node| node.name())
            .collect();
        assert_eq!(names, ["_default", "cn1", "cn2"]);
        Ok(())
    }
}
