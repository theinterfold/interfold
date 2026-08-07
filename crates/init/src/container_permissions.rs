// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::path::{Path, PathBuf};

/// Permission mode for the directories that the support container writes to.
///
/// The capital `X` adds the execute bit to directories only. Plain files do not
/// get the execute bit. A directory needs it to stay traversable. Solidity and
/// TypeScript sources do not need it.
pub const CONTAINER_WRITABLE_MODE: &str = "a+rwX";

/// UID of `devuser` in the support container image.
///
/// `crates/support/Dockerfile` sets this UID at build time. The CLI pulls the
/// image prebuilt, so a user cannot rebuild it with a different UID.
const SUPPORT_CONTAINER_UID: u32 = 1000;

/// Reports whether the project files need wider permissions for the container.
///
/// Only Linux keeps host ownership on a bind mount. If the owner is already the
/// container user, the default modes are sufficient.
pub async fn needs_permission_widening(cwd: &Path) -> anyhow::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let owner_uid = tokio::fs::metadata(cwd).await?.uid();
    Ok(widening_needed(cfg!(target_os = "linux"), owner_uid))
}

fn widening_needed(host_uids_reach_container: bool, owner_uid: u32) -> bool {
    host_uids_reach_container && owner_uid != SUPPORT_CONTAINER_UID
}

/// Lists the directories that the support container mounts read-write.
///
/// The RISC Zero build script in `crates/support/methods/build.rs` writes
/// `ImageID.sol` to `../contracts` and `Elf.sol` to `../tests`, both relative
/// to `/app`. `ctl/container` maps these two paths to
/// `.interfold/generated/contracts` and `tests` on the host.
pub fn container_writable_paths(cwd: &Path) -> Vec<PathBuf> {
    vec![
        cwd.join(".interfold").join("generated").join("contracts"),
        cwd.join("tests"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn writable_paths_are_the_directories_the_container_mounts() {
        let cwd = Path::new("/proj");
        let paths = container_writable_paths(cwd);

        assert!(paths.contains(&cwd.join(".interfold/generated/contracts")));
        assert!(paths.contains(&cwd.join("tests")));
    }

    #[test]
    fn the_projects_own_contracts_folder_is_not_widened() {
        let cwd = Path::new("/proj");
        let paths = container_writable_paths(cwd);

        // `contracts/` holds the project's own Solidity sources. Neither
        // `ctl/container` nor `support/scripts/dev.sh` mounts it into the
        // container. Wider permissions there give access that nothing needs.
        assert!(!paths.contains(&cwd.join("contracts")));
    }

    #[test]
    fn no_widening_when_the_container_user_already_owns_the_files() {
        assert!(!widening_needed(true, SUPPORT_CONTAINER_UID));
    }

    #[test]
    fn widening_when_the_owner_differs_from_the_container_user() {
        assert!(widening_needed(true, SUPPORT_CONTAINER_UID + 1));
    }

    #[test]
    fn no_widening_when_the_platform_maps_ownership() {
        // Docker Desktop translates ownership in its file-sharing layer. A
        // different UID never reaches the container.
        assert!(!widening_needed(false, SUPPORT_CONTAINER_UID + 1));
    }

    #[tokio::test]
    async fn writable_mode_keeps_directories_traversable() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let nested = root.path().join("nested");
        tokio::fs::create_dir(&nested).await?;

        crate::file_utils::chmod_recursive(root.path(), CONTAINER_WRITABLE_MODE).await?;

        // Without the execute bit, no process can enter a directory. The
        // container cannot then reach the files inside it.
        assert_eq!(mode_of(&nested).await? & 0o111, 0o111);
        assert_eq!(mode_of(&nested).await? & 0o222, 0o222);
        Ok(())
    }

    #[tokio::test]
    async fn writable_mode_does_not_mark_sources_executable() -> anyhow::Result<()> {
        let root = tempfile::tempdir()?;
        let source = root.path().join("MyProgram.sol");
        tokio::fs::write(&source, "// contract").await?;

        crate::file_utils::chmod_recursive(root.path(), CONTAINER_WRITABLE_MODE).await?;

        // Solidity sources are not programs. `777` set the execute bit on
        // every source file. The template still carries `100755` blobs from
        // an earlier run.
        assert_eq!(mode_of(&source).await? & 0o111, 0);
        assert_eq!(mode_of(&source).await? & 0o222, 0o222);
        Ok(())
    }

    async fn mode_of(path: &Path) -> anyhow::Result<u32> {
        use std::os::unix::fs::PermissionsExt;
        Ok(tokio::fs::metadata(path).await?.permissions().mode() & 0o777)
    }
}
