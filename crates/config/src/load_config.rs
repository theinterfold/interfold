// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::path::PathBuf;

use path_clean::clean;

pub type FindInParent = fn(&PathBuf, &str) -> Option<PathBuf>;

pub fn find_in_parent(path: &PathBuf, filename: &str) -> Option<PathBuf> {
    let mut current = PathBuf::from(path);

    loop {
        let file_path = current.join(filename);
        if file_path.exists() {
            return Some(file_path);
        }

        if !current.pop() {
            break;
        }
    }

    None
}

pub fn resolve_config_path<P: Into<PathBuf>>(
    find_in_parent: FindInParent,
    cwd: P,
    default_config_dir: P,
    default_filename: &str,
    cli_file: Option<P>,
) -> PathBuf {
    let cli_file: Option<PathBuf> = cli_file.map(Into::into);
    let default_config_dir = default_config_dir.into();
    let cwd = cwd.into();

    if let Some(cli_file) = cli_file {
        // config is passed in and is absolute
        if cli_file.is_absolute() {
            return cli_file;
        }

        // config is passed in and is relative
        return clean(cwd.join(cli_file));
    }

    // search from cwd
    if let Some(found) = find_in_parent(&cwd, default_filename) {
        return found;
    }

    // return default
    clean(default_config_dir.join(default_filename))
}

#[cfg(test)]
mod tests {
    use super::resolve_config_path;
    use anyhow::Result;
    use std::path::PathBuf;

    #[test]
    fn test_resolve_cli() -> Result<()> {
        fn not_found(_: &PathBuf, _: &str) -> Option<PathBuf> {
            None
        }
        fn found(_: &PathBuf, _: &str) -> Option<PathBuf> {
            Some(PathBuf::from("/foo/interfold.config.yaml"))
        }
        let path = resolve_config_path(
            not_found,
            PathBuf::from("/foo/bar"),
            PathBuf::from("/my/config"),
            "interfold.config.yaml",
            None,
        );

        assert_eq!(path, PathBuf::from("/my/config/interfold.config.yaml"));

        let path = resolve_config_path(
            found, // should be overridden by config attr
            PathBuf::from("/foo/bar"),
            PathBuf::from("/my/config"),
            "interfold.config.yaml",
            Some(PathBuf::from("/my/absolute/conf.yaml")),
        );

        assert_eq!(path, PathBuf::from("/my/absolute/conf.yaml"));

        let path = resolve_config_path(
            found, // should be overridden by config attr
            PathBuf::from("/foo/bar"),
            PathBuf::from("/my/config"),
            "interfold.config.yaml",
            None,
        );

        assert_eq!(path, PathBuf::from("/foo/interfold.config.yaml"));
        Ok(())
    }
}
