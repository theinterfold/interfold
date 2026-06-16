// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use path_clean::clean;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
pub struct PathsEngine {
    name: String,
    /// Config dir override. This allows us to set specific config_dir location in the config file
    /// wherever that is. This will locate the `key` file
    config_dir_override: Option<PathBuf>,
    /// Configuration file as found derived from the passed in arg eg. `--config`
    /// If this is set it will always be a fully qualified path as this will be the result of
    /// searching through the filesystem.
    found_config_file: Option<PathBuf>,
    /// Data dir override. This allows us to set specific data_dir location in the config file
    /// wherever that is. This will locate the `db` file
    data_dir_override: Option<PathBuf>,
    /// This can either be a fully qualified path to a specific db file or a relative path to the
    /// data_dir location
    db_file_override: Option<PathBuf>,
    /// This should be a fully qualified path to a specific bb executable
    bb_file_override: Option<PathBuf>,
    /// This can either be a fully qualified path to a specific log file or a relative path to the
    /// data_dir location
    log_file_override: Option<PathBuf>,
    /// This can either be a fully qualified path to a specific key file or a relative path to the
    /// config_dir location
    key_file_override: Option<PathBuf>,
    /// Input from the OS as to where the default data dir is
    default_data_dir: PathBuf,
    /// Input from the OS as to where the default config dir is
    default_config_dir: PathBuf,
    /// A reference to the cwd
    cwd: PathBuf,
}

pub const DEFAULT_CONFIG_NAME: &str = "interfold.config.yaml";
pub const DEFAULT_KEY_NAME: &str = "key";
pub const DEFAULT_DB_NAME: &str = "db";
pub const DEFAULT_LOG_NAME: &str = "log";

// Find the config file is specified anywhere upstream from cwd and if found then locate the
// data and config folders under .interfold/data and .interfold/config relative to the location of
// the config file. Otherwise locate config in the default app configuration folder and data in
// the default app data folder.
impl PathsEngine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        cwd: &PathBuf,
        default_data_dir: &PathBuf,
        default_config_dir: &PathBuf,
        found_config_file: Option<&PathBuf>,
        config_dir_override: Option<&PathBuf>,
        data_dir_override: Option<&PathBuf>,
        db_file_override: Option<&PathBuf>,
        key_file_override: Option<&PathBuf>,
        log_file_override: Option<&PathBuf>,
        bb_file_override: Option<&PathBuf>,
    ) -> Self {
        Self {
            name: name.to_owned(),
            cwd: PathBuf::from(cwd),
            default_data_dir: PathBuf::from(default_data_dir),
            default_config_dir: PathBuf::from(default_config_dir),
            config_dir_override: config_dir_override.map(PathBuf::from),
            found_config_file: found_config_file.map(PathBuf::from),
            data_dir_override: data_dir_override.map(PathBuf::from),
            db_file_override: db_file_override.map(PathBuf::from),
            key_file_override: key_file_override.map(PathBuf::from),
            log_file_override: log_file_override.map(PathBuf::from),
            bb_file_override: bb_file_override.map(PathBuf::from),
        }
    }

    /// Full path to the config file that will be loaded
    pub fn config_file(&self) -> PathBuf {
        if let Some(file) = self.found_config_file.clone() {
            return clean(file);
        }
        clean(self.default_config_dir.join(DEFAULT_CONFIG_NAME))
    }

    /// Returns true if the config file is the default config file (i.e., not a custom path)
    pub fn is_default_config_file(&self) -> bool {
        let default_path = clean(self.default_config_dir.join(DEFAULT_CONFIG_NAME));
        self.config_file() == default_path
    }

    /// Full path to the key file containing secret key
    pub fn key_file(&self) -> PathBuf {
        if let Some(key_file) = self.key_file_override.clone() {
            if key_file.is_absolute() {
                return clean(key_file);
            } else {
                return clean(self.get_config_dir().join(&self.name).join(key_file));
            }
        }

        clean(
            self.get_config_dir()
                .join(&self.name)
                .join(DEFAULT_KEY_NAME),
        )
    }

    /// Full path to the database file containing the db
    pub fn db_file(&self) -> PathBuf {
        if let Some(data_file) = self.db_file_override.clone() {
            if data_file.is_absolute() {
                return clean(data_file);
            } else {
                return clean(self.get_data_dir().join(&self.name).join(data_file));
            }
        }

        clean(self.get_data_dir().join(&self.name).join(DEFAULT_DB_NAME))
    }

    pub fn log_file(&self) -> PathBuf {
        if let Some(log_file) = self.log_file_override.clone() {
            if log_file.is_absolute() {
                return clean(log_file);
            } else {
                return clean(self.get_data_dir().join(&self.name).join(log_file));
            }
        }
        clean(self.get_data_dir().join(&self.name).join(DEFAULT_LOG_NAME))
    }

    pub fn relative_to_config(&self, path: &PathBuf) -> PathBuf {
        if path.is_absolute() {
            return PathBuf::from(path);
        }

        let config_file = self.config_file();

        // Most of the time the config_file will be in a folder
        // In case it is not use the cwd
        let relative_from = config_file.parent().unwrap_or(&self.cwd);

        clean(PathBuf::from(relative_from).join(path))
    }

    fn get_config_dir(&self) -> PathBuf {
        if let Some(config_dir) = self.config_dir_override.clone() {
            return config_dir;
        }
        if let Some(root_dir) = self.get_root_dir() {
            return root_dir.join("config");
        }

        self.default_config_dir.clone()
    }

    fn get_data_dir(&self) -> PathBuf {
        if let Some(data_dir) = self.data_dir_override.clone() {
            return data_dir;
        }

        if let Some(root_dir) = self.get_root_dir() {
            return root_dir.join("data");
        }

        self.default_data_dir.clone()
    }

    fn get_root_dir(&self) -> Option<PathBuf> {
        if let Some(file) = self.found_config_file.clone() {
            if let Some(parent) = file.parent() {
                return Some(PathBuf::from(parent).join(".interfold"));
            }
        }
        None
    }

    fn get_noir_base(&self) -> PathBuf {
        if let Some(root_dir) = self.get_root_dir() {
            return root_dir;
        }
        // Fallback to .interfold relative to default config dir (e.g., ~/.config/interfold/.interfold)
        self.default_config_dir.join(".interfold")
    }

    /// Get the noir base directory for ZK circuits and prover
    pub fn noir_dir(&self) -> PathBuf {
        clean(self.get_noir_base().join("noir"))
    }

    /// Get the bb binary path
    pub fn bb_binary(&self) -> PathBuf {
        if let Some(bb_file) = self.bb_file_override.clone() {
            if bb_file.is_absolute() {
                return clean(bb_file);
            } else {
                return clean(self.noir_dir().join(bb_file));
            }
        }
        clean(self.noir_dir().join("bin").join("bb"))
    }

    /// Get the circuits directory (shared across nodes)
    pub fn circuits_dir(&self) -> PathBuf {
        clean(self.noir_dir().join("circuits"))
    }

    /// Get the work directory for a specific node
    pub fn work_dir(&self, node_name: &str) -> PathBuf {
        clean(self.noir_dir().join("work").join(node_name))
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use super::PathsEngine;

    // Helper structs for the table test
    struct TestCase {
        name: &'static str,
        input: PathsInput,
        expected: PathsExpected,
    }

    struct PathsInput {
        name: &'static str,
        cwd: &'static str,
        default_data_dir: &'static str,
        default_config_dir: &'static str,
        config_dir_override: Option<&'static str>,
        found_config_file: Option<&'static str>,
        data_dir_override: Option<&'static str>,
        db_file_override: Option<&'static str>,
        log_file_override: Option<&'static str>,
        key_file_override: Option<&'static str>,
        bb_file_override: Option<&'static str>,
    }

    struct PathsExpected {
        config_file: &'static str,
        key_file: &'static str,
        db_file: &'static str,
        log_file: &'static str,
        bb_file: &'static str,
        noir_dir: &'static str,
        circuits_dir: &'static str,
        work_dir: &'static str,
    }

    fn test_cases(test_cases: Vec<TestCase>) {
        // Run all test cases
        for test_case in test_cases {
            println!("Running test case: {}", test_case.name);

            // Convert string inputs to PathBufs
            let default_data_dir = PathBuf::from(test_case.input.default_data_dir);
            let default_config_dir = PathBuf::from(test_case.input.default_config_dir);
            let config_dir = test_case.input.config_dir_override.map(PathBuf::from);
            let config_file = test_case.input.found_config_file.map(PathBuf::from);
            let data_dir_override = test_case.input.data_dir_override.map(PathBuf::from);
            let db_file = test_case.input.db_file_override.map(PathBuf::from);
            let key_file = test_case.input.key_file_override.map(PathBuf::from);
            let log_file = test_case.input.log_file_override.map(PathBuf::from);
            let bb_file = test_case.input.bb_file_override.map(PathBuf::from);
            let cwd = PathBuf::from(test_case.input.cwd);

            let paths = PathsEngine::new(
                test_case.input.name,
                &cwd,
                &default_data_dir,
                &default_config_dir,
                config_file.as_ref(),
                config_dir.as_ref(),
                data_dir_override.as_ref(),
                db_file.as_ref(),
                key_file.as_ref(),
                log_file.as_ref(),
                bb_file.as_ref(),
            );

            assert_eq!(
                paths.config_file(),
                PathBuf::from(test_case.expected.config_file),
                "Failed config_file assertion for test case: {}",
                test_case.name
            );
            assert_eq!(
                paths.key_file(),
                PathBuf::from(test_case.expected.key_file),
                "Failed key_file assertion for test case: {}",
                test_case.name
            );
            assert_eq!(
                paths.db_file(),
                PathBuf::from(test_case.expected.db_file),
                "Failed db_file assertion for test case: {}",
                test_case.name
            );

            assert_eq!(
                paths.log_file(),
                PathBuf::from(test_case.expected.log_file),
                "Failed log_file assertion for test case: {}",
                test_case.name
            );

            assert_eq!(
                paths.bb_binary(),
                PathBuf::from(test_case.expected.bb_file),
                "Failed bb_file assertion for test case: {}",
                test_case.name
            );

            assert_eq!(
                paths.noir_dir(),
                PathBuf::from(test_case.expected.noir_dir),
                "Failed noir_dir assertion for test case: {}",
                test_case.name
            );

            assert_eq!(
                paths.circuits_dir(),
                PathBuf::from(test_case.expected.circuits_dir),
                "Failed circuits_dir assertion for test case: {}",
                test_case.name
            );

            assert_eq!(
                paths.work_dir(test_case.input.name),
                PathBuf::from(test_case.expected.work_dir),
                "Failed work_dir assertion for test case: {}",
                test_case.name
            );
        }
    }

    #[test]
    fn test_all() {
        test_cases(vec![
            TestCase {
                name: "Defaults",
                input: PathsInput {
                    name: "_default",
                    cwd: "/no/matter",
                    default_data_dir: "/home/user/.local/share/interfold",
                    default_config_dir: "/home/user/.config/interfold",
                    config_dir_override: None,
                    found_config_file: None,
                    data_dir_override: None,
                    db_file_override: None,
                    key_file_override: None,
                    log_file_override: None,
                    bb_file_override: None,
                },
                expected: PathsExpected {
                    config_file: "/home/user/.config/interfold/interfold.config.yaml",
                    key_file: "/home/user/.config/interfold/_default/key",
                    db_file: "/home/user/.local/share/interfold/_default/db",
                    log_file: "/home/user/.local/share/interfold/_default/log",
                    bb_file: "/home/user/.config/interfold/.interfold/noir/bin/bb",
                    noir_dir: "/home/user/.config/interfold/.interfold/noir",
                    circuits_dir: "/home/user/.config/interfold/.interfold/noir/circuits",
                    work_dir: "/home/user/.config/interfold/.interfold/noir/work/_default",
                },
            },
            TestCase {
                name: "Config file found",
                input: PathsInput {
                    name: "_default",
                    cwd: "/no/matter",
                    default_data_dir: "/home/user/.local/share/interfold/data",
                    default_config_dir: "/home/user/.config/interfold/config",
                    config_dir_override: None,
                    found_config_file: Some("/foo/some.config.yaml"),
                    data_dir_override: None,
                    db_file_override: None,
                    key_file_override: None,
                    log_file_override: None,
                    bb_file_override: None,
                },
                expected: PathsExpected {
                    config_file: "/foo/some.config.yaml",
                    key_file: "/foo/.interfold/config/_default/key",
                    db_file: "/foo/.interfold/data/_default/db",
                    log_file: "/foo/.interfold/data/_default/log",
                    bb_file: "/foo/.interfold/noir/bin/bb",
                    noir_dir: "/foo/.interfold/noir",
                    circuits_dir: "/foo/.interfold/noir/circuits",
                    work_dir: "/foo/.interfold/noir/work/_default",
                },
            },
            TestCase {
                name: "Data dir override",
                input: PathsInput {
                    name: "_default",
                    cwd: "/no/matter",
                    default_data_dir: "/home/user/.local/share/interfold/data",
                    default_config_dir: "/home/user/.config/interfold/config",
                    config_dir_override: None,
                    found_config_file: Some("/foo/some.config.yaml"),
                    data_dir_override: Some("/path/to/data"),
                    db_file_override: None,
                    key_file_override: None,
                    log_file_override: None,
                    bb_file_override: None,
                },
                expected: PathsExpected {
                    config_file: "/foo/some.config.yaml",
                    key_file: "/foo/.interfold/config/_default/key",
                    db_file: "/path/to/data/_default/db",
                    log_file: "/path/to/data/_default/log",
                    bb_file: "/foo/.interfold/noir/bin/bb",
                    noir_dir: "/foo/.interfold/noir",
                    circuits_dir: "/foo/.interfold/noir/circuits",
                    work_dir: "/foo/.interfold/noir/work/_default",
                },
            },
            TestCase {
                name: "Config dir override",
                input: PathsInput {
                    name: "_default",
                    cwd: "/no/matter",
                    default_data_dir: "/home/user/.local/share/interfold/data",
                    default_config_dir: "/home/user/.config/interfold/config",
                    config_dir_override: Some("/confy/stuff"),
                    found_config_file: Some("/foo/some.config.yaml"),
                    data_dir_override: Some("/path/to/data"),
                    db_file_override: None,
                    key_file_override: None,
                    log_file_override: None,
                    bb_file_override: None,
                },
                expected: PathsExpected {
                    config_file: "/foo/some.config.yaml",
                    key_file: "/confy/stuff/_default/key",
                    db_file: "/path/to/data/_default/db",
                    log_file: "/path/to/data/_default/log",
                    bb_file: "/foo/.interfold/noir/bin/bb",
                    noir_dir: "/foo/.interfold/noir",
                    circuits_dir: "/foo/.interfold/noir/circuits",
                    work_dir: "/foo/.interfold/noir/work/_default",
                },
            },
            TestCase {
                name: "Key file override absolute",
                input: PathsInput {
                    cwd: "/no/matter",
                    name: "_default",
                    default_data_dir: "/home/user/.local/share/interfold/data",
                    default_config_dir: "/home/user/.config/interfold/config",
                    config_dir_override: Some("/confy/stuff"),
                    found_config_file: Some("/foo/some.config.yaml"),
                    data_dir_override: Some("/path/to/data"),
                    db_file_override: None,
                    key_file_override: Some("/ding/bat/key_file"),
                    log_file_override: None,
                    bb_file_override: None,
                },
                expected: PathsExpected {
                    config_file: "/foo/some.config.yaml",
                    key_file: "/ding/bat/key_file",
                    db_file: "/path/to/data/_default/db",
                    log_file: "/path/to/data/_default/log",
                    bb_file: "/foo/.interfold/noir/bin/bb",
                    noir_dir: "/foo/.interfold/noir",
                    circuits_dir: "/foo/.interfold/noir/circuits",
                    work_dir: "/foo/.interfold/noir/work/_default",
                },
            },
            TestCase {
                name: "Key file override relative",
                input: PathsInput {
                    cwd: "/no/matter",
                    name: "_default",
                    default_data_dir: "/home/user/.local/share/interfold/data",
                    default_config_dir: "/home/user/.config/interfold/config",
                    config_dir_override: Some("/confy/stuff"),
                    found_config_file: Some("/foo/some.config.yaml"),
                    data_dir_override: Some("/path/to/data"),
                    db_file_override: None,
                    key_file_override: Some("../bat/key_file"),
                    log_file_override: None,
                    bb_file_override: None,
                },

                expected: PathsExpected {
                    config_file: "/foo/some.config.yaml",
                    key_file: "/confy/stuff/bat/key_file",
                    db_file: "/path/to/data/_default/db",
                    log_file: "/path/to/data/_default/log",
                    bb_file: "/foo/.interfold/noir/bin/bb",
                    noir_dir: "/foo/.interfold/noir",
                    circuits_dir: "/foo/.interfold/noir/circuits",
                    work_dir: "/foo/.interfold/noir/work/_default",
                },
            },
            TestCase {
                name: "Data file override absolute",
                input: PathsInput {
                    cwd: "/no/matter",
                    name: "_default",
                    default_data_dir: "/home/user/.local/share/interfold/data",
                    default_config_dir: "/home/user/.config/interfold/config",
                    config_dir_override: Some("/confy/stuff"),
                    found_config_file: Some("/foo/some.config.yaml"),
                    data_dir_override: Some("/path/to/data"),
                    db_file_override: Some("/ding/blat/foo/my/data"),
                    key_file_override: Some("../bat/key_file"),
                    log_file_override: Some("../ding/loggy"),
                    bb_file_override: None,
                },
                expected: PathsExpected {
                    config_file: "/foo/some.config.yaml",
                    key_file: "/confy/stuff/bat/key_file",
                    db_file: "/ding/blat/foo/my/data",
                    log_file: "/path/to/data/ding/loggy",
                    bb_file: "/foo/.interfold/noir/bin/bb",
                    noir_dir: "/foo/.interfold/noir",
                    circuits_dir: "/foo/.interfold/noir/circuits",
                    work_dir: "/foo/.interfold/noir/work/_default",
                },
            },
            TestCase {
                name: "Data file override relative",
                input: PathsInput {
                    name: "_default",
                    cwd: "/no/matter",
                    default_data_dir: "/home/user/.local/share/interfold/data",
                    default_config_dir: "/home/user/.config/interfold/config",
                    config_dir_override: Some("/confy/stuff"),
                    found_config_file: Some("/foo/some.config.yaml"),
                    data_dir_override: Some("/path/to/data"),
                    db_file_override: Some("../../yes"),
                    key_file_override: Some("../bat/key_file"),
                    log_file_override: None,
                    bb_file_override: None,
                },
                expected: PathsExpected {
                    config_file: "/foo/some.config.yaml",
                    key_file: "/confy/stuff/bat/key_file",
                    db_file: "/path/to/yes",
                    log_file: "/path/to/data/_default/log",
                    bb_file: "/foo/.interfold/noir/bin/bb",
                    noir_dir: "/foo/.interfold/noir",
                    circuits_dir: "/foo/.interfold/noir/circuits",
                    work_dir: "/foo/.interfold/noir/work/_default",
                },
            },
            TestCase {
                name: "BB file override absolute",
                input: PathsInput {
                    name: "_default",
                    cwd: "/no/matter",
                    default_data_dir: "/home/user/.local/share/interfold/data",
                    default_config_dir: "/home/user/.config/interfold/config",
                    config_dir_override: None,
                    found_config_file: Some("/foo/some.config.yaml"),
                    data_dir_override: None,
                    db_file_override: None,
                    key_file_override: None,
                    log_file_override: None,
                    bb_file_override: Some("/custom/bin/bb"),
                },
                expected: PathsExpected {
                    config_file: "/foo/some.config.yaml",
                    key_file: "/foo/.interfold/config/_default/key",
                    db_file: "/foo/.interfold/data/_default/db",
                    log_file: "/foo/.interfold/data/_default/log",
                    bb_file: "/custom/bin/bb",
                    noir_dir: "/foo/.interfold/noir",
                    circuits_dir: "/foo/.interfold/noir/circuits",
                    work_dir: "/foo/.interfold/noir/work/_default",
                },
            },
            TestCase {
                name: "BB file override relative",
                input: PathsInput {
                    name: "_default",
                    cwd: "/no/matter",
                    default_data_dir: "/home/user/.local/share/interfold/data",
                    default_config_dir: "/home/user/.config/interfold/config",
                    config_dir_override: None,
                    found_config_file: Some("/foo/some.config.yaml"),
                    data_dir_override: None,
                    db_file_override: None,
                    key_file_override: None,
                    log_file_override: None,
                    bb_file_override: Some("../bb-binary"),
                },
                expected: PathsExpected {
                    config_file: "/foo/some.config.yaml",
                    key_file: "/foo/.interfold/config/_default/key",
                    db_file: "/foo/.interfold/data/_default/db",
                    log_file: "/foo/.interfold/data/_default/log",
                    bb_file: "/foo/.interfold/bb-binary",
                    noir_dir: "/foo/.interfold/noir",
                    circuits_dir: "/foo/.interfold/noir/circuits",
                    work_dir: "/foo/.interfold/noir/work/_default",
                },
            },
        ]);
    }

    #[test]
    fn test_is_default_config_file() {
        let default_data_dir = PathBuf::from("/home/user/.local/share/interfold");
        let default_config_dir = PathBuf::from("/home/user/.config/interfold");
        let cwd = PathBuf::from("/no/matter");

        // Test case 1: No found_config_file - should be default
        let paths = PathsEngine::new(
            "test",
            &cwd,
            &default_data_dir,
            &default_config_dir,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(paths.is_default_config_file());

        // Test case 2: found_config_file set to different path - not default
        let paths = PathsEngine::new(
            "test",
            &cwd,
            &default_data_dir,
            &default_config_dir,
            Some(&PathBuf::from("/foo/some.config.yaml")),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!paths.is_default_config_file());

        // Test case 3: found_config_file set to exact default path - should be default
        let paths = PathsEngine::new(
            "test",
            &cwd,
            &default_data_dir,
            &default_config_dir,
            Some(&PathBuf::from(
                "/home/user/.config/interfold/interfold.config.yaml",
            )),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(paths.is_default_config_file());

        // Test case 4: found_config_file set to same path with different representation - should be default
        let paths = PathsEngine::new(
            "test",
            &cwd,
            &default_data_dir,
            &default_config_dir,
            Some(&PathBuf::from(
                "/home/user/.config/interfold/./interfold.config.yaml",
            )),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(paths.is_default_config_file());
    }
}
