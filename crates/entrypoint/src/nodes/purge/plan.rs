// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Which locks the purge holds, which stores it checks, and which state it cannot check. The plan
//! is a function of the facts and has no side effects.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use super::facts::{
    ConfigEntry, DataEntry, Facts, FolderState, Link, Location, NodeFacts, Recorded,
};

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Plan {
    pub(super) locks: Vec<PlannedLock>,
    pub(super) stores: Vec<PlannedStore>,
    pub(super) unchecked: Vec<Unchecked>,
}

/// A process lock that the purge holds while it checks and deletes.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PlannedLock {
    pub(super) path: PathBuf,
    /// Every node that uses this lock.
    pub(super) nodes: Vec<String>,
    /// The lock's folder does not exist yet. The purge creates it in the data folder.
    pub(super) create: bool,
}

/// A store that the purge opens and checks.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PlannedStore {
    pub(super) db_file: PathBuf,
    pub(super) node: String,
    /// The store stands for a key file that the purge deletes, so it must hold the operator
    /// identity that the key protects.
    pub(super) needs_identity: bool,
}

/// State that the purge would delete but cannot check.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Unchecked {
    pub(super) node: String,
    pub(super) reason: Reason,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Reason {
    /// The purge would delete the node's key file or event log, but its store is not at this path.
    StoreNotFound(PathBuf),
    /// No configured node keeps its key file in this folder, and no node folder of the same name
    /// holds a store.
    UnknownKeyFolder(PathBuf),
    /// No configured node uses this file in the configuration folder as its key file.
    UnknownConfigFile(PathBuf),
    /// The link leads to neither a store nor a node folder that the purge checks.
    Link(PathBuf),
    /// The store record next to the key file names this store, and it is not there.
    RecordedStoreNotFound(PathBuf),
    /// The purge cannot read the store record at this path.
    UnreadableRecord(PathBuf),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::StoreNotFound(path) => write!(
                f,
                "the purge would delete its key file or event log, but its store is not at {}",
                path.display()
            ),
            Reason::UnknownKeyFolder(path) => write!(
                f,
                "no configured node keeps its key file in {}, and no node folder of that name holds \
                 a store",
                path.display()
            ),
            Reason::UnknownConfigFile(path) => write!(
                f,
                "no configured node uses {} as its key file",
                path.display()
            ),
            Reason::Link(path) => write!(
                f,
                "{} is a symbolic link to state that the purge does not check",
                path.display()
            ),
            Reason::RecordedStoreNotFound(path) => write!(
                f,
                "the node last started with the store {}, and the store is not there",
                path.display()
            ),
            Reason::UnreadableRecord(path) => write!(
                f,
                "the purge cannot read the store record {}, or inspect the store that it names",
                path.display()
            ),
        }
    }
}

/// The plan for the facts.
pub(super) fn plan(facts: &Facts) -> Plan {
    let mut planner = Planner::default();
    for node in facts.nodes.iter().filter(|node| node.in_scope) {
        planner.add_node(node);
    }
    let mut links = Vec::new();
    for entry in &facts.data {
        match entry {
            DataEntry::Folder {
                name,
                lock,
                stores,
                links: inner,
                ..
            } => {
                planner.add_folder_lock(lock, name);
                for store in stores {
                    planner.add_store(store, name, false);
                }
                links.extend(inner);
            }
            DataEntry::Link(link) => links.push(link),
        }
    }
    for entry in &facts.config {
        planner.add_config_entry(entry, facts);
    }
    // Links go last, so that the plan knows every lock and store that a link can lead to.
    for link in links {
        planner.add_link(link);
    }
    planner.plan
}

#[derive(Default)]
struct Planner {
    plan: Plan,
    /// Resolved lock and store paths, to the index of their plan entry.
    locks: HashMap<PathBuf, usize>,
    stores: HashMap<PathBuf, usize>,
}

impl Planner {
    fn add_node(&mut self, node: &NodeFacts) {
        match node.lock_folder {
            FolderState::Missing if node.lock_folder_in_data => {
                self.add_lock(&node.lock, &node.name, true)
            }
            FolderState::Missing => {}
            FolderState::Exists | FolderState::Purging => {
                self.add_lock(&node.lock, &node.name, false)
            }
        }
        // The store that the node last started with, which its record names, holds the operator
        // key; the store at the configured path is then checked for key shares only.
        let deletes_state = node.key_file_in_target || node.event_log_in_target;
        let recorded_elsewhere = matches!(
            &node.recorded,
            Recorded::Store { db_file, .. } if *db_file != node.db_file
        );
        if deletes_state {
            self.add_recorded(&node.recorded, &node.name, node.key_file_in_target);
        }
        match &node.store {
            Some(store) => self.add_store(
                store,
                &node.name,
                node.key_file_in_target && !recorded_elsewhere,
            ),
            // An earlier purge passed its checks, marked the folder, and stopped part of the way.
            // This purge finishes the deletion. The purge empties only folders in the data folder.
            None if node.lock_folder == FolderState::Purging && node.lock_folder_in_data => {}
            None if deletes_state && !recorded_elsewhere => {
                self.add_unchecked(&node.name, Reason::StoreNotFound(node.db_file.clone()))
            }
            None => {}
        }
    }

    /// Hold the lock of the store that a key file's record names, and check the store.
    fn add_recorded(&mut self, recorded: &Recorded, node: &str, needs_identity: bool) {
        match recorded {
            Recorded::Nothing => {}
            Recorded::Store {
                store: Some(store),
                lock,
                ..
            } => {
                self.add_lock(lock, node, false);
                self.add_store(store, node, needs_identity);
            }
            Recorded::Store {
                store: None,
                db_file,
                ..
            } => self.add_unchecked(node, Reason::RecordedStoreNotFound(db_file.clone())),
            Recorded::Unreadable(path) => {
                self.add_unchecked(node, Reason::UnreadableRecord(path.clone()))
            }
        }
    }

    fn add_config_entry(&mut self, entry: &ConfigEntry, facts: &Facts) {
        match entry {
            ConfigEntry::Folder {
                name,
                location,
                records,
            } => {
                let configured = facts
                    .nodes
                    .iter()
                    .any(|node| node.key_file.parent() == Some(location.resolved.as_path()));
                if configured {
                    return;
                }
                // A key file in the folder with a record is checked through the store that the
                // record names, before the store of a node folder of the same name.
                if !records.is_empty() {
                    for (_, recorded) in records {
                        self.add_recorded(recorded, name, true);
                    }
                    return;
                }
                // A node folder of the same name must hold the store that the key protects, or be
                // the marked leftover of an earlier purge that checked it.
                match node_folder_store(facts, name) {
                    Some(store) => self.require_identity(&store.resolved),
                    None if node_folder_marked(facts, name) => {}
                    None => {
                        self.add_unchecked(name, Reason::UnknownKeyFolder(location.path.clone()))
                    }
                }
            }
            ConfigEntry::File {
                name,
                location,
                recorded,
            } => {
                let configured = facts
                    .nodes
                    .iter()
                    .any(|node| node.key_file == location.located);
                if configured {
                    return;
                }
                // A key file that no configured node uses is checked through its record.
                match recorded {
                    Recorded::Nothing => {
                        self.add_unchecked(name, Reason::UnknownConfigFile(location.path.clone()))
                    }
                    recorded => self.add_recorded(recorded, name, true),
                }
            }
        }
    }

    fn add_link(&mut self, link: &Link) {
        // A link that points to nothing leads to no state.
        let Some(target) = &link.target else {
            return;
        };
        let leads_to_checked_state = self.stores.contains_key(target)
            || self
                .locks
                .keys()
                .any(|lock| lock.parent() == Some(target.as_path()));
        if !leads_to_checked_state {
            self.add_unchecked(&link.node, Reason::Link(link.path.clone()));
        }
    }

    fn add_lock(&mut self, lock: &Location, node: &str, create: bool) {
        match self.locks.get(&lock.resolved) {
            Some(&index) => {
                let planned = &mut self.plan.locks[index];
                if !planned.nodes.iter().any(|name| name == node) {
                    planned.nodes.push(node.to_string());
                }
            }
            None => {
                self.locks
                    .insert(lock.resolved.clone(), self.plan.locks.len());
                self.plan.locks.push(PlannedLock {
                    path: lock.path.clone(),
                    nodes: vec![node.to_string()],
                    create,
                });
            }
        }
    }

    /// The lock of a node folder. The folder's name is the node's name only when no configured
    /// node uses the lock.
    fn add_folder_lock(&mut self, lock: &Location, name: &str) {
        if !self.locks.contains_key(&lock.resolved) {
            self.add_lock(lock, name, false);
        }
    }

    fn add_store(&mut self, store: &Location, node: &str, needs_identity: bool) {
        match self.stores.get(&store.resolved) {
            Some(&index) => self.plan.stores[index].needs_identity |= needs_identity,
            None => {
                self.stores
                    .insert(store.resolved.clone(), self.plan.stores.len());
                self.plan.stores.push(PlannedStore {
                    db_file: store.path.clone(),
                    node: node.to_string(),
                    needs_identity,
                });
            }
        }
    }

    fn require_identity(&mut self, store: &Path) {
        if let Some(&index) = self.stores.get(store) {
            self.plan.stores[index].needs_identity = true;
        }
    }

    fn add_unchecked(&mut self, node: &str, reason: Reason) {
        self.plan.unchecked.push(Unchecked {
            node: node.to_string(),
            reason,
        });
    }
}

/// The node folder named `name` holds a complete purge marker.
fn node_folder_marked(facts: &Facts, name: &str) -> bool {
    facts.data.iter().any(|entry| {
        matches!(entry, DataEntry::Folder { name: folder, marked: true, .. } if folder == name)
    })
}

/// The `db` store in the node folder named `name`, where `start` puts a node's store.
fn node_folder_store<'a>(facts: &'a Facts, name: &str) -> Option<&'a Location> {
    facts.data.iter().find_map(|entry| match entry {
        DataEntry::Folder {
            name: folder,
            stores,
            ..
        } if folder == name => stores
            .iter()
            .find(|store| store.path.file_name().is_some_and(|file| file == "db")),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATA: &str = "/p/.interfold/data";
    const CONFIG: &str = "/p/.interfold/config";

    fn at(path: &str) -> Location {
        Location {
            path: PathBuf::from(path),
            located: PathBuf::from(path),
            resolved: PathBuf::from(path),
        }
    }

    /// A configured node with the default layout: store, lock and event log in the data folder,
    /// and the key file in the configuration folder.
    fn node(name: &str) -> NodeFacts {
        NodeFacts {
            name: name.to_string(),
            db_file: PathBuf::from(format!("{DATA}/{name}/db")),
            store: Some(at(&format!("{DATA}/{name}/db"))),
            lock: at(&format!("{DATA}/{name}/interfold.lock")),
            lock_folder: FolderState::Exists,
            lock_folder_in_data: true,
            in_scope: true,
            key_file_in_target: true,
            key_file: PathBuf::from(format!("{CONFIG}/{name}/key")),
            event_log_in_target: true,
            recorded: Recorded::Nothing,
        }
    }

    /// A record that names the store `db_file`, which exists.
    fn recorded(db_file: &str) -> Recorded {
        Recorded::Store {
            db_file: PathBuf::from(db_file),
            store: Some(at(db_file)),
            lock: at(&format!(
                "{}/interfold.lock",
                Path::new(db_file).parent().unwrap().display()
            )),
        }
    }

    fn node_folder(name: &str, stores: &[&str]) -> DataEntry {
        DataEntry::Folder {
            name: name.to_string(),
            lock: at(&format!("{DATA}/{name}/interfold.lock")),
            marked: false,
            stores: stores
                .iter()
                .map(|store| at(&format!("{DATA}/{name}/{store}")))
                .collect(),
            links: Vec::new(),
        }
    }

    fn key_folder(name: &str) -> ConfigEntry {
        ConfigEntry::Folder {
            name: name.to_string(),
            location: at(&format!("{CONFIG}/{name}")),
            records: Vec::new(),
        }
    }

    fn facts(nodes: Vec<NodeFacts>, data: Vec<DataEntry>, config: Vec<ConfigEntry>) -> Facts {
        Facts {
            nodes,
            data,
            config,
        }
    }

    fn unchecked(node: &str, reason: Reason) -> Unchecked {
        Unchecked {
            node: node.to_string(),
            reason,
        }
    }

    #[test]
    fn a_default_node_is_locked_and_its_store_must_hold_its_identity() {
        let plan = plan(&facts(
            vec![node("cn1")],
            vec![node_folder("cn1", &["db"])],
            vec![key_folder("cn1")],
        ));
        assert_eq!(
            plan,
            Plan {
                locks: vec![PlannedLock {
                    path: PathBuf::from(format!("{DATA}/cn1/interfold.lock")),
                    nodes: vec!["cn1".into()],
                    create: false,
                }],
                stores: vec![PlannedStore {
                    db_file: PathBuf::from(format!("{DATA}/cn1/db")),
                    node: "cn1".into(),
                    needs_identity: true,
                }],
                unchecked: vec![],
            }
        );
    }

    #[test]
    fn a_missing_store_is_unchecked_when_the_key_file_or_the_event_log_would_go() {
        for (key_file_in_target, event_log_in_target, expected) in [
            (true, false, true),
            (false, true, true),
            (false, false, false),
        ] {
            let mut away = node("away");
            away.store = None;
            away.lock_folder = FolderState::Missing;
            away.lock_folder_in_data = false;
            away.key_file_in_target = key_file_in_target;
            away.event_log_in_target = event_log_in_target;
            let plan = plan(&facts(vec![away], vec![], vec![]));
            let expected: Vec<_> = expected
                .then(|| {
                    unchecked(
                        "away",
                        Reason::StoreNotFound(PathBuf::from(format!("{DATA}/away/db"))),
                    )
                })
                .into_iter()
                .collect();
            assert_eq!(plan.unchecked, expected);
        }
    }

    #[test]
    fn a_folder_that_an_earlier_purge_marked_is_not_unchecked() {
        let mut purged = node("purged");
        purged.store = None;
        purged.lock_folder = FolderState::Purging;
        let plan = plan(&facts(vec![purged], vec![], vec![]));
        assert!(plan.unchecked.is_empty());
        assert_eq!(plan.locks.len(), 1);
    }

    /// An empty node folder without the marker is not a leftover. It can be the mount point of a
    /// per-node volume that is not mounted, while the node's store holds a key share elsewhere.
    #[test]
    fn an_empty_folder_without_the_marker_is_unchecked() {
        let mut unmounted = node("unmounted");
        unmounted.store = None;
        let plan = plan(&facts(vec![unmounted], vec![], vec![]));
        assert_eq!(
            plan.unchecked,
            vec![unchecked(
                "unmounted",
                Reason::StoreNotFound(PathBuf::from(format!("{DATA}/unmounted/db")))
            )]
        );
    }

    /// The purge empties only folders in the data folder, so a marked folder elsewhere is not its
    /// own leftover.
    #[test]
    fn a_marked_folder_outside_the_data_folder_is_not_a_leftover() {
        let mut away = node("away");
        away.store = None;
        away.lock_folder = FolderState::Purging;
        away.lock_folder_in_data = false;
        let plan = plan(&facts(vec![away], vec![], vec![]));
        assert_eq!(
            plan.unchecked,
            vec![unchecked(
                "away",
                Reason::StoreNotFound(PathBuf::from(format!("{DATA}/away/db")))
            )]
        );
    }

    #[test]
    fn a_missing_node_folder_in_the_data_folder_is_created_and_locked() {
        let mut later = node("later");
        later.store = None;
        later.lock_folder = FolderState::Missing;
        later.key_file_in_target = false;
        later.event_log_in_target = false;
        let plan = plan(&facts(vec![later], vec![], vec![]));
        assert!(plan.locks[0].create);
        assert!(plan.unchecked.is_empty());
    }

    #[test]
    fn nodes_that_share_a_lock_are_all_named_and_each_store_is_checked() {
        let mut one = node("one");
        let mut two = node("two");
        one.lock = at(&format!("{DATA}/shared/interfold.lock"));
        two.lock = at(&format!("{DATA}/shared/interfold.lock"));
        one.db_file = PathBuf::from(format!("{DATA}/shared/one"));
        one.store = Some(at(&format!("{DATA}/shared/one")));
        two.db_file = PathBuf::from(format!("{DATA}/shared/two"));
        two.store = Some(at(&format!("{DATA}/shared/two")));
        // The shared folder's own name does not join the configured names.
        let plan = plan(&facts(
            vec![one, two],
            vec![node_folder("shared", &["one", "two"])],
            vec![],
        ));
        assert_eq!(plan.locks.len(), 1);
        assert_eq!(plan.locks[0].nodes, vec!["one", "two"]);
        assert_eq!(plan.stores.len(), 2);
    }

    #[test]
    fn a_key_folder_needs_a_configured_node_or_a_node_folder_with_a_store() {
        // A node folder of the same name with a store claims the key folder, and its store must
        // then hold the identity.
        let plan_with_store = plan(&facts(
            vec![],
            vec![node_folder("old", &["db"])],
            vec![key_folder("old")],
        ));
        assert!(plan_with_store.unchecked.is_empty());
        assert!(plan_with_store.stores[0].needs_identity);

        // A node folder without a store does not.
        let plan_without_store = plan(&facts(
            vec![],
            vec![node_folder("old", &[])],
            vec![key_folder("old")],
        ));
        assert_eq!(
            plan_without_store.unchecked,
            vec![unchecked(
                "old",
                Reason::UnknownKeyFolder(PathBuf::from(format!("{CONFIG}/old")))
            )]
        );

        // A node folder that an earlier purge checked and marked does, after its store is gone.
        let mut marked = node_folder("old", &[]);
        if let DataEntry::Folder { marked: flag, .. } = &mut marked {
            *flag = true;
        }
        let plan_marked = plan(&facts(vec![], vec![marked], vec![key_folder("old")]));
        assert!(plan_marked.unchecked.is_empty());
    }

    /// A configured key file that is a symbolic link matches by its located path.
    #[test]
    fn a_linked_key_file_is_configured() {
        let mut linked = node("linked");
        linked.key_file = PathBuf::from(format!("{CONFIG}/linked.key"));
        let file = ConfigEntry::File {
            name: "linked.key".to_string(),
            location: Location {
                path: PathBuf::from(format!("{CONFIG}/linked.key")),
                located: PathBuf::from(format!("{CONFIG}/linked.key")),
                resolved: PathBuf::from("/secrets/linked.key"),
            },
            recorded: Recorded::Nothing,
        };
        assert!(plan(&facts(vec![linked], vec![], vec![file]))
            .unchecked
            .is_empty());
    }

    #[test]
    fn a_file_in_the_configuration_folder_must_be_a_configured_key_file() {
        let mut flat = node("flat");
        flat.key_file = PathBuf::from(format!("{CONFIG}/flat.key"));
        let file = |name: &str| ConfigEntry::File {
            name: name.to_string(),
            location: at(&format!("{CONFIG}/{name}")),
            recorded: Recorded::Nothing,
        };
        let plan = plan(&facts(
            vec![flat],
            vec![],
            vec![file("flat.key"), file("stray")],
        ));
        assert_eq!(
            plan.unchecked,
            vec![unchecked(
                "stray",
                Reason::UnknownConfigFile(PathBuf::from(format!("{CONFIG}/stray")))
            )]
        );
    }

    #[test]
    fn a_link_must_lead_to_a_checked_store_or_a_locked_node_folder() {
        let link = |node: &str, path: &str, target: Option<&str>| Link {
            node: node.to_string(),
            path: PathBuf::from(path),
            target: target.map(PathBuf::from),
        };
        let data = vec![
            node_folder("cn1", &["db"]),
            DataEntry::Link(link(
                "to-store",
                "/p/.interfold/data/to-store",
                Some(&format!("{DATA}/cn1/db")),
            )),
            DataEntry::Link(link(
                "to-folder",
                "/p/.interfold/data/to-folder",
                Some(&format!("{DATA}/cn1")),
            )),
            DataEntry::Link(link("to-root", "/p/.interfold/data/to-root", Some("/"))),
            DataEntry::Link(link("dangling", "/p/.interfold/data/dangling", None)),
        ];
        let plan = plan(&facts(vec![], data, vec![]));
        assert_eq!(
            plan.unchecked,
            vec![unchecked(
                "to-root",
                Reason::Link(PathBuf::from("/p/.interfold/data/to-root"))
            )]
        );
    }

    #[test]
    fn a_node_outside_the_targets_is_not_planned() {
        let mut elsewhere = node("elsewhere");
        elsewhere.in_scope = false;
        assert_eq!(
            plan(&facts(vec![elsewhere], vec![], vec![])),
            Plan::default()
        );
    }

    /// A node that started with a store elsewhere: the purge holds that store's lock and checks it
    /// for the operator key, and checks the store at the configured path for key shares only.
    #[test]
    fn the_store_that_the_record_names_is_locked_and_holds_the_identity() {
        let mut moved = node("cn1");
        moved.recorded = recorded("/elsewhere/cn1/db");
        let plan = plan(&facts(
            vec![moved],
            vec![node_folder("cn1", &["db"])],
            vec![],
        ));

        assert!(plan
            .locks
            .iter()
            .any(|lock| lock.path == Path::new("/elsewhere/cn1/interfold.lock")));
        let store = |path: &str| {
            plan.stores
                .iter()
                .find(|store| store.db_file == Path::new(path))
                .unwrap()
        };
        assert!(store("/elsewhere/cn1/db").needs_identity);
        assert!(!store(&format!("{DATA}/cn1/db")).needs_identity);
        assert!(plan.unchecked.is_empty());
    }

    /// A record that names a store that is not there, or that the purge cannot read, is a
    /// refusal; a node without a store at its configured path then needs no store there.
    #[test]
    fn a_missing_recorded_store_or_an_unreadable_record_is_a_refusal() {
        let mut gone = node("cn1");
        gone.store = None;
        gone.recorded = Recorded::Store {
            db_file: PathBuf::from("/elsewhere/cn1/db"),
            store: None,
            lock: at("/elsewhere/cn1/interfold.lock"),
        };
        assert_eq!(
            plan(&facts(vec![gone], vec![], vec![])).unchecked,
            vec![unchecked(
                "cn1",
                Reason::RecordedStoreNotFound(PathBuf::from("/elsewhere/cn1/db"))
            )]
        );

        let mut unreadable = node("cn2");
        unreadable.recorded =
            Recorded::Unreadable(PathBuf::from(format!("{CONFIG}/cn2/key.store-record")));
        assert_eq!(
            plan(&facts(
                vec![unreadable],
                vec![node_folder("cn2", &["db"])],
                vec![]
            ))
            .unchecked,
            vec![unchecked(
                "cn2",
                Reason::UnreadableRecord(PathBuf::from(format!("{CONFIG}/cn2/key.store-record")))
            )]
        );
    }

    /// A key file that no configured node uses is checked through its record, instead of refused.
    #[test]
    fn an_unconfigured_key_file_is_checked_through_its_record() {
        let file = ConfigEntry::File {
            name: "old.key".to_string(),
            location: at(&format!("{CONFIG}/old.key")),
            recorded: recorded("/elsewhere/old/db"),
        };
        let plan = plan(&facts(vec![], vec![], vec![file]));
        assert!(plan.unchecked.is_empty());
        assert_eq!(
            plan.stores,
            vec![PlannedStore {
                db_file: PathBuf::from("/elsewhere/old/db"),
                node: "old.key".to_string(),
                needs_identity: true,
            }]
        );
        assert_eq!(plan.locks.len(), 1);
    }
}
