// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, process::Stdio, sync::Arc};
use tokio::{
    process::{Child, Command},
    sync::Mutex,
    task::JoinHandle,
};

pub const SERVER_ADDRESS: &str = "127.0.0.1:13415";

/// All the parameters of a command
pub type CommandParams = (String, Vec<String>);
/// A map of all the start commands to manage
pub type CommandMap = HashMap<String, CommandParams>;
/// The management record of the individual process
pub type ProcessRecord = (Child, Vec<JoinHandle<()>>);
/// The map that holds processes
pub type ProcessMap = Arc<Mutex<HashMap<String, ProcessRecord>>>;

/// Spawn a child process and return the Child handle
///
/// The returned handle owns the child: `kill_on_drop` means dropping it kills the process. Use
/// this only when the caller retains the handle for the child's whole life, as `ProcessManager`
/// does in its `ProcessMap`. For a process that must outlive this one, use
/// [`spawn_detached_process`].
pub async fn spawn_process(program: &str, args: Vec<String>) -> Result<Child> {
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A termination-path error must not turn dropping our last handle into an orphaned
        // ciphernode. Normal stops still use SIGTERM and the graceful drain in ProcessManager.
        .kill_on_drop(true)
        .spawn()?;

    Ok(child)
}

/// Spawn a child process that outlives this one.
///
/// Unlike [`spawn_process`] this does NOT set `kill_on_drop`: the caller starts the child and
/// returns, so the handle is dropped immediately and `kill_on_drop` would kill the very process
/// it just started. The child is also detached from this process's pipes, because the read ends
/// close when the caller exits and the child would then fail on every write to a broken pipe.
///
/// The caller keeps no handle, so the child is reached through its own protocol from then on
/// (for the daemon, the socket at [`SERVER_ADDRESS`]).
pub async fn spawn_detached_process(program: &str, args: Vec<String>) -> Result<Child> {
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false)
        .spawn()?;

    Ok(child)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "data")]
pub enum Action {
    Start { id: String },
    Stop { id: String },
    Restart { id: String },
    StartAll,
    StopAll,
    Terminate,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type", content = "data")]
pub enum Query {
    Success,
    Failure { message: String },
    Status { status: SwarmStatus },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProcessStatus {
    Started,
    Stopped,
    Exited { code: Option<i32> },
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SwarmStatus {
    pub processes: HashMap<String, ProcessStatus>,
    /// Config file the daemon was launched with. The control port is a fixed loopback
    /// address, so a client started from a different checkout or config would otherwise
    /// silently drive someone else's swarm. `None` only from daemons built before this field.
    #[serde(default)]
    pub config_file: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn process_exists(pid: u32) -> bool {
        // SAFETY: signal 0 performs an existence/permission check and does not mutate the target.
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    #[tokio::test]
    async fn dropping_the_last_child_handle_does_not_orphan_the_process() {
        let child = spawn_process("sh", vec!["-c".into(), "exec sleep 30".into()])
            .await
            .unwrap();
        let pid = child.id().unwrap();
        assert!(process_exists(pid));

        drop(child);

        tokio::time::timeout(Duration::from_secs(5), async {
            while process_exists(pid) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("kill-on-drop child should exit promptly");
    }
}
