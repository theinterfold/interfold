// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncBufReadExt;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tokio::{
    io::AsyncWriteExt,
    process::{ChildStderr, ChildStdout},
    task::JoinHandle,
};
use tracing::{error, info, warn};

use super::nodes::{
    spawn_process, CommandMap, ProcessMap, ProcessRecord, ProcessStatus, SwarmStatus,
};

/// How long the daemon waits for a child to exit after SIGTERM before SIGKILL.
///
/// Must exceed the child's own graceful-shutdown budget, or the daemon kills it
/// mid store-flush and the persisted state the flush was protecting is lost.
const GRACEFUL_CHILD_SHUTDOWN_TIMEOUT: Duration =
    Duration::from_secs(e3_events::NODE_SHUTDOWN_DEADLINE.as_secs() + 5);
const _: () = assert!(
    GRACEFUL_CHILD_SHUTDOWN_TIMEOUT.as_secs() > e3_events::NODE_SHUTDOWN_DEADLINE.as_secs(),
    "the daemon must outwait the node's own shutdown budget before escalating to SIGKILL"
);
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const EXIT_WATCH_INTERVAL: Duration = Duration::from_secs(2);

/// Forward stdout from child process to parent's stdout
fn forward_stdout(id: &str, stdout: ChildStdout) -> JoinHandle<()> {
    let id = id.to_owned();
    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stdout);
        let mut buffer = Vec::new();

        loop {
            buffer.clear();
            let n = reader.read_until(b'\n', &mut buffer).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            if let Err(e) = tokio::io::stdout()
                .write_all(format!("[{}] {}", id, String::from_utf8_lossy(&buffer)).as_bytes())
                .await
            {
                error!("Failed to write child stdout: {}", e);
            }
        }
    })
}

/// Forward stderr from child process to parent's stderr
fn forward_stderr(id: &str, stderr: ChildStderr) -> JoinHandle<()> {
    let id = id.to_owned();
    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stderr);
        let mut buffer = Vec::new();

        loop {
            buffer.clear();
            let n = reader.read_until(b'\n', &mut buffer).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            if let Err(e) = tokio::io::stderr()
                .write_all(format!("[{}] {}", id, String::from_utf8_lossy(&buffer)).as_bytes())
                .await
            {
                error!("Failed to write child stdout: {}", e);
            }
        }
    })
}

/// Run a single command
async fn run_command(id: &str, program: &str, args: Vec<String>) -> Result<ProcessRecord> {
    let mut handles = vec![];
    let mut child = spawn_process(program, args).await?;

    if let Some(stdout) = child.stdout.take() {
        handles.push(forward_stdout(id, stdout));
    }

    if let Some(stderr) = child.stderr.take() {
        handles.push(forward_stderr(id, stderr));
    }

    Ok((child, handles))
}

/// Poll a child for an unexpected exit and report it.
///
/// The daemon otherwise learns that a node died only when an operator runs `nodes ps`. A
/// deliberate `stop` removes the record from the map before terminating the child, so a record
/// that is still present when the child has exited is a crash, not an operator action. The
/// watcher is aborted together with the output forwarders when the record is dropped.
fn watch_exit(id: &str, processes: &ProcessMap) -> JoinHandle<()> {
    let id = id.to_owned();
    let processes = processes.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(EXIT_WATCH_INTERVAL).await;
            let mut guard = processes.lock().await;
            let Some((child, _)) = guard.get_mut(&id) else {
                // Removed by `stop`/`terminate`: expected.
                return;
            };
            match child.try_wait() {
                Ok(None) => continue,
                Ok(Some(status)) => {
                    error!(
                        process = %id,
                        exit_code = ?status.code(),
                        signal = ?std::os::unix::process::ExitStatusExt::signal(&status),
                        "SWARM child exited unexpectedly; it is NOT restarted automatically \
                         (use `nodes start {id}`)"
                    );
                    return;
                }
                Err(error) => {
                    warn!(process = %id, %error, "Failed to poll child exit status");
                    return;
                }
            }
        }
    })
}

/// Attach the exit watcher to a freshly stored record.
async fn attach_exit_watcher(id: &str, processes: &ProcessMap) {
    let watcher = watch_exit(id, processes);
    if let Some((_, handlers)) = processes.lock().await.get_mut(id) {
        handlers.push(watcher);
    } else {
        watcher.abort();
    }
}

/// Run commands as child processes and set up output forwarding
async fn run_commands(commands: &CommandMap, processes: &ProcessMap) -> Result<()> {
    let commands = commands.clone();
    for (id, (program, args)) in commands {
        let record = match run_command(&id, &program, args).await {
            Ok(record) => record,
            Err(error) => {
                if let Err(cleanup_error) = terminate_processes(processes).await {
                    error!(%cleanup_error, "Failed to clean up partially started process swarm");
                }
                return Err(error).with_context(|| format!("failed to start process {id}"));
            }
        };

        // Store the process
        let mut processes_guard = processes.lock().await;
        processes_guard.insert(id.clone(), record);
        drop(processes_guard);
        attach_exit_watcher(&id, processes).await;
    }
    Ok(())
}

/// Start a process
async fn start(id: &str, commands: &CommandMap, processes: &ProcessMap) -> Result<()> {
    {
        let mut processes = processes.lock().await;
        let exited = if let Some((child, _)) = processes.get_mut(id) {
            match child.try_wait().context("failed to inspect child status")? {
                None => bail!("Process {} already running!", id),
                Some(_) => true,
            }
        } else {
            false
        };
        if exited {
            if let Some((_, handlers)) = processes.remove(id) {
                for handler in handlers {
                    handler.abort();
                }
            }
        }
    }
    let Some(command) = commands.get(id) else {
        bail!("Bad command {}", id);
    };

    let (program, args) = command.clone();
    let record = run_command(id, &program, args).await?;
    let mut processes_guard = processes.lock().await;
    processes_guard.insert(id.to_owned(), record);
    drop(processes_guard);
    attach_exit_watcher(id, processes).await;

    Ok(())
}

/// Start a process
async fn stop(id: &str, processes: &ProcessMap) -> Result<()> {
    warn!("stopping {}...", id);
    let process_record = processes.lock().await.remove(id);
    let Some(mut process_record) = process_record else {
        info!("Cannot stop process that isn't running {}", id);
        return Ok(());
    };
    terminate_process_record(id, &mut process_record).await?;
    Ok(())
}

fn send_sigterm(child: &tokio::process::Child) -> Result<()> {
    let pid = child.id().context("child has no process id")?;
    // SAFETY: `libc::kill` does not dereference pointers. The PID comes from a live
    // `tokio::process::Child`, and the signal constant is valid on this Unix-only module.
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error).context("failed to send SIGTERM to child")
    }
}

/// Ask a process to shut down, then force-kill it only after the grace period.
async fn terminate_process_record(id: &str, process_record: &mut ProcessRecord) -> Result<()> {
    info!("Terminating {}", id);
    let (child, handlers) = process_record;

    if child.try_wait()?.is_none() {
        send_sigterm(child)?;
        match tokio::time::timeout(GRACEFUL_CHILD_SHUTDOWN_TIMEOUT, child.wait()).await {
            Ok(status) => {
                status?;
            }
            Err(_) => {
                warn!(
                    process = id,
                    timeout_seconds = GRACEFUL_CHILD_SHUTDOWN_TIMEOUT.as_secs(),
                    "Child did not exit after SIGTERM; sending SIGKILL"
                );
                child.kill().await?;
            }
        }
    }

    for mut handler in handlers.drain(..) {
        if tokio::time::timeout(OUTPUT_DRAIN_TIMEOUT, &mut handler)
            .await
            .is_err()
        {
            handler.abort();
        }
    }
    info!("Process {} terminated.", id);
    Ok(())
}

/// Terminate all processes
async fn terminate_processes(processes: &ProcessMap) -> Result<()> {
    info!("starting to terminate processes...");
    let records = std::mem::take(&mut *processes.lock().await);
    let mut first_error = None;
    for (id, mut process_record) in records {
        if let Err(error) = terminate_process_record(&id, &mut process_record).await {
            error!(process = id, %error, "Failed to terminate child process");
            first_error.get_or_insert(error);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Terminate all child processes
async fn terminate_processes_and_exit(processes: &ProcessMap) {
    let processes = processes.clone();
    // taking this off the hot path so we can send a response to the client
    tokio::spawn(async move {
        let exit_code = match terminate_processes(&processes).await {
            Ok(()) => {
                info!("SWARM All processes terminated, exiting");
                0
            }
            Err(error) => {
                error!(%error, "SWARM child shutdown failed");
                1
            }
        };
        let _ = std::io::stdout().flush();
        std::process::exit(exit_code);
    });
}

static SIGNAL_HANDLER_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Set up signal handlers for graceful shutdown
/// This will only be executed once, even if called multiple times
fn setup_signal_handlers(manager: &ProcessManager) -> JoinHandle<()> {
    // If signal handler already initialized, return a dummy completed JoinHandle
    if SIGNAL_HANDLER_INITIALIZED.swap(true, Ordering::SeqCst) {
        return tokio::spawn(async {});
    }

    // Set up the actual signal handler
    let manager = manager.clone();
    tokio::spawn(async move {
        let mut sigterm =
            signal(SignalKind::terminate()).expect("SWARM Failed to set up SIGTERM handler");
        sigterm.recv().await;
        info!("Received SIGTERM, shutting down all processes...");
        manager.terminate().await
    })
}

#[derive(Debug, Clone)]
pub struct ProcessManager {
    commands: CommandMap,
    processes: ProcessMap,
    /// Config file this swarm was launched from; reported in `/status` so clients can refuse
    /// to act on a daemon that serves a different config.
    config_file: Option<String>,
}

impl ProcessManager {
    pub fn with_config_file(mut self, config_file: impl Into<String>) -> Self {
        self.config_file = Some(config_file.into());
        self
    }

    pub async fn start_all(&self) -> Result<()> {
        run_commands(&self.commands, &self.processes).await?;
        Ok(())
    }

    pub async fn start(&self, id: &str) -> Result<()> {
        start(id, &self.commands, &self.processes).await?;
        Ok(())
    }

    pub async fn stop(&self, id: &str) -> Result<()> {
        stop(id, &self.processes).await?;
        Ok(())
    }

    pub async fn restart(&self, id: &str) -> Result<()> {
        stop(id, &self.processes).await?;
        start(id, &self.commands, &self.processes).await?;
        Ok(())
    }

    pub async fn stop_all(&self) -> Result<()> {
        terminate_processes(&self.processes).await
    }

    pub async fn terminate(&self) {
        terminate_processes_and_exit(&self.processes).await;
    }

    pub async fn status(&self, id: &str) -> ProcessStatus {
        let mut processes = self.processes.lock().await;
        let Some((child, _)) = processes.get_mut(id) else {
            return ProcessStatus::Stopped;
        };
        match child.try_wait() {
            Ok(None) => ProcessStatus::Started,
            Ok(Some(status)) => ProcessStatus::Exited {
                code: status.code(),
            },
            Err(error) => {
                warn!(process = id, %error, "Failed to inspect child process status");
                ProcessStatus::Unknown
            }
        }
    }

    pub async fn list(&self) -> SwarmStatus {
        let mut processes = HashMap::new();

        for id in self.commands.keys() {
            processes.insert(id.to_string(), self.status(id).await);
        }

        SwarmStatus {
            processes,
            config_file: self.config_file.clone(),
        }
    }
}

impl From<CommandMap> for ProcessManager {
    fn from(value: CommandMap) -> Self {
        let processes = Arc::new(Mutex::new(HashMap::new()));
        let manager = Self {
            commands: value,
            processes,
            config_file: None,
        };

        setup_signal_handlers(&manager);

        manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn wait_for_status(manager: &ProcessManager, id: &str, expected: ProcessStatus) {
        let observed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = manager.status(id).await;
                if status == expected {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("process {id} did not reach {expected:?}"));

        assert_eq!(observed, expected);
    }

    async fn wait_for_file(path: &std::path::Path) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("file was not created: {}", path.display()));
    }

    #[tokio::test]
    async fn exited_child_is_not_reported_as_started_and_can_be_started_again() {
        let commands = CommandMap::from([(
            "short".to_string(),
            (
                "sh".to_string(),
                vec!["-c".to_string(), "exit 7".to_string()],
            ),
        )]);
        let manager = ProcessManager::from(commands);
        manager.start("short").await.unwrap();

        wait_for_status(&manager, "short", ProcessStatus::Exited { code: Some(7) }).await;

        manager.start("short").await.unwrap();
        wait_for_status(&manager, "short", ProcessStatus::Exited { code: Some(7) }).await;
    }

    #[tokio::test]
    async fn stop_sends_sigterm_before_forcing_termination() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("terminated");
        let ready = directory.path().join("ready");
        let script = r#"trap 'printf "terminated\n" > "$1"; exit 0' TERM; : > "$2"; while :; do sleep 0.05; done"#;
        let commands = CommandMap::from([(
            "long".to_string(),
            (
                "sh".to_string(),
                vec![
                    "-c".to_string(),
                    script.to_string(),
                    "process-manager-test".to_string(),
                    marker.to_string_lossy().into_owned(),
                    ready.to_string_lossy().into_owned(),
                ],
            ),
        )]);
        let manager = ProcessManager::from(commands);
        manager.start("long").await.unwrap();
        wait_for_file(&ready).await;

        manager.stop("long").await.unwrap();

        assert_eq!(
            std::fs::read_to_string(marker).unwrap().trim(),
            "terminated"
        );
        assert_eq!(manager.status("long").await, ProcessStatus::Stopped);
    }

    /// The exit watcher must stop polling once a record has been removed by `stop`, and must
    /// still be attached (so it can be aborted) while the child is running.
    #[tokio::test]
    async fn exit_watcher_is_attached_and_released_with_the_record() {
        let commands = CommandMap::from([(
            "long".to_string(),
            (
                "sh".to_string(),
                vec!["-c".to_string(), "sleep 30".to_string()],
            ),
        )]);
        let manager = ProcessManager::from(commands);
        manager.start("long").await.unwrap();

        // Two output forwarders plus the exit watcher.
        assert_eq!(
            manager.processes.lock().await.get("long").unwrap().1.len(),
            3
        );

        manager.stop("long").await.unwrap();
        assert!(manager.processes.lock().await.get("long").is_none());
    }

    /// A child that dies on its own stays in the map as `Exited` (so `nodes ps` reports it)
    /// and the watcher observes the exit rather than an operator stop.
    #[tokio::test]
    async fn crashed_child_is_still_reported_by_status() {
        let commands = CommandMap::from([(
            "crash".to_string(),
            (
                "sh".to_string(),
                vec!["-c".to_string(), "kill -9 $$".to_string()],
            ),
        )]);
        let manager = ProcessManager::from(commands);
        manager.start("crash").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Signal death has no exit code.
        assert_eq!(
            manager.status("crash").await,
            ProcessStatus::Exited { code: None }
        );
    }
}
