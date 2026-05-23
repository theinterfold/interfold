// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::*;
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;
use tokio::{
    io::AsyncWriteExt,
    process::{ChildStderr, ChildStdout},
    task::JoinHandle,
};
use tracing::{error, info, warn};

use super::log_buffer::LogBuffer;
use super::nodes::{
    spawn_process, CommandMap, ProcessMap, ProcessRecord, ProcessStatus, SwarmStatus,
};

/// Forward stdout from child process to parent's stdout and the shared log buffer.
fn forward_stdout(id: &str, stdout: ChildStdout, buf: Arc<LogBuffer>) -> JoinHandle<()> {
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
            let line = String::from_utf8_lossy(&buffer);
            buf.push(&id, &line).await;
            if let Err(e) = tokio::io::stdout()
                .write_all(format!("[{}] {}", id, line).as_bytes())
                .await
            {
                error!("Failed to write child stdout: {}", e);
            }
        }
    })
}

/// Forward stderr from child process to parent's stderr and the shared log buffer.
fn forward_stderr(id: &str, stderr: ChildStderr, buf: Arc<LogBuffer>) -> JoinHandle<()> {
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
            let line = String::from_utf8_lossy(&buffer);
            buf.push(&id, &line).await;
            if let Err(e) = tokio::io::stderr()
                .write_all(format!("[{}] {}", id, line).as_bytes())
                .await
            {
                error!("Failed to write child stderr: {}", e);
            }
        }
    })
}

/// Run a single command, forwarding its output to stdout/stderr and the log buffer.
async fn run_command(
    id: &str,
    program: &str,
    args: Vec<String>,
    log_buffer: Arc<LogBuffer>,
) -> Result<ProcessRecord> {
    let mut handles = vec![];
    let mut child = spawn_process(program, args).await?;

    if let Some(stdout) = child.stdout.take() {
        handles.push(forward_stdout(id, stdout, log_buffer.clone()));
    }

    if let Some(stderr) = child.stderr.take() {
        handles.push(forward_stderr(id, stderr, log_buffer.clone()));
    }

    Ok((child, handles))
}

/// Run commands as child processes and set up output forwarding.
async fn run_commands(
    commands: &CommandMap,
    processes: &ProcessMap,
    log_buffer: Arc<LogBuffer>,
) -> Result<()> {
    let commands = commands.clone();
    for (id, (program, args)) in commands {
        let record = run_command(&id, &program, args, log_buffer.clone()).await?;

        // Store the process
        let mut processes_guard = processes.lock().await;
        processes_guard.insert(id, record);
    }
    Ok(())
}

/// Start a process.
async fn start(
    id: &str,
    commands: &CommandMap,
    processes: &ProcessMap,
    log_buffer: Arc<LogBuffer>,
) -> Result<()> {
    if processes.lock().await.contains_key(id) {
        bail!("Process {} already running!", id);
    }
    let Some(command) = commands.get(id) else {
        bail!("Bad command {}", id);
    };

    let (program, args) = command.clone();
    let record = run_command(id, &program, args, log_buffer).await?;
    let mut processes_guard = processes.lock().await;
    processes_guard.insert(id.to_owned(), record);

    Ok(())
}

/// Start a process
async fn stop(id: &str, processes: &ProcessMap) -> Result<()> {
    warn!("stopping {}...", id);
    let mut processes_lock = processes.lock().await;
    if !processes_lock.contains_key(id) {
        info!("Cannot stop process that isn't running {}", id);
        return Ok(());
    };
    if let Some(mut process_record) = processes_lock.remove(id) {
        terminate_process_record(id, &mut process_record).await;
    }
    Ok(())
}

/// Terminate a process
async fn terminate_process_record(id: &str, process_record: &mut ProcessRecord) {
    info!("Terminating {}", id);
    let (child, handlers) = process_record;
    for handler in handlers.drain(..) {
        // drop all stdout/in handlers
        handler.abort();
    }

    if let Err(e) = child.kill().await {
        error!("Failed to kill process {}: {}", id, e);
    }

    info!("Terminating process: {}...", id);
    let _ = child.wait().await;
    info!("Process {} terminated.", id);
}

/// Terminate all processes
async fn terminate_processes(processes: &ProcessMap) {
    info!("starting to terminate processes...");
    let keys: Vec<String> = {
        processes
            .lock()
            .await
            .keys()
            .map(|k| k.to_string())
            .collect()
    };

    let mut processes_guard = processes.lock().await;
    for id in keys {
        if let Some(mut process_record) = processes_guard.remove(&id) {
            terminate_process_record(&id, &mut process_record).await;
        }
    }
}

/// Terminate all child processes
async fn terminate_processes_and_exit(processes: &ProcessMap) {
    let processes = processes.clone();
    // taking this off the hot path so we can send a response to the client
    tokio::spawn(async move {
        terminate_processes(&processes).await;
        info!("SWARM All processes terminated, exiting");
        let _ = std::io::stdout().flush();
        std::process::exit(0);
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
    log_buffer: Arc<LogBuffer>,
}

impl ProcessManager {
    /// Access the shared log buffer (cheap Arc clone).
    pub fn log_buffer(&self) -> Arc<LogBuffer> {
        self.log_buffer.clone()
    }

    pub async fn start_all(&self) -> Result<()> {
        run_commands(&self.commands, &self.processes, self.log_buffer.clone()).await?;
        Ok(())
    }

    pub async fn start(&self, id: &str) -> Result<()> {
        start(id, &self.commands, &self.processes, self.log_buffer.clone()).await?;
        Ok(())
    }

    pub async fn stop(&self, id: &str) -> Result<()> {
        stop(id, &self.processes).await?;
        Ok(())
    }

    pub async fn restart(&self, id: &str) -> Result<()> {
        stop(id, &self.processes).await?;
        start(id, &self.commands, &self.processes, self.log_buffer.clone()).await?;
        Ok(())
    }

    pub async fn stop_all(&self) -> Result<()> {
        terminate_processes(&self.processes).await;
        Ok(())
    }

    pub async fn terminate(&self) {
        terminate_processes_and_exit(&self.processes).await;
    }

    pub async fn status(&self, id: &str) -> ProcessStatus {
        let processes = self.processes.lock().await;
        if processes.contains_key(id) {
            ProcessStatus::Started
        } else {
            ProcessStatus::Stopped
        }
    }

    pub async fn list(&self) -> SwarmStatus {
        let mut processes = HashMap::new();

        for id in self.commands.keys() {
            processes.insert(id.to_string(), self.status(id).await);
        }

        SwarmStatus { processes }
    }
}

impl From<CommandMap> for ProcessManager {
    fn from(value: CommandMap) -> Self {
        // TODO: should probably implement a singleton pattern here but rn it doesn't matter
        let processes = Arc::new(Mutex::new(HashMap::new()));
        let manager = Self {
            commands: value,
            processes,
            log_buffer: Arc::new(LogBuffer::new()),
        };

        setup_signal_handlers(&manager);

        manager
    }
}
