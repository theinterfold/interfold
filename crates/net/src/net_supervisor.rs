// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use crate::{events::NetCommand, NetworkStatus};
use anyhow::{Context, Result};
use std::future::{pending, Future};
use tokio::sync::{mpsc, watch};
use tracing::{error, info};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkTaskExit {
    pub reason: String,
    pub clean: bool,
}

#[derive(Clone, Debug)]
enum NetworkTaskSupervisorKind {
    Managed {
        command_tx: mpsc::Sender<NetCommand>,
        exit_rx: watch::Receiver<Option<NetworkTaskExit>>,
    },
    /// In-process channel bridges used by tests do not own a libp2p task.
    External,
}

/// Clonable observation and shutdown handle for the required libp2p task.
#[derive(Clone, Debug)]
pub struct NetworkTaskSupervisor(NetworkTaskSupervisorKind);

impl NetworkTaskSupervisor {
    pub fn external() -> Self {
        Self(NetworkTaskSupervisorKind::External)
    }

    pub fn is_managed(&self) -> bool {
        matches!(self.0, NetworkTaskSupervisorKind::Managed { .. })
    }

    /// Wait until the required network task exits. External test bridges never resolve here.
    pub async fn wait_for_exit(&self) -> Result<NetworkTaskExit> {
        let NetworkTaskSupervisorKind::Managed { exit_rx, .. } = &self.0 else {
            return pending().await;
        };
        let mut exit_rx = exit_rx.clone();
        loop {
            if let Some(exit) = exit_rx.borrow().clone() {
                return Ok(exit);
            }
            exit_rx
                .changed()
                .await
                .context("network task supervisor closed without an exit result")?;
        }
    }

    /// Stop ingress explicitly and wait for the interface loop to acknowledge termination.
    pub async fn shutdown_and_wait(&self) -> Result<Option<NetworkTaskExit>> {
        let NetworkTaskSupervisorKind::Managed {
            command_tx,
            exit_rx,
        } = &self.0
        else {
            return Ok(None);
        };

        if let Some(exit) = exit_rx.borrow().clone() {
            return Ok(Some(exit));
        }
        // A closed command channel means the task is already exiting. Its watch result remains the
        // authoritative reason, so still wait for it below.
        let _ = command_tx.send(NetCommand::Shutdown).await;
        self.wait_for_exit().await.map(Some)
    }
}

pub(crate) fn supervise_network_task<F>(
    command_tx: mpsc::Sender<NetCommand>,
    status: NetworkStatus,
    task: F,
) -> NetworkTaskSupervisor
where
    F: Future<Output = Result<()>> + 'static,
{
    let (exit_tx, exit_rx) = watch::channel(None);
    actix::spawn(async move {
        let result = task.await;
        let exit = match result {
            Ok(()) => {
                info!("Required libp2p interface stopped");
                status.record_error("libp2p interface stopped");
                NetworkTaskExit {
                    reason: "libp2p interface stopped".to_string(),
                    clean: true,
                }
            }
            Err(error) => {
                let reason = format!("libp2p interface failed: {error:#}");
                status.record_error(reason.clone());
                error!(%reason, "Required network task exited");
                NetworkTaskExit {
                    reason,
                    clean: false,
                }
            }
        };
        exit_tx.send_replace(Some(exit));
    });

    NetworkTaskSupervisor(NetworkTaskSupervisorKind::Managed {
        command_tx,
        exit_rx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix::test]
    async fn failure_is_observable_and_revokes_status() {
        let (command_tx, _command_rx) = mpsc::channel(1);
        let status = NetworkStatus::new(1);
        let supervisor = supervise_network_task(command_tx, status.clone(), async {
            anyhow::bail!("swarm failed")
        });

        let exit = supervisor.wait_for_exit().await.unwrap();
        assert!(!exit.clean);
        assert!(exit.reason.contains("swarm failed"));
        assert!(status
            .snapshot()
            .last_error
            .expect("network error should be projected")
            .contains("swarm failed"));
    }

    #[actix::test]
    async fn explicit_shutdown_waits_for_clean_interface_exit() {
        let (command_tx, mut command_rx) = mpsc::channel(1);
        let status = NetworkStatus::new(0);
        let supervisor = supervise_network_task(command_tx, status, async move {
            match command_rx.recv().await {
                Some(NetCommand::Shutdown) => Ok(()),
                other => anyhow::bail!("unexpected network command: {other:?}"),
            }
        });

        let exit = supervisor
            .shutdown_and_wait()
            .await
            .unwrap()
            .expect("managed task should report its exit");
        assert!(exit.clean);
    }
}
