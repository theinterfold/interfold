// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{collections::HashMap, thread, time::Duration};

use actix::{Actor, Handler, Message, MessageResponse};
use e3_utils::MAILBOX_LIMIT;

#[derive(Message)]
#[rtype(result = "FlattenedReport")]
pub struct ToReport;

#[derive(Message, Debug)]
#[rtype("()")]
pub struct TrackDuration {
    name: String,
    duration: Duration,
}

impl TrackDuration {
    pub fn new(name: String, duration: Duration) -> Self {
        Self { name, duration }
    }
}

#[derive(Default)]
pub struct MultithreadReport {
    rayon_threads: usize,
    max_simultaneous_rayon_tasks: usize,
    events: Vec<TrackDuration>,
}

impl Actor for MultithreadReport {
    type Context = actix::Context<Self>;
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(MAILBOX_LIMIT);
    }
}

impl MultithreadReport {
    pub fn new(rayon_threads: usize, max_simultaneous_rayon_tasks: usize) -> Self {
        Self {
            rayon_threads,
            max_simultaneous_rayon_tasks,
            events: Vec::new(),
        }
    }

    fn track(&mut self, msg: TrackDuration) {
        self.events.push(msg);
    }

    fn to_report(&self) -> FlattenedReport {
        let mut total_dur: HashMap<String, Duration> = HashMap::new();
        let mut runs: HashMap<String, u64> = HashMap::new();
        let cores_available: usize = match thread::available_parallelism() {
            Ok(count) => count.into(),
            Err(_) => 0usize,
        };

        // Accumulate durations and count runs
        for event in &self.events {
            *runs.entry(event.name.clone()).or_insert(0) += 1;

            total_dur
                .entry(event.name.clone())
                .and_modify(|d| *d += event.duration)
                .or_insert(event.duration);
        }

        // Calculate averages
        let avg_dur = total_dur
            .clone()
            .into_iter()
            .map(|(name, total)| {
                let count = runs[&name];
                let avg = Duration::from_nanos((total.as_nanos() / count as u128) as u64);
                (name, avg)
            })
            .collect();

        let mt_total = total_dur
            .clone()
            .into_iter()
            .fold(Duration::ZERO, |acc, (_, item)| acc + item);

        FlattenedReport {
            cores_available,
            total_dur,
            avg_dur,
            mt_total,
            rayon_threads: self.rayon_threads,
            max_simultaneous_rayon_tasks: self.max_simultaneous_rayon_tasks,
            runs,
        }
    }
}

impl Handler<TrackDuration> for MultithreadReport {
    type Result = ();
    fn handle(&mut self, msg: TrackDuration, _: &mut Self::Context) -> Self::Result {
        self.track(msg)
    }
}

impl Handler<ToReport> for MultithreadReport {
    type Result = FlattenedReport;
    fn handle(&mut self, _: ToReport, _: &mut Self::Context) -> Self::Result {
        self.to_report()
    }
}

/// One row of the flattened multithread report (seconds, for export / dashboards).
#[derive(Debug, Clone, PartialEq)]
pub struct OperationTimingSec {
    pub name: String,
    pub avg_seconds: f64,
    pub runs: u64,
    pub total_seconds: f64,
}

#[derive(MessageResponse, Debug, Clone, Eq, PartialEq)]
pub struct FlattenedReport {
    cores_available: usize,
    rayon_threads: usize,
    max_simultaneous_rayon_tasks: usize,
    avg_dur: HashMap<String, Duration>,
    total_dur: HashMap<String, Duration>,
    mt_total: Duration,
    runs: HashMap<String, u64>,
}

impl FlattenedReport {
    pub fn rayon_threads(&self) -> usize {
        self.rayon_threads
    }

    pub fn max_simultaneous_rayon_tasks(&self) -> usize {
        self.max_simultaneous_rayon_tasks
    }

    pub fn cores_available(&self) -> usize {
        self.cores_available
    }

    /// Wall-clock sum of all tracked operation durations (same as printed "Total time").
    pub fn tracked_total_seconds(&self) -> f64 {
        self.mt_total.as_secs_f64()
    }

    /// Per-operation averages and totals, sorted by name (stable with `Display` output).
    pub fn operation_timings_sec(&self) -> Vec<OperationTimingSec> {
        let mut names: Vec<_> = self.avg_dur.keys().cloned().collect();
        names.sort();
        names
            .into_iter()
            .map(|name| {
                let runs = *self.runs.get(&name).unwrap_or(&0);
                let total = *self.total_dur.get(&name).unwrap_or(&Duration::ZERO);
                let avg = *self.avg_dur.get(&name).unwrap_or(&Duration::ZERO);
                OperationTimingSec {
                    name,
                    avg_seconds: avg.as_secs_f64(),
                    runs,
                    total_seconds: total.as_secs_f64(),
                }
            })
            .collect()
    }
}

impl std::fmt::Display for FlattenedReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:<32} {:>5}", "Rayon Threads:", self.rayon_threads)?;
        writeln!(
            f,
            "{:<32} {:>5}",
            "Max Simultaneous Rayon Tasks:", self.max_simultaneous_rayon_tasks
        )?;
        writeln!(f, "{:<32} {:>5}", "Cores Available:", self.cores_available)?;
        writeln!(f)?;
        writeln!(
            f,
            "{:<30} {:>15} {:>10} {:>15}",
            "Name", "Avg Duration", "Runs", "Total Duration"
        )?;
        writeln!(f, "{}", "-".repeat(73))?;

        let mut entries: Vec<_> = self.avg_dur.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));

        for (name, avg_dur) in entries {
            let runs = self.runs.get(name).unwrap_or(&0);
            let total_dur = self.total_dur.get(name).unwrap();
            writeln!(
                f,
                "{:<30} {:>15?} {:>10} {:>15?}",
                name, avg_dur, runs, total_dur
            )?;
        }

        writeln!(f, "{:<50} {:>22?}", "Total time", self.mt_total)?;

        Ok(())
    }
}
