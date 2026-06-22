// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Read-only release awareness for node operators.

use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

const LATEST_RELEASE: &str = "https://api.github.com/repos/gnosisguild/interfold/releases/latest";
const RELEASES_PAGE: &str = "https://github.com/gnosisguild/interfold/releases";
const CACHE_TTL: Duration = Duration::from_secs(60 * 60);
const ERROR_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ReleaseInfo {
    tag: String,
    name: String,
    url: String,
    published_at: Option<String>,
    notes: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UpdateSnapshot {
    current_version: String,
    latest: Option<ReleaseInfo>,
    update_available: bool,
    releases_url: &'static str,
    checked_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    name: Option<String>,
    html_url: String,
    published_at: Option<String>,
    body: Option<String>,
}

#[derive(Default)]
struct Cache {
    refreshed_at: Option<Instant>,
    snapshot: Option<UpdateSnapshot>,
}

#[derive(Clone)]
pub(crate) struct UpdateService {
    client: reqwest::Client,
    current_version: String,
    cache: Arc<Mutex<Cache>>,
}

impl UpdateService {
    pub(crate) fn new(current_version: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            current_version: current_version.into(),
            cache: Arc::new(Mutex::new(Cache::default())),
        }
    }

    pub(crate) async fn snapshot(&self) -> UpdateSnapshot {
        let mut cache = self.cache.lock().await;
        let ttl = if cache
            .snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.error.is_some())
        {
            ERROR_CACHE_TTL
        } else {
            CACHE_TTL
        };
        if cache
            .refreshed_at
            .is_some_and(|refreshed| refreshed.elapsed() < ttl)
        {
            if let Some(snapshot) = &cache.snapshot {
                return snapshot.clone();
            }
        }

        let fetched = tokio::time::timeout(Duration::from_secs(8), self.fetch()).await;
        let snapshot = match fetched {
            Ok(Ok(release)) => UpdateSnapshot {
                update_available: compare_versions(&release.tag, &self.current_version)
                    == Ordering::Greater,
                current_version: self.current_version.clone(),
                latest: Some(release),
                releases_url: RELEASES_PAGE,
                checked_at_ms: now_ms(),
                error: None,
            },
            Ok(Err(error)) => UpdateSnapshot {
                current_version: self.current_version.clone(),
                latest: cache
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.latest.clone()),
                update_available: cache
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.update_available),
                releases_url: RELEASES_PAGE,
                checked_at_ms: now_ms(),
                error: Some(error.to_string()),
            },
            Err(_) => UpdateSnapshot {
                current_version: self.current_version.clone(),
                latest: cache
                    .snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.latest.clone()),
                update_available: cache
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.update_available),
                releases_url: RELEASES_PAGE,
                checked_at_ms: now_ms(),
                error: Some("release check timed out".into()),
            },
        };
        cache.refreshed_at = Some(Instant::now());
        cache.snapshot = Some(snapshot.clone());
        snapshot
    }

    async fn fetch(&self) -> anyhow::Result<ReleaseInfo> {
        let release = self
            .client
            .get(LATEST_RELEASE)
            .header(
                reqwest::header::USER_AGENT,
                "interfold-ciphernode-dashboard",
            )
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .await?
            .error_for_status()?
            .json::<GitHubRelease>()
            .await?;
        let notes = release.body.unwrap_or_default();
        Ok(ReleaseInfo {
            name: release
                .name
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| release.tag_name.clone()),
            tag: release.tag_name,
            url: release.html_url,
            published_at: release.published_at,
            notes: notes.chars().take(8_000).collect(),
        })
    }
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    version_parts(left).cmp(&version_parts(right))
}

fn version_parts(value: &str) -> [u64; 3] {
    let mut result = [0; 3];
    for (index, part) in value
        .trim_start_matches('v')
        .split(['.', '-'])
        .take(3)
        .enumerate()
    {
        result[index] = part.parse().unwrap_or(0);
    }
    result
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_release_tags_without_extra_dependencies() {
        assert_eq!(compare_versions("v0.3.0", "0.2.2"), Ordering::Greater);
        assert_eq!(compare_versions("v0.2.2", "0.2.2"), Ordering::Equal);
        assert_eq!(compare_versions("v0.2.1", "0.2.2"), Ordering::Less);
    }
}
