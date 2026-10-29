// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! `interfold update` and `interfold uninstall`: change or remove the installed binary.

use anyhow::{anyhow, bail, Context, Result};
use e3_console::{log, Console};
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tar::Archive;

const GITHUB_REPO: &str = "theinterfold/interfold";
const BINARY_NAME: &str = "interfold";
const INSTALL_SCRIPT: &str =
    "https://raw.githubusercontent.com/theinterfold/interfold/main/install";

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    published_at: Option<String>,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

/// Replace this binary with the release that `version` names: `latest` (the default), `dev`, or a
/// release tag. An older tag downgrades.
pub async fn execute(out: Console, version: Option<String>, node_running: bool) -> Result<()> {
    let target = installed_binary()?;
    let client = reqwest::Client::builder()
        .user_agent(concat!("interfold/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(20))
        .build()
        .context("Failed to create HTTP client")?;

    let release = resolve_release(&client, version.as_deref()).await?;
    let current = env!("CARGO_PKG_VERSION");
    if tags_match(current, &release.tag_name) {
        log!(out, "{BINARY_NAME} is already at {}", release.tag_name);
        return Ok(());
    }

    let asset_name = format!("{BINARY_NAME}-{}.tar.gz", platform()?);
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == asset_name)
        .ok_or_else(|| anyhow!("Release {} has no {asset_name} archive", release.tag_name))?;

    log!(
        out,
        "Changing {BINARY_NAME} from v{current} to {}",
        release.tag_name
    );
    let archive = download_with_progress(&client, &asset.browser_download_url).await?;
    replace_binary(&archive, &target)?;
    log!(
        out,
        "Installed {BINARY_NAME} {} at {}",
        release.tag_name,
        target.display()
    );

    if node_running {
        log!(
            out,
            "A node is running. It continues to use v{current} until you restart it."
        );
    }
    let folder = target.parent().unwrap_or(&target);
    log!(
        out,
        "To change the release again, run `{BINARY_NAME} update --version <TAG>`. Release 0.19.0 \
         and earlier do not have this command. For these releases, run the install script: \
         curl -fsSL {INSTALL_SCRIPT} | bash -s -- --version <TAG> --dir {}",
        folder.display()
    );
    Ok(())
}

/// Remove this binary. The configuration and the node data stay.
pub fn uninstall(out: Console) -> Result<()> {
    let target = installed_binary()?;
    fs::remove_file(&target).map_err(|error| write_error(error, &target))?;
    log!(
        out,
        "Removed {}. The configuration and the node data stay.",
        target.display()
    );
    Ok(())
}

/// The file of this binary, with symlinks resolved, so that the update replaces the binary and not
/// a link to it.
fn installed_binary() -> Result<PathBuf> {
    let path = std::env::current_exe().context("Failed to find the path of this binary")?;
    fs::canonicalize(&path).with_context(|| format!("Failed to resolve {}", path.display()))
}

/// Release archives exist for Linux on x86_64 and for macOS on Apple silicon only.
fn platform() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("macos", "aarch64") => Ok("macos-aarch64"),
        (os, arch) => bail!(
            "No release archive exists for {os} on {arch}. Build the CLI from source on this platform."
        ),
    }
}

async fn fetch_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    label: &str,
) -> Result<T> {
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to fetch release {label}"))?;
    if !response.status().is_success() {
        bail!(
            "GitHub API request for release {label} failed with status: {}",
            response.status()
        );
    }
    response
        .json()
        .await
        .context("Failed to parse GitHub release response")
}

/// Get the release to install: `latest` (the default), `dev`, or a release tag.
async fn resolve_release(client: &reqwest::Client, version: Option<&str>) -> Result<GitHubRelease> {
    match version.map(str::trim) {
        None | Some("latest") => {
            let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
            fetch_json(client, &url, "latest").await
        }
        // After a stable release, `dev` selects it until the next pre-release. GitHub lists the
        // newest releases first, so the first page holds it.
        Some("dev") => {
            let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=100");
            let releases: Vec<GitHubRelease> = fetch_json(client, &url, "list").await?;
            newest_release(releases).ok_or_else(|| anyhow!("No release is published"))
        }
        Some(tag) => {
            let mut last_error = None;
            for candidate in tag_candidates(tag) {
                let url =
                    format!("https://api.github.com/repos/{GITHUB_REPO}/releases/tags/{candidate}");
                match fetch_json(client, &url, &candidate).await {
                    Ok(release) => return Ok(release),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| anyhow!("Release {tag} not found")))
        }
    }
}

async fn download_with_progress(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .context("Failed to start download")?;
    if !response.status().is_success() {
        bail!("Download failed with status: {}", response.status());
    }

    let progress = ProgressBar::new(response.content_length().unwrap_or(0));
    progress.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .context("Invalid progress bar template")?
            .progress_chars("#>-"),
    );

    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.context("Failed to read chunk")? {
        bytes.extend_from_slice(&chunk);
        progress.set_position(bytes.len() as u64);
    }
    progress.finish_and_clear();
    Ok(bytes)
}

/// Extract the binary from a release archive and put it at `target`. The binary goes to a new
/// temporary file with a random name next to `target`, and a rename replaces `target`. The temporary
/// file is never an existing file or link, so the update cannot write through a planted symlink. A
/// running process keeps the file that it started from, and a failed extraction leaves `target` as
/// it was and removes the temporary file.
fn replace_binary(archive: &[u8], target: &Path) -> Result<()> {
    let folder = target.parent().unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(&format!(".{BINARY_NAME}-update-"))
        .tempfile_in(folder)
        .map_err(|error| write_error(error, target))?;
    extract_binary(archive, temporary.as_file_mut())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o755))
            .context("Failed to set executable permissions")?;
    }
    temporary
        .persist(target)
        .map_err(|error| write_error(error.error, target))?;
    Ok(())
}

fn extract_binary(archive: &[u8], destination: &mut fs::File) -> Result<()> {
    let mut archive = Archive::new(GzDecoder::new(archive));
    for entry in archive
        .entries()
        .context("Failed to read the release archive")?
    {
        let mut entry = entry.context("Failed to read the release archive")?;
        let path = entry.path().context("Failed to read the release archive")?;
        if path.file_name() != Some(std::ffi::OsStr::new(BINARY_NAME)) {
            continue;
        }
        io::copy(&mut entry, destination).context("Failed to extract the binary")?;
        return Ok(());
    }
    bail!("The release archive does not contain the {BINARY_NAME} binary")
}

/// Creating, renaming, and removing the binary all need write access to its folder, so a permission
/// error names the folder.
fn write_error(error: io::Error, path: &Path) -> anyhow::Error {
    if error.kind() == io::ErrorKind::PermissionDenied {
        anyhow!(
            "Permission denied for {}. Run the command again with sudo.",
            path.parent().unwrap_or(path).display()
        )
    } else {
        anyhow!(error).context(format!("Failed to write {}", path.display()))
    }
}

/// Tag forms to try for a requested version, most likely first. Release tags
/// carry a `v` prefix, so a bare `0.13.0` also resolves.
fn tag_candidates(tag: &str) -> Vec<String> {
    let trimmed = tag.trim();
    if trimmed.starts_with('v') {
        vec![trimmed.to_string()]
    } else {
        vec![format!("v{}", trimmed), trimmed.to_string()]
    }
}

/// Compare two version strings, ignoring a leading `v` on either side.
fn tags_match(a: &str, b: &str) -> bool {
    a.trim().trim_start_matches('v') == b.trim().trim_start_matches('v')
}

/// A branch test release tag has the form `v<core>-<label>.g<sha7>`, for example `v0.20.0-lbfv.g1a2b3c4`.
/// It is not a channel release, so `dev` never selects it. The shape matches
/// `TEST_RELEASE_VERSION` in `scripts/release/version.mjs`.
fn is_test_release_tag(tag: &str) -> bool {
    let Some((core, suffix)) = tag.trim().trim_start_matches('v').split_once('-') else {
        return false;
    };
    let is_core = {
        let parts: Vec<&str> = core.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    };
    let Some((label, sha)) = suffix.split_once(".g") else {
        return false;
    };
    is_core
        && !label.is_empty()
        && label.bytes().all(|b| b.is_ascii_lowercase())
        && sha.len() == 7
        && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Select the most recently published release, stable or pre-release, but not a branch test
/// release. GitHub writes
/// `published_at` as an RFC 3339 UTC time, so the text order is the time order.
fn newest_release(releases: Vec<GitHubRelease>) -> Option<GitHubRelease> {
    releases
        .into_iter()
        .filter(|release| !is_test_release_tag(&release.tag_name))
        .max_by(|a, b| a.published_at.cmp(&b.published_at))
}

#[cfg(test)]
mod tests {
    use super::{
        is_test_release_tag, newest_release, replace_binary, tag_candidates, tags_match,
        GitHubRelease,
    };
    use flate2::{write::GzEncoder, Compression};
    use std::fs;

    fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
        for (name, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *contents).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn update_replaces_the_binary_only_when_the_archive_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("interfold");
        fs::write(&target, b"old").unwrap();

        // A wrong archive leaves the installed binary as it was.
        let error = replace_binary(&archive(&[("README", b"text")]), &target).unwrap_err();
        assert!(error.to_string().contains("does not contain"), "{error}");
        assert_eq!(fs::read(&target).unwrap(), b"old");

        replace_binary(&archive(&[("interfold", b"new")]), &target).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        // No temporary file stays next to the binary.
        let names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["interfold"]);
    }

    #[test]
    fn dev_selects_the_most_recently_published_release() {
        let release = |tag: &str, published_at: &str| GitHubRelease {
            tag_name: tag.to_string(),
            published_at: Some(published_at.to_string()),
            assets: Vec::new(),
        };
        let newest = |releases: Vec<GitHubRelease>| newest_release(releases).map(|r| r.tag_name);

        // Publication time decides, not the version.
        let dev_releases = vec![
            release("v0.19.0-dev.2", "2026-10-01T00:00:00Z"),
            release("v0.18.1-dev.1", "2026-10-03T00:00:00Z"),
        ];
        assert_eq!(newest(dev_releases).as_deref(), Some("v0.18.1-dev.1"));

        // A stable release is the dev release until the next pre-release.
        let after_stable = vec![
            release("v0.19.0-dev.2", "2026-10-01T00:00:00Z"),
            release("v0.19.0", "2026-10-09T00:00:00Z"),
        ];
        assert_eq!(newest(after_stable).as_deref(), Some("v0.19.0"));
        let after_next_dev = vec![
            release("v0.19.0", "2026-10-09T00:00:00Z"),
            release("v0.20.0-dev.1", "2026-10-12T00:00:00Z"),
        ];
        assert_eq!(newest(after_next_dev).as_deref(), Some("v0.20.0-dev.1"));

        assert!(newest(Vec::new()).is_none());
    }

    #[test]
    fn dev_never_selects_a_branch_test_release() {
        let release = |tag: &str, published_at: &str| GitHubRelease {
            tag_name: tag.to_string(),
            published_at: Some(published_at.to_string()),
            assets: Vec::new(),
        };
        let releases = vec![
            release("v0.20.0-dev.1", "2026-10-01T00:00:00Z"),
            release("v0.20.0-lbfv.g1a2b3c4", "2026-10-05T00:00:00Z"),
        ];
        assert_eq!(
            newest_release(releases).map(|r| r.tag_name).as_deref(),
            Some("v0.20.0-dev.1")
        );
        assert!(newest_release(vec![release(
            "v0.20.0-lbfv.g1a2b3c4",
            "2026-10-05T00:00:00Z"
        )])
        .is_none());

        for tag in ["v0.20.0-lbfv.g1a2b3c4", "0.20.0-lbfv.g0123456"] {
            assert!(is_test_release_tag(tag), "{tag}");
        }
        for tag in [
            "v0.20.0",
            "v0.20.0-dev.2",
            "v0.19.0-test.2",
            "v0.20.0-beta.1",
            "v0.20.0-lbfv.g1a2b3c",
            "v0.20.0-lbfv.g1a2b3c4d",
            "v0.20.0-lbfv.gABCDEFG",
            "v0.20-lbfv.g1a2b3c4",
        ] {
            assert!(!is_test_release_tag(tag), "{tag}");
        }
    }

    #[test]
    fn tag_candidates_add_the_v_prefix_first() {
        assert_eq!(tag_candidates("v0.13.0"), ["v0.13.0"]);
        assert_eq!(tag_candidates("0.13.0"), ["v0.13.0", "0.13.0"]);
        assert_eq!(tag_candidates("  v1.0.0-beta.1 "), ["v1.0.0-beta.1"]);
    }

    #[test]
    fn tags_match_ignores_the_v_prefix() {
        assert!(tags_match("0.13.0", "v0.13.0"));
        assert!(tags_match("v0.13.0", "v0.13.0"));
        assert!(!tags_match("0.13.0", "v0.14.0"));
    }
}
