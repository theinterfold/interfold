// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use directories::BaseDirs;
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::Deserialize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::Archive;

const GITHUB_REPO: &str = "gnosisguild/interfold";
const BINARY_NAME: &str = "interfold";

#[derive(Parser)]
#[command(
    name = "interfoldup",
    about = "Installer for the Interfold CLI tool",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Install the latest version of interfold
    Install {
        /// Install to /usr/local/bin instead of ~/.local/bin
        #[arg(long)]
        system: bool,
    },
    /// Update interfold to the latest version
    Update {
        /// Install to /usr/local/bin instead of ~/.local/bin
        #[arg(long)]
        system: bool,
    },
    /// Remove the installed interfold binary
    Uninstall {
        /// Remove from /usr/local/bin instead of ~/.local/bin
        #[arg(long)]
        system: bool,
    },
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug)]
struct Platform {
    os: String,
    arch: String,
}

impl Platform {
    fn detect() -> Result<Self> {
        let os = match std::env::consts::OS {
            "linux" => "linux",
            "macos" => "macos",
            _ => {
                return Err(anyhow!(
                    "Unsupported operating system: {}",
                    std::env::consts::OS
                ))
            }
        };

        let arch = match std::env::consts::ARCH {
            "x86_64" => "x86_64",
            "aarch64" => "aarch64",
            _ => {
                return Err(anyhow!(
                    "Unsupported architecture: {}",
                    std::env::consts::ARCH
                ))
            }
        };

        Ok(Platform {
            os: os.to_string(),
            arch: arch.to_string(),
        })
    }

    fn asset_pattern(&self) -> String {
        format!("{}-{}-{}", BINARY_NAME, self.os, self.arch)
    }
}

struct Installer {
    client: Client,
    platform: Platform,
}

impl Installer {
    fn new() -> Result<Self> {
        let client = Client::builder()
            .user_agent("interfoldup/0.1.0")
            .build()
            .context("Failed to create HTTP client")?;

        let platform = Platform::detect()?;

        Ok(Installer { client, platform })
    }

    async fn get_latest_release(&self) -> Result<GitHubRelease> {
        let url = format!(
            "https://api.github.com/repos/{}/releases/latest",
            GITHUB_REPO
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch latest release")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "GitHub API request failed with status: {}",
                response.status()
            ));
        }

        let release: GitHubRelease = response
            .json()
            .await
            .context("Failed to parse GitHub release response")?;

        Ok(release)
    }

    async fn download_with_progress(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .context("Failed to start download")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "Download failed with status: {}",
                response.status()
            ));
        }

        let total_size = response.content_length().unwrap_or(0);

        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-")
        );

        let mut downloaded = 0u64;
        let mut buffer = Vec::new();

        let mut stream = response;
        while let Some(chunk) = stream.chunk().await.context("Failed to read chunk")? {
            buffer.extend_from_slice(&chunk);
            downloaded += chunk.len() as u64;
            pb.set_position(downloaded);
        }

        pb.finish_with_message("Download complete");
        Ok(buffer)
    }

    async fn download_and_install(&self, system: bool) -> Result<()> {
        println!(
            "Detecting platform: {}-{}",
            self.platform.os, self.platform.arch
        );

        let release = self.get_latest_release().await?;
        println!("Latest release: {}", release.tag_name);

        let asset_pattern = self.platform.asset_pattern();
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name.contains(&asset_pattern))
            .ok_or_else(|| {
                anyhow!(
                    "No compatible asset found for {}-{}. Available assets: {}",
                    self.platform.os,
                    self.platform.arch,
                    release
                        .assets
                        .iter()
                        .map(|a| a.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;

        println!("Downloading {} ...", asset.name);
        let bytes = self
            .download_with_progress(&asset.browser_download_url)
            .await?;

        let target_dir = self.get_install_dir(system)?;
        fs::create_dir_all(&target_dir).context("Failed to create target directory")?;

        let target_path = target_dir.join(BINARY_NAME);

        println!("Extracting to {} ...", target_path.display());
        let tar = GzDecoder::new(&bytes[..]);
        let mut archive = Archive::new(tar);

        for entry in archive
            .entries()
            .context("Failed to read archive entries")?
        {
            let mut entry = entry.context("Failed to read archive entry")?;
            let path = entry.path().context("Failed to get entry path")?;

            if path.file_name() == Some(std::ffi::OsStr::new(BINARY_NAME)) {
                let mut file =
                    fs::File::create(&target_path).context("Failed to create target file")?;
                io::copy(&mut entry, &mut file).context("Failed to extract binary")?;
                break;
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&target_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&target_path, perms)
                .context("Failed to set executable permissions")?;
        }

        println!(
            "Successfully installed {} to {}",
            BINARY_NAME,
            target_path.display()
        );

        self.check_path(&target_dir);

        Ok(())
    }

    fn get_install_dir(&self, system: bool) -> Result<PathBuf> {
        if system {
            Ok(PathBuf::from("/usr/local/bin"))
        } else {
            let base_dirs =
                BaseDirs::new().ok_or_else(|| anyhow!("Failed to get base directories"))?;
            let local_bin = base_dirs.home_dir().join(".local/bin");
            Ok(local_bin)
        }
    }

    fn check_path(&self, install_dir: &Path) {
        if let Ok(path_var) = std::env::var("PATH") {
            let paths: Vec<&str> = path_var.split(':').collect();
            if !paths.iter().any(|&p| Path::new(p) == install_dir) {
                println!("Warning: {} is not in your PATH", install_dir.display());
                println!("Add it to your PATH with:");
                println!("export PATH=\"{}:$PATH\"", install_dir.display());
            }
        }
    }

    async fn uninstall(&self, system: bool) -> Result<()> {
        let target_dir = self.get_install_dir(system)?;
        let target_path = target_dir.join(BINARY_NAME);

        if target_path.exists() {
            fs::remove_file(&target_path).context("Failed to remove binary")?;
            println!(
                "Successfully removed {} from {}",
                BINARY_NAME,
                target_path.display()
            );
        } else {
            println!(
                "{} is not installed at {}",
                BINARY_NAME,
                target_path.display()
            );
        }

        Ok(())
    }

    async fn update(&self, system: bool) -> Result<()> {
        let target_dir = self.get_install_dir(system)?;
        let target_path = target_dir.join(BINARY_NAME);

        if !target_path.exists() {
            println!(
                "{} is not installed. Running install instead...",
                BINARY_NAME
            );
            return self.download_and_install(system).await;
        }
        let current_version = self.get_current_version(&target_path);
        let latest_release = self.get_latest_release().await?;

        if let Some(current) = current_version {
            if current == latest_release.tag_name {
                println!("{} is already up to date ({})", BINARY_NAME, current);
                return Ok(());
            }
            println!(
                "Updating {} from {} to {}",
                BINARY_NAME, current, latest_release.tag_name
            );
        } else {
            println!("Updating {} to {}", BINARY_NAME, latest_release.tag_name);
        }

        self.download_and_install(system).await
    }

    fn get_current_version(&self, binary_path: &Path) -> Option<String> {
        Command::new(binary_path)
            .arg("--version")
            .output()
            .ok()
            .and_then(|output| {
                let version_output = String::from_utf8(output.stdout).ok()?;
                version_output
                    .split_whitespace()
                    .last()
                    .map(|v| v.to_string())
            })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let installer = Installer::new()?;

    match cli.command {
        Commands::Install { system } => {
            installer.download_and_install(system).await?;
        }
        Commands::Update { system } => {
            installer.update(system).await?;
        }
        Commands::Uninstall { system } => {
            installer.uninstall(system).await?;
        }
    }

    Ok(())
}
