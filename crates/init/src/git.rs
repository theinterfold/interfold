// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::{path::Path, vec};

use anyhow::{Context, Result};
use tokio::process::Command;
use url::Url;

pub async fn shallow_clone(
    git_repo: &str,
    branch: &str,
    target_folder: &str,
    verbose: bool,
) -> Result<()> {
    let mut args = vec![
        "clone",
        "--depth",
        "1",
        "-c",
        "advice.detachedHead=false",
        "--branch",
        branch,
        git_repo,
        target_folder,
    ];
    if !verbose {
        args.push("--quiet");
    }

    let status = Command::new("git").args(&args).status().await?;

    if !status.success() {
        return Err(anyhow::anyhow!(
            "Git clone failed with exit code: {}",
            status.code().unwrap_or(-1)
        ));
    }

    Ok(())
}

pub async fn init(path: impl AsRef<Path>, verbose: bool) -> Result<()> {
    let path = path.as_ref();

    let mut args = vec!["init", "-b", "main"];
    if !verbose {
        args.push("--quiet");
    }

    Command::new("git")
        .args(&args)
        .current_dir(path)
        .output()
        .await
        .with_context(|| {
            format!(
                "Failed to execute git init in directory: {}",
                path.display()
            )
        })?;
    Ok(())
}

pub async fn add_all(path: impl AsRef<Path>, verbose: bool) -> Result<()> {
    let path = path.as_ref();

    let mut args = vec!["add", "."];
    if !verbose {
        args.push("--quiet");
    }

    Command::new("git")
        .args(&args)
        .current_dir(path)
        .output()
        .await
        .with_context(|| format!("Failed to execute git add in directory: {}", path.display()))?;
    Ok(())
}

pub async fn commit(path: impl AsRef<Path>, message: &str, verbose: bool) -> Result<()> {
    let path = path.as_ref();

    let mut args = vec!["commit", "-m", message];
    if !verbose {
        args.push("--quiet");
    }

    Command::new("git")
        .args(&args)
        .current_dir(path)
        .output()
        .await
        .with_context(|| {
            format!(
                "Failed to execute git commit in directory: {}",
                path.display()
            )
        })?;
    Ok(())
}

pub async fn add_submodule(
    repo_path: impl AsRef<Path>,
    submodule_url: &str,
    submodule_path: &str,
    verbose: bool,
) -> Result<()> {
    let repo_path = repo_path.as_ref();

    let mut args = vec!["submodule", "add", submodule_url, submodule_path];
    if !verbose {
        args.insert(2, "--quiet");
    }

    Command::new("git")
        .args(&args)
        .current_dir(repo_path)
        .output()
        .await
        .with_context(|| {
            format!(
                "Failed to add git submodule '{}' at '{}' in directory: {}",
                submodule_url,
                submodule_path,
                repo_path.display()
            )
        })?;

    Ok(())
}

pub async fn get_commit_hash(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();

    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(path)
        .output()
        .await
        .with_context(|| format!("Failed to get commit hash in directory: {}", path.display()))?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "Git rev-parse failed with exit code: {}",
            output.status.code().unwrap_or(-1)
        ));
    }

    let hash = String::from_utf8(output.stdout)?.trim().to_string();

    Ok(hash)
}

#[derive(Debug)]
pub struct GitReference {
    pub base_url: String,
    pub branch: Option<String>,
    pub path: Option<String>,
}

pub fn parse_git_url(input: String) -> Result<GitReference, url::ParseError> {
    let url = Url::parse(&input)?;

    // Remove git+ prefix and fragment to get base URL
    let base_url = {
        let mut u = url.clone();
        u.set_fragment(None);
        u.to_string().trim_start_matches("git+").to_string()
    };

    // Parse fragment for branch:path
    let (branch, path) = if let Some(fragment) = url.fragment() {
        let parts: Vec<&str> = fragment.splitn(2, ':').collect();
        (
            Some(parts[0].to_string()),
            parts.get(1).map(|s| s.to_string()),
        )
    } else {
        (None, None)
    };

    Ok(GitReference {
        base_url,
        branch,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_git_url;
    use anyhow::*;
    #[test]
    fn test_git_url() -> Result<()> {
        let g = parse_git_url(
            "git+https://github.com/gnosisguild/interfold.git#main:template/default".to_string(),
        )?;

        assert_eq!(g.branch, Some("main".to_string()));
        assert_eq!(
            g.base_url,
            "https://github.com/gnosisguild/interfold.git".to_string()
        );

        assert_eq!(g.path, Some("template/default".to_string()));

        Ok(())
    }
}
