// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::path::PathBuf;

use anyhow::Result;
use serde_json::{Map, Value};
use tokio::fs;

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum DependencyType {
    Dependencies,
    DevDependencies,
    PeerDependencies,
}

impl DependencyType {
    fn as_key(&self) -> &'static str {
        match self {
            DependencyType::Dependencies => "dependencies",
            DependencyType::DevDependencies => "devDependencies",
            DependencyType::PeerDependencies => "peerDependencies",
        }
    }
}

pub async fn get_version_from_package_json(file_path: &PathBuf) -> Result<String> {
    let content = fs::read_to_string(file_path).await?;
    let json: Value = serde_json::from_str(&content)?;

    json["version"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("version field not found or not a string"))
}

pub async fn add_package_to_json(
    file_path: &PathBuf,
    package_name: &str,
    version: &str,
    dep_type: DependencyType,
) -> Result<()> {
    let dep_key = dep_type.as_key();
    let content = fs::read_to_string(file_path).await?;

    let mut json: Value = serde_json::from_str(&content)?;

    let obj = json
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("package.json root is not an object"))?;

    let deps = obj
        .entry(dep_key)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not an object", dep_key))?;

    deps.insert(package_name.to_string(), Value::String(version.to_string()));

    let formatted_json = serde_json::to_string_pretty(&json)?;
    fs::write(file_path, formatted_json).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_dev_dependency_keeps_existing_fields() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("package.json");
        fs::write(&path, r#"{"version":"1.2.3","devDependencies":{"a":"1"}}"#)
            .await
            .unwrap();

        add_package_to_json(&path, "b", "2", DependencyType::DevDependencies)
            .await
            .unwrap();

        let saved: Value = serde_json::from_str(&fs::read_to_string(&path).await.unwrap()).unwrap();
        assert_eq!(
            saved["devDependencies"],
            serde_json::json!({"a": "1", "b": "2"})
        );
        assert_eq!(get_version_from_package_json(&path).await.unwrap(), "1.2.3");
    }
}
