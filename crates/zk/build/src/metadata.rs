// SPDX-License-Identifier: LGPL-3.0-only

//! Composition of owner-provided metadata for build tools.

use anyhow::Result;
use e3_committee::{CiphernodesCommitteeSize, CommitteeMetadata};
use e3_fhe_params::metadata::BfvMetadata;
use e3_zk_config::metadata::ZkMetadata;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoMetadata {
    pub format_version: u32,
    pub bfv: BfvMetadata,
    pub zk: ZkMetadata,
    pub committees: Vec<CommitteeMetadata>,
    pub build_pairs: Vec<[String; 2]>,
}

pub fn collect(root: &Path) -> Result<CryptoMetadata> {
    let build_pairs = crate::build_pairs(root)?;
    Ok(CryptoMetadata {
        format_version: 1,
        bfv: BfvMetadata::current()?,
        zk: ZkMetadata::current(),
        committees: CiphernodesCommitteeSize::ALL
            .into_iter()
            .map(CommitteeMetadata::from)
            .collect(),
        build_pairs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn collecting_metadata_does_not_write_to_its_input_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let directory = root.join("scripts/circuits");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("build-pairs.json"),
            r#"[["insecure-64","minimum"]]"#,
        )
        .unwrap();
        let before = crate::tests::snapshot(root);
        collect(root).unwrap();
        assert_eq!(crate::tests::snapshot(root), before);
    }
}
