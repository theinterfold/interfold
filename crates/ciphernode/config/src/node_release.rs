// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::{keccak256, B256};
use serde::Deserialize;
use std::sync::OnceLock;

const RELEASE_DOMAIN: &str = "interfold.node.release:v1:";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct NodeRelease {
    pub protocol_version: u32,
    pub node_generation: u32,
}

impl NodeRelease {
    pub fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    pub fn release_id(&self) -> B256 {
        keccak256(format!("{RELEASE_DOMAIN}{}", self.version()))
    }
}

pub fn current_node_release() -> &'static NodeRelease {
    static RELEASE: OnceLock<NodeRelease> = OnceLock::new();
    RELEASE.get_or_init(|| {
        toml::from_str(include_str!("../protocol-release.toml"))
            .expect("protocol-release.toml must contain valid release versions")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_release_has_nonzero_compatibility_versions() {
        let release = current_node_release();
        assert_ne!(release.protocol_version, 0);
        assert_ne!(release.node_generation, 0);
        assert_ne!(release.release_id(), B256::ZERO);
    }
}
