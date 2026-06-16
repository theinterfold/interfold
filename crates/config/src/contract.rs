// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use alloy_primitives::Address;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Hash, Eq, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Contract {
    Full {
        address: String,
        deploy_block: Option<u64>,
    },
    AddressOnly(String),
}

impl Contract {
    pub fn address_str(&self) -> &str {
        use Contract::*;
        match self {
            Full { address, .. } => address,
            AddressOnly(v) => v,
        }
    }

    pub fn address(&self) -> Result<Address> {
        let addr = self.address_str().parse()?;
        Ok(addr)
    }

    pub fn deploy_block(&self) -> Option<u64> {
        use Contract::*;
        match self {
            Full { deploy_block, .. } => *deploy_block,
            AddressOnly(_) => None,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize, Serialize)]
pub struct ContractAddresses {
    pub interfold: Contract,
    pub ciphernode_registry: Contract,
    pub bonding_registry: Contract,
    pub e3_program: Option<Contract>,
    pub fee_token: Option<Contract>,
    pub slashing_manager: Option<Contract>,
    pub dkg_fold_attestation_verifier: Option<Contract>,
}

impl ContractAddresses {
    pub fn contracts(&self) -> Vec<&Contract> {
        [
            Some(&self.interfold),
            Some(&self.ciphernode_registry),
            Some(&self.bonding_registry),
            self.e3_program.as_ref(),
            self.fee_token.as_ref(),
            self.slashing_manager.as_ref(),
            self.dkg_fold_attestation_verifier.as_ref(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}
