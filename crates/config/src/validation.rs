// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use std::str::FromStr;

use url::Url;

#[derive(Clone, Debug)]
pub struct ValidUrl(Url);

impl FromStr for ValidUrl {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ValidUrl(Url::parse(s)?))
    }
}

impl std::fmt::Display for ValidUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<ValidUrl> for String {
    fn from(value: ValidUrl) -> Self {
        value.0.to_string()
    }
}
