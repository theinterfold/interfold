// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait ProgramSupportApi {
    async fn compile(&self) -> Result<()>;
    async fn start(&self) -> Result<()>;
}
