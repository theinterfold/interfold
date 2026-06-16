// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

mod zk;

pub use zk::*;

use core::fmt;

use actix::Message;
use anyhow::bail;
use e3_trbfv::{
    calculate_decryption_key::CalculateDecryptionKeyResponse,
    calculate_decryption_share::CalculateDecryptionShareResponse,
    calculate_threshold_decryption::CalculateThresholdDecryptionResponse,
    gen_esi_sss::GenEsiSssResponse, gen_pk_share_and_sk_sss::GenPkShareAndSkSssResponse,
    TrBFVResponse,
};
use serde::{Deserialize, Serialize};

use crate::{CorrelationId, E3id};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComputeRequestKind {
    TrBFV(e3_trbfv::TrBFVRequest),
    Zk(ZkRequest),
}

/// Variants for compute response kinds.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComputeResponseKind {
    TrBFV(e3_trbfv::TrBFVResponse),
    Zk(ZkResponse),
}

/// The compute instruction for a threadpool computation.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct ComputeRequest {
    pub request: ComputeRequestKind,
    pub correlation_id: CorrelationId,
    pub e3_id: E3id, // It may come to pass this should be option
                     // but our initial need is only within the e3 flow
}

impl ComputeRequest {
    pub fn new(request: ComputeRequestKind, correlation_id: CorrelationId, e3_id: E3id) -> Self {
        Self {
            request,
            correlation_id,
            e3_id,
        }
    }

    pub fn trbfv(
        request: e3_trbfv::TrBFVRequest,
        correlation_id: CorrelationId,
        e3_id: E3id,
    ) -> Self {
        Self::new(ComputeRequestKind::TrBFV(request), correlation_id, e3_id)
    }

    pub fn zk(request: ZkRequest, correlation_id: CorrelationId, e3_id: E3id) -> Self {
        Self::new(ComputeRequestKind::Zk(request), correlation_id, e3_id)
    }
}

impl fmt::Display for ComputeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match &self.request {
            ComputeRequestKind::TrBFV(req) => match req {
                e3_trbfv::TrBFVRequest::GenEsiSss(_) => "GenEsiSss",
                e3_trbfv::TrBFVRequest::GenPkShareAndSkSss(_) => "GenPkShareAndSkSss",
                e3_trbfv::TrBFVRequest::CalculateDecryptionKey(_) => "CalculateDecryptionKey",
                e3_trbfv::TrBFVRequest::CalculateDecryptionShare(_) => "CalculateDecryptionShare",
                e3_trbfv::TrBFVRequest::CalculateThresholdDecryption(_) => {
                    "CalculateThresholdDecryption"
                }
            },
            ComputeRequestKind::Zk(req) => match req {
                ZkRequest::PkBfv(_) => "ZkPkBfv",
                ZkRequest::PkGeneration(_) => "ZkPkGeneration",
                ZkRequest::ShareComputation(_) => "ZkShareComputation",
                ZkRequest::ShareEncryption(_) => "ZkShareEncryption",
                ZkRequest::DkgShareDecryption(_) => "ZkDkgShareDecryption",
                ZkRequest::VerifyShareProofs(_) => "ZkVerifyShareProofs",
                ZkRequest::VerifyShareDecryptionProofs(_) => "ZkVerifyShareDecryptionProofs",
                ZkRequest::PkAggregation(_) => "ZkPkAggregation",
                ZkRequest::ThresholdShareDecryption(_) => "ZkThresholdShareDecryption",
                ZkRequest::DecryptedSharesAggregation(_) => "ZkDecryptedSharesAggregation",
                ZkRequest::NodeDkgFold(_) => "ZkNodeDkgFold",
                ZkRequest::NodesFoldStep(_) => "ZkNodesFoldStep",
                ZkRequest::DkgAggregation(_) => "ZkDkgAggregation",
                ZkRequest::DecryptionAggregation(_) => "ZkDecryptionAggregation",
            },
        };
        write!(f, "{}", s)
    }
}

/// The compute result from a threadpool computation.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct ComputeResponse {
    pub response: ComputeResponseKind,
    pub correlation_id: CorrelationId,
    pub e3_id: E3id,
}

impl ComputeResponse {
    pub fn new(response: ComputeResponseKind, correlation_id: CorrelationId, e3_id: E3id) -> Self {
        Self {
            response,
            correlation_id,
            e3_id,
        }
    }

    pub fn trbfv(
        response: e3_trbfv::TrBFVResponse,
        correlation_id: CorrelationId,
        e3_id: E3id,
    ) -> Self {
        Self::new(ComputeResponseKind::TrBFV(response), correlation_id, e3_id)
    }

    pub fn zk(response: ZkResponse, correlation_id: CorrelationId, e3_id: E3id) -> Self {
        Self::new(ComputeResponseKind::Zk(response), correlation_id, e3_id)
    }

    pub fn try_into_zk(self) -> anyhow::Result<ZkResponse> {
        match self.response {
            ComputeResponseKind::Zk(zk) => Ok(zk),
            _ => bail!("Expected ZkResponse but got TrBFV"),
        }
    }

    pub fn try_into_trbfv(self) -> anyhow::Result<TrBFVResponse> {
        match self.response {
            ComputeResponseKind::TrBFV(trbfv) => Ok(trbfv),
            _ => bail!("Expected TrBFVResponse but got Zk"),
        }
    }
}

/// An error from a threadpool computation.
#[derive(Message, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[rtype(result = "()")]
pub struct ComputeRequestError {
    kind: ComputeRequestErrorKind,
    request: ComputeRequest,
}

impl ComputeRequestError {
    pub fn new(kind: ComputeRequestErrorKind, request: ComputeRequest) -> Self {
        Self { kind, request }
    }

    pub fn get_err(&self) -> &ComputeRequestErrorKind {
        &self.kind
    }

    pub fn correlation_id(&self) -> &CorrelationId {
        &self.request.correlation_id
    }

    pub fn request(&self) -> &ComputeRequest {
        &self.request
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComputeRequestErrorKind {
    TrBFV(e3_trbfv::TrBFVError),
    Zk(ZkError),
}

impl std::error::Error for ComputeRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.get_err() {
            ComputeRequestErrorKind::TrBFV(err) => Some(err),
            ComputeRequestErrorKind::Zk(err) => Some(err),
        }
    }
}

impl fmt::Display for ComputeRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.get_err() {
            ComputeRequestErrorKind::TrBFV(err) => {
                write!(f, "TrBFV computation error: {:?}", err)
            }
            ComputeRequestErrorKind::Zk(err) => {
                write!(f, "ZK proof error: {}", err)
            }
        }
    }
}

impl TryFrom<ComputeResponse> for CalculateDecryptionShareResponse {
    type Error = anyhow::Error;
    fn try_from(value: ComputeResponse) -> Result<Self, Self::Error> {
        match value.response {
            ComputeResponseKind::TrBFV(TrBFVResponse::CalculateDecryptionShare(data)) => Ok(data),
            _ => {
                bail!("Expected CalculateDecryptionShareResponse in response but it was not found")
            }
        }
    }
}

impl TryFrom<ComputeResponse> for CalculateDecryptionKeyResponse {
    type Error = anyhow::Error;
    fn try_from(value: ComputeResponse) -> Result<Self, Self::Error> {
        match value.response {
            ComputeResponseKind::TrBFV(TrBFVResponse::CalculateDecryptionKey(data)) => Ok(data),
            _ => {
                bail!("Expected CalculateDecryptionKeyResponse in response but it was not found")
            }
        }
    }
}

impl TryFrom<ComputeResponse> for GenPkShareAndSkSssResponse {
    type Error = anyhow::Error;
    fn try_from(value: ComputeResponse) -> Result<Self, Self::Error> {
        match value.response {
            ComputeResponseKind::TrBFV(TrBFVResponse::GenPkShareAndSkSss(data)) => Ok(data),
            _ => {
                bail!("Expected GenPkShareAndSkSssResponse in response but it was not found")
            }
        }
    }
}

impl TryFrom<ComputeResponse> for GenEsiSssResponse {
    type Error = anyhow::Error;
    fn try_from(value: ComputeResponse) -> Result<Self, Self::Error> {
        match value.response {
            ComputeResponseKind::TrBFV(TrBFVResponse::GenEsiSss(data)) => Ok(data),
            _ => {
                bail!("Expected GenEsiSssResponse in response but it was not found")
            }
        }
    }
}

impl TryFrom<ComputeResponse> for CalculateThresholdDecryptionResponse {
    type Error = anyhow::Error;
    fn try_from(value: ComputeResponse) -> Result<Self, Self::Error> {
        match value.response {
            ComputeResponseKind::TrBFV(TrBFVResponse::CalculateThresholdDecryption(data)) => {
                Ok(data)
            }
            _ => {
                bail!(
                    "Expected CalculateThresholdDecryptionResponse in response but it was not found"
                )
            }
        }
    }
}

impl TryFrom<ComputeResponse> for PkBfvProofResponse {
    type Error = anyhow::Error;
    fn try_from(value: ComputeResponse) -> Result<Self, Self::Error> {
        match value.response {
            ComputeResponseKind::Zk(ZkResponse::PkBfv(data)) => Ok(data),
            _ => {
                bail!("Expected PkBfvProofResponse in response but it was not found")
            }
        }
    }
}
