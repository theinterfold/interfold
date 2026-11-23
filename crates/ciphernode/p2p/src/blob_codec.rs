// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Compact binary codecs for batched blob transfers and direct pairwise messages.
//!
//! Avoiding CBOR and writing/reading raw blob bytes directly from `Arc<[u8]>` eliminates both
//! redundant framing overhead and extra multi-megabyte copies on the hot blob-transfer path.

use crate::behaviour::{MAX_BLOB_BYTES, MAX_ENVELOPE_BYTES};
use alloy_primitives::B256;
use async_trait::async_trait;
use e3_protocol::{wire::PeerProof, E3Id};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{request_response, StreamProtocol};
use serde::{Deserialize, Serialize};
use std::{io, sync::Arc};

/// Maximum number of blobs requested in a single batched stream request.
pub(crate) const MAX_BATCH_BLOBS: usize = 16;
/// Soft target byte budget when grouping multiple blobs into a single batch request.
/// A single blob larger than this (up to [`MAX_BLOB_BYTES`]) still travels alone in a 1-item batch.
pub(crate) const MAX_BATCH_BYTES: u64 = 16 * 1024 * 1024;
/// Hard ceiling on a batch request envelope (E3Id + PeerProof + up to 16 hashes).
const MAX_BLOB_REQUEST_BYTES: usize = 4 * 1024;
/// Hard ceiling on total raw blob bytes inside one batch response.
const MAX_BATCH_RESPONSE_BYTES: u64 = MAX_BLOB_BYTES + MAX_BATCH_BYTES;
/// Hard ceiling on a serialized PeerProof inside a direct message.
const MAX_PROOF_BYTES: usize = 1024;

/// A request for one or more public blobs of an E3, and the requester's proof of identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BlobBatchRequest {
    pub(crate) e3: E3Id,
    pub(crate) hashes: Vec<B256>,
    pub(crate) requester: PeerProof,
}

/// Ordered responses corresponding 1-to-1 with [`BlobBatchRequest::hashes`].
#[derive(Clone, Debug)]
pub(crate) struct BlobBatchResponse {
    pub(crate) items: Vec<Option<Arc<[u8]>>>,
}

#[derive(Clone, Default)]
pub(crate) struct BlobBatchCodec;

#[async_trait]
impl request_response::Codec for BlobBatchCodec {
    type Protocol = StreamProtocol;
    type Request = BlobBatchRequest;
    type Response = BlobBatchResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let len = read_u32(io).await? as usize;
        if len == 0 || len > MAX_BLOB_REQUEST_BYTES {
            return Err(invalid("blob request exceeds limit"));
        }
        let mut buf = vec![0u8; len];
        io.read_exact(&mut buf).await?;
        let req: BlobBatchRequest = bincode::deserialize(&buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if req.hashes.is_empty() || req.hashes.len() > MAX_BATCH_BLOBS {
            return Err(invalid("blob batch count out of range"));
        }
        Ok(req)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let count = read_u16(io).await? as usize;
        if count > MAX_BATCH_BLOBS {
            return Err(invalid("blob response count exceeds limit"));
        }
        let mut items = Vec::with_capacity(count);
        let mut total_bytes: u64 = 0;
        for _ in 0..count {
            let mut tag = [0u8; 1];
            io.read_exact(&mut tag).await?;
            match tag[0] {
                0 => items.push(None),
                1 => {
                    let len = read_u32(io).await? as u64;
                    if len > MAX_BLOB_BYTES {
                        return Err(invalid("blob exceeds maximum size"));
                    }
                    total_bytes = total_bytes
                        .checked_add(len)
                        .filter(|&sum| sum <= MAX_BATCH_RESPONSE_BYTES)
                        .ok_or_else(|| invalid("blob batch response exceeds size limit"))?;
                    let mut buf = vec![0u8; len as usize];
                    io.read_exact(&mut buf).await?;
                    items.push(Some(Arc::from(buf)));
                }
                _ => return Err(invalid("invalid blob item tag")),
            }
        }
        Ok(BlobBatchResponse { items })
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if req.hashes.is_empty() || req.hashes.len() > MAX_BATCH_BLOBS {
            return Err(invalid("blob batch count out of range"));
        }
        let encoded =
            bincode::serialize(&req).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if encoded.len() > MAX_BLOB_REQUEST_BYTES {
            return Err(invalid("blob request exceeds limit"));
        }
        io.write_all(&(encoded.len() as u32).to_be_bytes()).await?;
        io.write_all(&encoded).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if res.items.len() > MAX_BATCH_BLOBS {
            return Err(invalid("blob response count exceeds limit"));
        }
        io.write_all(&(res.items.len() as u16).to_be_bytes())
            .await?;
        for item in res.items {
            match item {
                None => io.write_all(&[0u8]).await?,
                Some(bytes) => {
                    let len = u32::try_from(bytes.len())
                        .map_err(|_| invalid("blob exceeds u32 length"))?;
                    if len as u64 > MAX_BLOB_BYTES {
                        return Err(invalid("blob exceeds maximum size"));
                    }
                    let mut header = [0u8; 5];
                    header[0] = 1;
                    header[1..5].copy_from_slice(&len.to_be_bytes());
                    io.write_all(&header).await?;
                    io.write_all(&bytes).await?;
                }
            }
        }
        io.close().await
    }
}

/// A recipient-targeted signed envelope delivered directly to its recipient over QUIC.
#[derive(Clone, Debug)]
pub(crate) struct DirectMessage {
    pub(crate) envelope: Vec<u8>,
    pub(crate) sender_proof: PeerProof,
}

/// Whether the recipient accepted and queued the direct message (`false` triggers gossip fallback).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectAck(pub(crate) bool);

#[derive(Clone, Default)]
pub(crate) struct DirectCodec;

#[async_trait]
impl request_response::Codec for DirectCodec {
    type Protocol = StreamProtocol;
    type Request = DirectMessage;
    type Response = DirectAck;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let proof_len = read_u32(io).await? as usize;
        if proof_len == 0 || proof_len > MAX_PROOF_BYTES {
            return Err(invalid("direct sender proof exceeds limit"));
        }
        let mut proof_buf = vec![0u8; proof_len];
        io.read_exact(&mut proof_buf).await?;
        let sender_proof: PeerProof = bincode::deserialize(&proof_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let env_len = read_u32(io).await? as usize;
        if env_len == 0 || env_len > MAX_ENVELOPE_BYTES {
            return Err(invalid("direct envelope exceeds limit"));
        }
        let mut envelope = vec![0u8; env_len];
        io.read_exact(&mut envelope).await?;
        Ok(DirectMessage {
            envelope,
            sender_proof,
        })
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut ack = [0u8; 1];
        io.read_exact(&mut ack).await?;
        Ok(DirectAck(ack[0] != 0))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let proof_buf = bincode::serialize(&req.sender_proof)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if proof_buf.len() > MAX_PROOF_BYTES || req.envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(invalid("direct message exceeds limit"));
        }
        io.write_all(&(proof_buf.len() as u32).to_be_bytes())
            .await?;
        io.write_all(&proof_buf).await?;
        io.write_all(&(req.envelope.len() as u32).to_be_bytes())
            .await?;
        io.write_all(&req.envelope).await?;
        io.close().await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[u8::from(res.0)]).await?;
        io.close().await
    }
}

async fn read_u16<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    io.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

async fn read_u32<T: AsyncRead + Unpin>(io: &mut T) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    io.read_exact(&mut buf).await?;
    Ok(u32::from_be_bytes(buf))
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
