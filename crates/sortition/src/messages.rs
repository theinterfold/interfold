// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

use actix::prelude::*;
use e3_events::E3id;
use std::ops::Deref;

#[derive(Message, Clone, Debug, PartialEq, Eq)]
#[rtype(result = "()")]
pub struct WithSortitionTicket<T> {
    inner: T,
    party_ticket_id: Option<(u64, Option<u64>)>,
    address: String,
}

impl<T> WithSortitionTicket<T> {
    pub fn new(inner: T, party_ticket_id: Option<(u64, Option<u64>)>, address: &str) -> Self {
        Self {
            inner,
            party_ticket_id,
            address: address.to_owned(),
        }
    }

    pub fn is_selected(&self) -> bool {
        self.party_ticket_id.is_some()
    }

    pub fn address(&self) -> &str {
        self.address.as_ref()
    }

    pub fn ticket_id(&self) -> Option<u64> {
        self.party_ticket_id.and_then(|(_, ticket_id)| ticket_id)
    }

    pub fn party_id(&self) -> Option<u64> {
        self.party_ticket_id.map(|(party_id, _)| party_id)
    }
}

impl<T> Deref for WithSortitionTicket<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[derive(Message, Clone, Debug, PartialEq, Eq)]
#[rtype(result = "()")]
pub struct E3CommitteeContainsRequest<T: Send + Sync>
where
    T: Send + Sync,
{
    pub(crate) inner: T,
    pub(crate) e3_id: E3id,
    pub(crate) node: String,
    pub(crate) sender: Recipient<E3CommitteeContainsResponse<T>>,
}

impl<T> E3CommitteeContainsRequest<T>
where
    T: Send + Sync,
{
    pub fn new(
        e3_id: E3id,
        node: String,
        inner: T,
        sender: impl Into<Recipient<E3CommitteeContainsResponse<T>>>,
    ) -> Self {
        Self {
            inner,
            e3_id,
            node,
            sender: sender.into(),
        }
    }
}

#[derive(Message, Clone, Debug, PartialEq, Eq)]
#[rtype(result = "()")]
pub struct E3CommitteeContainsResponse<T: Send + Sync> {
    inner: T,
    is_found_in_committee: bool,
}

impl<T> E3CommitteeContainsResponse<T>
where
    T: Send + Sync,
{
    pub fn new(inner: T, is_found_in_committee: bool) -> Self {
        Self {
            inner,
            is_found_in_committee,
        }
    }

    pub fn is_found_in_committee(&self) -> bool {
        self.is_found_in_committee
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: Send + Sync> Deref for E3CommitteeContainsResponse<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Request the ordered finalized committee member list for an E3.
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct GetCommitteeMembersRequest {
    pub e3_id: E3id,
    pub reply: Recipient<CommitteeMembersResponse>,
}

/// Response with committee members in party-id order (index == party_id).
#[derive(Message, Clone, Debug)]
#[rtype(result = "()")]
pub struct CommitteeMembersResponse {
    /// `None` when the E3 committee is not finalized in sortition yet.
    pub members: Option<Vec<String>>,
}
