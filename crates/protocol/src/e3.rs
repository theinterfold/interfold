// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! One E3 at this node: its stage, its DKG from the committee's finalization, and its decryption
//! from the key's publication.

use crate::{
    decryption::{Decryption, Handover, PublishedKey},
    dkg::{AttestationContext, Dkg, DkgTiming},
    node::{Body, CryptoParams, Effect, PeerMessage, Purpose, Stage, WorkResult},
    resend::Resend,
    BlobRef, E3Id, UnixSecs,
};
use alloy_primitives::{Address, Bytes, B256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct E3 {
    id: E3Id,
    me: Address,
    pub stage: Stage,
    pub params: CryptoParams,
    /// The Interfold contract that holds the request.
    pub interfold: Address,
    pub attestation: AttestationContext,
    /// From the committee's finalization on; a node outside the committee ends the E3 instead.
    pub dkg: Option<Dkg>,
    /// From the key's publication on.
    pub decryption: Option<Decryption>,
    /// When a failed E3's accusation work ends.
    pub ends_at: Option<UnixSecs>,
    resend: Resend,
}

impl E3 {
    pub(crate) fn new(
        id: E3Id,
        me: Address,
        params: CryptoParams,
        interfold: Address,
        attestation: AttestationContext,
    ) -> Self {
        Self {
            id,
            me,
            stage: Stage::Requested,
            params,
            interfold,
            attestation,
            dkg: None,
            decryption: None,
            ends_at: None,
            resend: Resend::default(),
        }
    }

    pub(crate) fn finalize(
        &mut self,
        now: UnixSecs,
        members: Vec<Address>,
        timing: DkgTiming,
    ) -> Vec<Effect> {
        let (dkg, effects) = Dkg::start(
            self.id,
            self.me,
            members,
            self.params,
            timing,
            self.attestation,
            now,
        );
        self.dkg = Some(dkg);
        self.stage = Stage::CommitteeFinalized;
        self.sent(now, effects)
    }

    /// The chain's key, committee order, and roster are the authority for decryption. This node's
    /// DKG supplies its sealed decryption key only if it summed that key over the same roster;
    /// shares from a key over another roster would not combine.
    pub(crate) fn key_published(
        &mut self,
        committee: Vec<Address>,
        roster: Vec<Address>,
        commitment: B256,
    ) {
        let Some(dkg) = &mut self.dkg else {
            return;
        };
        dkg.key_published();
        let same_roster = dkg.roster_members().as_ref() == Some(&roster);
        let key = dkg.decryption_key().filter(|_| same_roster);
        let handover = Handover {
            roster,
            key,
            expelled: dkg.expelled().clone(),
        };
        let published = PublishedKey {
            interfold: self.interfold,
            committee,
            commitment,
        };
        let members = dkg.members().to_vec();
        self.decryption = Some(Decryption::new(
            self.id,
            self.me,
            members,
            self.params,
            handover,
            published,
        ));
    }

    pub(crate) fn ciphertext_ready(
        &mut self,
        now: UnixSecs,
        ciphertext: BlobRef,
        deadline: UnixSecs,
    ) -> Vec<Effect> {
        let effects = match self.decryption_mut() {
            Some(decryption) => decryption.ciphertext_ready(now, ciphertext, deadline),
            None => Vec::new(),
        };
        self.sent(now, effects)
    }

    /// Whether a message of `body`'s kind has its handler here yet; until then it waits in the
    /// hold.
    pub(crate) fn routes(&self, body: &Body) -> bool {
        match body {
            Body::Dkg(_) => self.dkg.is_some(),
            Body::Decryption(_) => self.decryption.is_some(),
        }
    }

    pub(crate) fn receive(&mut self, now: UnixSecs, message: PeerMessage) -> Vec<Effect> {
        let effects = match message.body {
            Body::Dkg(body) => match self.dkg_mut() {
                Some(dkg) => dkg.receive(now, message.sender, body),
                None => Vec::new(),
            },
            Body::Decryption(body) => match self.decryption_mut() {
                Some(decryption) => decryption.receive(now, message.sender, body),
                None => Vec::new(),
            },
        };
        self.sent(now, effects)
    }

    pub(crate) fn job_done(&mut self, now: UnixSecs, result: WorkResult) -> Vec<Effect> {
        let effects = match result {
            WorkResult::Dkg(result) => match self.dkg_mut() {
                Some(dkg) => dkg.job_done(now, result),
                None => Vec::new(),
            },
            WorkResult::Decryption(result) => match self.decryption_mut() {
                Some(decryption) => decryption.job_done(now, result),
                None => Vec::new(),
            },
        };
        self.sent(now, effects)
    }

    pub(crate) fn signed(
        &mut self,
        now: UnixSecs,
        purpose: Purpose,
        signatures: Vec<Bytes>,
    ) -> Vec<Effect> {
        let effects = match purpose {
            Purpose::Dkg(purpose) => match self.dkg_mut() {
                Some(dkg) => dkg.signed(now, purpose, signatures),
                None => Vec::new(),
            },
            Purpose::Decryption(purpose) => match self.decryption_mut() {
                Some(decryption) => decryption.signed(now, purpose, signatures),
                None => Vec::new(),
            },
        };
        self.sent(now, effects)
    }

    pub(crate) fn expel(&mut self, now: UnixSecs, member: Address) -> Vec<Effect> {
        let mut effects = Vec::new();
        if let Some(dkg) = self.dkg_mut() {
            effects.extend(dkg.expel(now, member));
        }
        if let Some(decryption) = self.decryption_mut() {
            effects.extend(decryption.expel(now, member));
        }
        self.sent(now, effects)
    }

    pub(crate) fn pass_deadlines(&mut self, now: UnixSecs) -> Vec<Effect> {
        let mut effects = Vec::new();
        if let Some(dkg) = self.dkg_mut() {
            effects.extend(dkg.pass_deadlines(now));
        }
        if let Some(decryption) = self.decryption_mut() {
            effects.extend(decryption.pass_deadlines(now));
        }
        let mut effects = self.sent(now, effects);
        let (dkg_runs, decryption_runs) = self.work_running();
        let again = self.resend.due(now, |body| match body {
            Body::Dkg(_) => dkg_runs,
            Body::Decryption(_) => decryption_runs,
        });
        effects.extend(again.into_iter().map(Effect::Gossip));
        effects
    }

    pub(crate) fn next_deadline(&self) -> Option<UnixSecs> {
        let (dkg_runs, decryption_runs) = self.work_running();
        let work = self.running().then(|| {
            let dkg = self.dkg.as_ref().and_then(Dkg::next_deadline);
            let decryption = self.decryption.as_ref().and_then(Decryption::next_deadline);
            let resend = self.resend.next_deadline(|body| match body {
                Body::Dkg(_) => dkg_runs,
                Body::Decryption(_) => decryption_runs,
            });
            dkg.into_iter().chain(decryption).chain(resend).min()
        });
        self.ends_at.into_iter().chain(work.flatten()).min()
    }

    /// Keep this node's messages for sending again while their work runs.
    fn sent(&mut self, now: UnixSecs, effects: Vec<Effect>) -> Vec<Effect> {
        for effect in &effects {
            if let Effect::Gossip(message) = effect {
                self.resend.record(now, message.clone());
            }
        }
        effects
    }

    /// Whether the DKG, and decryption, still run here.
    fn work_running(&self) -> (bool, bool) {
        let dkg = self.dkg.as_ref().is_some_and(Dkg::running);
        let decryption = self.decryption.as_ref().is_some_and(Decryption::running);
        (self.running() && dkg, self.running() && decryption)
    }

    /// The chain has not failed the E3; after a failure only accusation work remains.
    fn running(&self) -> bool {
        self.stage != Stage::Failed
    }

    fn dkg_mut(&mut self) -> Option<&mut Dkg> {
        let running = self.running();
        self.dkg.as_mut().filter(|_| running)
    }

    fn decryption_mut(&mut self) -> Option<&mut Decryption> {
        let running = self.running();
        self.decryption.as_mut().filter(|_| running)
    }
}
