// SPDX-License-Identifier: LGPL-3.0-only
//
// This file is provided WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.

//! Gossip loses messages, so a node sends its latest message of each kind again while the work it
//! feeds still runs at this node: first after half a minute, then twice as long each time up to
//! five minutes, for at most eight hours. Receivers keep the first copy, so a repeat changes
//! nothing.

use crate::{
    accusation::{AccusationMessage, Ballot},
    decryption::DecryptionMessage,
    dkg::DkgMessage,
    node::{Body, PeerMessage},
    UnixSecs,
};
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const FIRST_INTERVAL: UnixSecs = 30;
const MAX_INTERVAL: UnixSecs = 5 * 60;
const MAX_SPAN: UnixSecs = 8 * 60 * 60;

/// What a later message replaces: a member's newer Ready report replaces its older one, and shares
/// for one recipient replace only that recipient's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum Slot {
    EncryptionKey,
    Shares(Address),
    Ready,
    Roster,
    DecryptionKey,
    Keyshare,
    NodeFold,
    DecryptionShares,
    /// This node's accusation or vote in one window.
    Accusation(Ballot),
}

impl Slot {
    fn of(body: &Body) -> Self {
        match body {
            Body::Dkg(DkgMessage::EncryptionKey(_)) => Self::EncryptionKey,
            Body::Dkg(DkgMessage::Shares(shares)) => Self::Shares(shares.recipient),
            Body::Dkg(DkgMessage::Ready(_)) => Self::Ready,
            Body::Dkg(DkgMessage::Roster(_)) => Self::Roster,
            Body::Dkg(DkgMessage::DecryptionKey(_)) => Self::DecryptionKey,
            Body::Dkg(DkgMessage::Keyshare(_)) => Self::Keyshare,
            Body::Dkg(DkgMessage::NodeFold(_)) => Self::NodeFold,
            Body::Decryption(DecryptionMessage::Shares(_)) => Self::DecryptionShares,
            Body::Accusation(AccusationMessage::Accuse { vote, .. })
            | Body::Accusation(AccusationMessage::Vote(vote)) => {
                Self::Accusation(Ballot::of(&vote.vote))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Sent {
    message: PeerMessage,
    first: UnixSecs,
    next: UnixSecs,
    interval: UnixSecs,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Resend {
    sent: BTreeMap<Slot, Sent>,
}

impl Resend {
    pub(crate) fn record(&mut self, now: UnixSecs, message: PeerMessage) {
        let sent = Sent {
            message,
            first: now,
            next: now + FIRST_INTERVAL,
            interval: FIRST_INTERVAL,
        };
        self.sent.insert(Slot::of(&sent.message.body), sent);
    }

    /// The messages due again whose work `runs` at this node; messages whose work stopped, or
    /// whose span ended, are dropped.
    pub(crate) fn due(&mut self, now: UnixSecs, runs: impl Fn(&Body) -> bool) -> Vec<PeerMessage> {
        self.sent
            .retain(|_, sent| runs(&sent.message.body) && now < sent.first + MAX_SPAN);
        self.sent
            .values_mut()
            .filter(|sent| sent.next <= now)
            .map(|sent| {
                sent.interval = (sent.interval * 2).min(MAX_INTERVAL);
                sent.next = now + sent.interval;
                sent.message.clone()
            })
            .collect()
    }

    pub(crate) fn next_deadline(&self, runs: impl Fn(&Body) -> bool) -> Option<UnixSecs> {
        self.sent
            .values()
            .filter(|sent| runs(&sent.message.body))
            .map(|sent| sent.next)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{address, e3};

    #[test]
    fn a_message_goes_again_at_doubling_intervals_up_to_five_minutes_for_eight_hours() {
        let mut resend = Resend::default();
        resend.record(
            0,
            PeerMessage {
                e3: e3(1),
                sender: address(1),
                body: Body::Dkg(DkgMessage::Ready(Vec::new())),
            },
        );
        let mut sent_at = Vec::new();
        while let Some(next) = resend.next_deadline(|_| true) {
            if !resend.due(next, |_| true).is_empty() {
                sent_at.push(next);
            }
        }
        assert_eq!(sent_at[..7], [30, 90, 210, 450, 750, 1_050, 1_350]);
        assert!(sent_at.iter().all(|at| *at < MAX_SPAN));
        assert!(*sent_at.last().unwrap() >= MAX_SPAN - MAX_INTERVAL);
    }
}
