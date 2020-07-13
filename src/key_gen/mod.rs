// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.
//
//
// hbbft is copyright 2018, POA Networks, Ltd.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. All files in the project
// carrying such notice may not be copied, modified, or distributed except
// according to those terms.
//
// Original copied from:
// https://raw.githubusercontent.com/poanetwork/hbbft/10dbf705e4ce9c43e5263f2e1c5227e02d2d20f7/src/sync_key_gen.rs
//
//! A _synchronous_ algorithm for dealerless distributed key generation.
//!
//! This protocol is meant to run in a _completely synchronous_ setting where each node handles all
//! messages in the same order. It can e.g. exchange messages as transactions on top of
//! `HoneyBadger`, or it can run "on-chain", i.e. committing its messages to a blockchain.
//!
//! Its messages are encrypted where necessary, so they can be publicly broadcast.
//!
//! When the protocol completes, every node receives a secret key share suitable for threshold
//! signatures and encryption. The secret master key is not known by anyone. The protocol succeeds
//! if up to _t_ nodes are faulty, where _t_ is the `threshold` parameter. The number of nodes must
//! be at least _2 t + 1_.
//!
//! ## Usage
//!
//! Before beginning the threshold key generation process, each validator needs to generate a
//! regular (non-threshold) key pair and multicast its public key. `KeyGen::new` returns the
//! instance itself and a `Part` message, containing a contribution to the new threshold keys.
//! It needs to be sent to all nodes. `KeyGen::handle_part` in turn produces an `Ack`
//! message, which is also multicast.
//!
//! All nodes must handle the exact same set of `Part` and `Ack` messages. In this sense the
//! algorithm is synchronous: If Alice's `Ack` was handled by Bob but not by Carol, Bob and
//! Carol could receive different public key sets, and secret key shares that don't match. One way
//! to ensure this is to commit the messages to a public ledger before handling them, e.g. by
//! feeding them to a preexisting instance of Honey Badger. The messages will then appear in the
//! same order for everyone.
//!
//! To complete the process, call `KeyGen::generate`. It produces your secret key share and the
//! public key set.
//!
//! While not asynchronous, the algorithm is fault tolerant: It is not necessary to handle a
//! `Part` and all `Ack` messages from every validator. A `Part` is _complete_ if it
//! received at least _2 t + 1_ valid `Ack`s. Only complete `Part`s are used for key
//! generation in the end, and as long as at least one complete `Part` is from a correct node,
//! the new key set is secure. You can use `KeyGen::is_ready` to check whether at least
//! _t + 1_ `Part`s are complete. So all nodes can call `generate` as soon as `is_ready` returns
//! `true`.
//!
//! Alternatively, you can use any stronger criterion, too, as long as all validators call
//! `generate` at the same point, i.e. after handling the same set of messages.
//! `KeyGen::count_complete` returns the number of complete `Part` messages. And
//! `KeyGen::is_node_ready` can be used to check whether a particluar node's `Part` is
//! complete.
//!
//! The `Part` and `Ack` messages alone contain all the information needed for anyone to compute
//! the public key set, and for anyone owning one of the participating secret keys to compute
//! their own secret key share. In particular:
//! * Observer nodes can also use `KeyGen`. For observers, no `Part` and `Ack`
//! messages will be created and they do not need to send anything. On completion, they will only
//! receive the public key set, but no secret key share.
//! * If a participant crashed and lost its `KeyGen` instance, but still has its original
//! key pair, and if the key generation messages were committed to some public ledger, it can
//! create a new `KeyGen`, handle all the messages in order, and compute its secret key share.
//!
//! ## How it works
//!
//! The algorithm is based on ideas from
//! [Distributed Key Generation in the Wild](https://eprint.iacr.org/2012/377.pdf) and
//! [A robust threshold elliptic curve digital signature providing a new verifiable secret sharing scheme](https://www.researchgate.net/profile/Ihab_Ali/publication/4205262_A_robust_threshold_elliptic_curve_digital_signature_providing_a_new_verifiable_secret_sharing_scheme/links/02e7e538f15726323a000000/A-robust-threshold-elliptic-curve-digital-signature-providing-a-new-verifiable-secret-sharing-scheme.pdf?origin=publication_detail).
//!
//! In a trusted dealer scenario, the following steps occur:
//!
//! 1. Dealer generates a `BivarPoly` of degree _t_ and publishes the `BivarCommitment` which is
//!    used to publicly verify the polynomial's values.
//! 2. Dealer sends _row_ _m > 0_ to node number _m_.
//! 3. Node _m_, in turn, sends _value_ number _s_ to node number _s_.
//! 4. This process continues until _2 t + 1_ nodes confirm they have received a valid row. If
//!    there are at most _t_ faulty nodes, we know that at least _t + 1_ correct nodes sent on an
//!    entry of every other node's column to that node.
//! 5. This means every node can reconstruct its column, and the value at _0_ of its column.
//! 6. These values all lie on a univariate polynomial of degree _t_ and can be used as secret keys.
//!
//! In our _dealerless_ environment, at least _t + 1_ nodes each generate a polynomial using the
//! method above. The sum of the secret keys we received from each node is then used as our secret
//! key. No single node knows the secret master key.

pub mod dkg_result;
pub mod message;
pub mod parsec_rng;

#[cfg(test)]
mod tests;

use crate::{DkgResult, SecretId};
use failure::Fail;
use rand::RngCore;
use serde_derive::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use threshold_crypto::ff::Field;
use threshold_crypto::group::CurveAffine;
use threshold_crypto::{
    poly::{BivarCommitment, BivarPoly, Poly},
    serde_impl::FieldWrap,
    Fr, G1Affine, SecretKeyShare,
};

/// A local error while handling an `Ack` or `Part` message, that was not caused by that message
/// being invalid.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum Error {
    /// Unknown sender.
    #[fail(display = "Unknown sender")]
    UnknownSender,
    /// Failed to serialize message.
    #[fail(display = "Serialization error: {}", _0)]
    Serialization(String),
    /// Failed to encrypt message.
    #[fail(display = "Encryption error")]
    Encryption,
}

impl From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Error {
        Error::Serialization(format!("{:?}", err))
    }
}

/// A submission by a validator for the key generation. It must to be sent to all participating
/// nodes and handled by all of them, including the one that produced it.
///
/// The message contains a commitment to a bivariate polynomial, and for each node, an encrypted
/// row of values. If this message receives enough `Ack`s, it will be used as summand to produce
/// the the key set in the end.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Part(BivarCommitment, Vec<Vec<u8>>);

impl Debug for Part {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Part")
            .field(&format!("<degree {}>", self.0.degree()))
            .field(&format!("<{} rows>", self.1.len()))
            .finish()
    }
}

/// A confirmation that we have received and verified a validator's part. It must be sent to
/// all participating nodes and handled by all of them, including ourselves.
///
/// The message is only produced after we verified our row against the commitment in the `Part`.
/// For each node, it contains one encrypted value of that row.
#[derive(Deserialize, Serialize, Clone, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct Ack(u64, Vec<Vec<u8>>);

impl Debug for Ack {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ack")
            .field(&self.0)
            .field(&format!("<{} values>", self.1.len()))
            .finish()
    }
}

/// The information needed to track a single proposer's secret sharing process.
#[derive(Debug, PartialEq, Eq)]
struct ProposalState {
    /// The proposer's commitment.
    commit: BivarCommitment,
    /// The verified values we received from `Ack` messages.
    values: BTreeMap<u64, Fr>,
    /// The nodes which have acked this part, valid or not.
    acks: BTreeSet<u64>,
}

impl ProposalState {
    /// Creates a new part state with a commitment.
    fn new(commit: BivarCommitment) -> ProposalState {
        ProposalState {
            commit,
            values: BTreeMap::new(),
            acks: BTreeSet::new(),
        }
    }

    /// Returns `true` if at least `2 * threshold + 1` nodes have acked.
    fn is_complete(&self, threshold: usize) -> bool {
        self.acks.len() > 2 * threshold
    }
}

#[cfg(feature = "dump-graphs")]
impl serde::Serialize for ProposalState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let values: Vec<_> = self
            .values
            .iter()
            .map(|(idx, fr)| (*idx, FieldWrap(fr)))
            .collect();
        (&self.commit, values, &self.acks).serialize(s)
    }
}

impl<'a> serde::Deserialize<'a> for ProposalState {
    fn deserialize<D: serde::Deserializer<'a>>(deserializer: D) -> Result<Self, D::Error> {
        let (commit, values, acks) = serde::Deserialize::deserialize(deserializer)?;
        let values: Vec<(u64, FieldWrap<Fr>)> = values;
        Ok(Self {
            commit,
            values: values.into_iter().map(|(idx, fr)| (idx, fr.0)).collect(),
            acks,
        })
    }
}

/// The outcome of handling and verifying a `Part` message.
pub enum PartOutcome {
    /// The message was valid: the part of it that was encrypted to us matched the public
    /// commitment, so we can multicast an `Ack` message for it. If we are an observer or we have
    /// already handled the same `Part` before, this contains `None` instead.
    Valid(Option<Ack>),
    /// The message was invalid: We now know that the proposer is faulty, and dont' send an `Ack`.
    Invalid(PartFault),
}

/// The outcome of handling and verifying an `Ack` message.
pub enum AckOutcome {
    /// The message was valid.
    Valid,
    /// The message was invalid: The sender is faulty.
    Invalid(AckFault),
}

/// A synchronous algorithm for dealerless distributed key generation.
///
/// It requires that all nodes handle all messages in the exact same order.
#[cfg_attr(feature = "dump-graphs", derive(Serialize))]
#[derive(Deserialize)]
pub struct KeyGen<S: SecretId> {
    /// Our node ID.
    our_id: S::PublicId,
    /// Our node index.
    our_idx: Option<u64>,
    /// The public keys of all nodes, by node ID.
    pub_keys: BTreeSet<S::PublicId>,
    /// Proposed bivariate polynomials.
    parts: BTreeMap<u64, ProposalState>,
    /// The degree of the generated polynomial.
    threshold: usize,
}

impl<S: SecretId> KeyGen<S> {
    /// Creates a new `KeyGen` instance, together with the `Part` message that should be
    /// multicast to all nodes.
    ///
    /// If we are not a validator but only an observer, no `Part` message is produced and no
    /// messages need to be sent.
    pub fn new(
        sec_key: &S,
        pub_keys: BTreeSet<S::PublicId>,
        threshold: usize,
        mut rng: &mut dyn RngCore,
    ) -> Result<(KeyGen<S>, Option<Part>), Error> {
        let our_id = sec_key.public_id().clone();
        let our_idx = pub_keys
            .iter()
            .position(|id| *id == our_id)
            .map(|idx| idx as u64);
        let key_gen = KeyGen {
            our_id,
            our_idx,
            pub_keys,
            parts: BTreeMap::new(),
            threshold,
        };
        if our_idx.is_none() {
            return Ok((key_gen, None)); // No part: we are an observer.
        }

        let our_part = BivarPoly::random(threshold, &mut rng);
        let commit = our_part.commitment();
        let encrypt = |(i, pk): (usize, &S::PublicId)| {
            let row = our_part.row(i + 1);
            sec_key
                .encrypt(pk, &bincode::serialize(&row)?)
                .ok_or(Error::Encryption)
        };
        let rows = key_gen
            .pub_keys
            .iter()
            .enumerate()
            .map(encrypt)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok((key_gen, Some(Part(commit, rows))))
    }

    #[allow(unused)]
    /// Returns the map of participating nodes and their public keys.
    pub fn public_keys(&self) -> &BTreeSet<S::PublicId> {
        &self.pub_keys
    }

    /// Handles a `Part` message. If it is valid, returns an `Ack` message to be broadcast.
    ///
    /// If we are only an observer, `None` is returned instead and no messages need to be sent.
    ///
    /// All participating nodes must handle the exact same sequence of messages.
    /// Note that `handle_part` also needs to explicitly be called with this instance's own `Part`.
    pub fn handle_part(
        &mut self,
        sec_key: &S,
        sender_id: &S::PublicId,
        part: Part,
    ) -> Result<PartOutcome, Error> {
        let sender_idx = self.node_index(sender_id).ok_or(Error::UnknownSender)?;
        let row = match self.handle_part_or_fault(sec_key, sender_idx, sender_id, part) {
            Ok(Some(row)) => row,
            Ok(None) => return Ok(PartOutcome::Valid(None)),
            Err(fault) => return Ok(PartOutcome::Invalid(fault)),
        };
        // The row is valid. Encrypt one value for each node and broadcast an `Ack`.
        let mut values = Vec::new();
        for (idx, pk) in self.pub_keys.iter().enumerate() {
            let val = row.evaluate(idx + 1);
            let ser_val = bincode::serialize(&FieldWrap(val))?;
            values.push(sec_key.encrypt(pk, ser_val).ok_or(Error::Encryption)?);
        }
        Ok(PartOutcome::Valid(Some(Ack(sender_idx, values))))
    }

    /// Handles an `Ack` message.
    ///
    /// All participating nodes must handle the exact same sequence of messages.
    /// Note that `handle_ack` also needs to explicitly be called with this instance's own `Ack`s.
    pub fn handle_ack(
        &mut self,
        sec_key: &S,
        sender_id: &S::PublicId,
        ack: Ack,
    ) -> Result<AckOutcome, Error> {
        let sender_idx = self.node_index(sender_id).ok_or(Error::UnknownSender)?;
        Ok(
            match self.handle_ack_or_fault(sec_key, sender_id, sender_idx, ack) {
                Ok(()) => AckOutcome::Valid,
                Err(fault) => AckOutcome::Invalid(fault),
            },
        )
    }

    /// Returns the index of the node, or `None` if it is unknown.
    fn node_index(&self, node_id: &S::PublicId) -> Option<u64> {
        self.pub_keys
            .iter()
            .position(|id| id == node_id)
            .map(|idx| idx as u64)
    }

    /// Returns the number of complete parts. If this is at least `threshold + 1`, the keys can
    /// be generated, but it is possible to wait for more to increase security.
    pub fn count_complete(&self) -> usize {
        self.parts
            .values()
            .filter(|part| part.is_complete(self.threshold))
            .count()
    }

    /// Returns `true` if enough parts are complete to safely generate the new key.
    pub fn is_ready(&self) -> bool {
        self.count_complete() > self.threshold
    }

    /// Returns the new secret key share and the public key set.
    ///
    /// These are only secure if `is_ready` returned `true`. Otherwise it is not guaranteed that
    /// none of the nodes knows the secret master key.
    ///
    /// If we are only an observer node, no secret key share is returned.
    ///
    /// All participating nodes must have handled the exact same sequence of `Part` and `Ack`
    /// messages before calling this method. Otherwise their key shares will not match.
    pub fn generate(&self) -> Result<(BTreeSet<S::PublicId>, DkgResult), Error> {
        let mut pk_commit = Poly::zero().commitment();
        let mut opt_sk_val = self.our_idx.map(|_| Fr::zero());
        let is_complete = |part: &&ProposalState| part.is_complete(self.threshold);
        for part in self.parts.values().filter(is_complete) {
            pk_commit += part.commit.row(0);
            if let Some(sk_val) = opt_sk_val.as_mut() {
                let row = Poly::interpolate(part.values.iter().take(self.threshold + 1));
                sk_val.add_assign(&row.evaluate(0));
            }
        }
        let opt_sk = if let Some(mut fr) = opt_sk_val {
            let sk = SecretKeyShare::from_mut(&mut fr);
            Some(sk)
        } else {
            None
        };
        Ok((
            self.pub_keys.clone(),
            DkgResult::new(pk_commit.into(), opt_sk),
        ))
    }

    /// Handles a `Part` message, or returns a `PartFault` if it is invalid.
    fn handle_part_or_fault(
        &mut self,
        sec_key: &S,
        sender_idx: u64,
        sender_id: &S::PublicId,
        Part(commit, rows): Part,
    ) -> Result<Option<Poly>, PartFault> {
        if rows.len() != self.pub_keys.len() {
            return Err(PartFault::RowCount);
        }
        if let Some(state) = self.parts.get(&sender_idx) {
            if state.commit != commit {
                return Err(PartFault::MultipleParts);
            }
            return Ok(None); // We already handled this `Part` before.
        }
        // Retrieve our own row's commitment, and store the full commitment.
        let opt_idx_commit_row = self.our_idx.map(|idx| (idx, commit.row(idx + 1)));
        let _ = self.parts.insert(sender_idx, ProposalState::new(commit));
        let (our_idx, commit_row) = match opt_idx_commit_row {
            Some((idx, row)) => (idx, row),
            None => return Ok(None), // We are only an observer. Nothing to send or decrypt.
        };
        // We are a validator: Decrypt and deserialize our row and compare it to the commitment.
        let ser_row = sec_key
            .decrypt(sender_id, &rows[our_idx as usize])
            .ok_or(PartFault::DecryptRow)?;
        let row: Poly = bincode::deserialize(&ser_row).map_err(|_| PartFault::DeserializeRow)?;
        if row.commitment() != commit_row {
            return Err(PartFault::RowCommitment);
        }
        Ok(Some(row))
    }

    /// Handles an `Ack` message, or returns an `AckFault` if it is invalid.
    fn handle_ack_or_fault(
        &mut self,
        sec_key: &S,
        sender_id: &S::PublicId,
        sender_idx: u64,
        Ack(proposer_idx, values): Ack,
    ) -> Result<(), AckFault> {
        if values.len() != self.pub_keys.len() {
            return Err(AckFault::ValueCount);
        }
        let part = self
            .parts
            .get_mut(&proposer_idx)
            .ok_or(AckFault::MissingPart)?;
        if !part.acks.insert(sender_idx) {
            return Ok(()); // We already handled this `Ack` before.
        }
        let our_idx = match self.our_idx {
            Some(our_idx) => our_idx,
            None => return Ok(()), // We are only an observer. Nothing to decrypt for us.
        };
        // We are a validator: Decrypt and deserialize our value and compare it to the commitment.
        let ser_val = sec_key
            .decrypt(sender_id, &values[our_idx as usize])
            .ok_or(AckFault::DecryptValue)?;
        let val = bincode::deserialize::<FieldWrap<Fr>>(&ser_val)
            .map_err(|_| AckFault::DeserializeValue)?
            .into_inner();
        if part.commit.evaluate(our_idx + 1, sender_idx + 1) != G1Affine::one().mul(val) {
            return Err(AckFault::ValueCommitment);
        }
        let _ = part.values.insert(sender_idx + 1, val);
        Ok(())
    }
}

// https://github.com/rust-lang/rust/issues/52560
// Cannot derive Debug without changing the type parameter
impl<S: SecretId> Debug for KeyGen<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "KeyGen{{our_id:{:?}, our_idx:{:?}, pub_keys :{:?}, parts:{:?}, threshold:{:?}}}",
            self.our_id, self.our_idx, self.pub_keys, self.parts, self.threshold
        )
    }
}

/// An error in an `Ack` message sent by a faulty node.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Fail, Serialize, Deserialize, PartialOrd, Ord)]
pub enum AckFault {
    /// The number of values differs from the number of nodes.
    #[fail(display = "The number of values differs from the number of nodes")]
    ValueCount,
    /// No corresponding Part received.
    #[fail(display = "No corresponding Part received")]
    MissingPart,
    /// Value decryption failed.
    #[fail(display = "Value decryption failed")]
    DecryptValue,
    /// Value deserialization failed.
    #[fail(display = "Value deserialization failed")]
    DeserializeValue,
    /// Value doesn't match the commitment.
    #[fail(display = "Value doesn't match the commitment")]
    ValueCommitment,
}

/// An error in a `Part` message sent by a faulty node.
#[derive(Clone, Copy, Eq, PartialEq, Debug, Fail, Serialize, Deserialize, PartialOrd, Ord)]
pub enum PartFault {
    /// The number of rows differs from the number of nodes.
    #[fail(display = "The number of rows differs from the number of nodes")]
    RowCount,
    /// Received multiple different Part messages from the same sender.
    #[fail(display = "Received multiple different Part messages from the same sender")]
    MultipleParts,
    /// Could not decrypt our row in the Part message.
    #[fail(display = "Could not decrypt our row in the Part message")]
    DecryptRow,
    /// Could not deserialize our row in the Part message.
    #[fail(display = "Could not deserialize our row in the Part message")]
    DeserializeRow,
    /// Row does not match the commitment.
    #[fail(display = "Row does not match the commitment")]
    RowCommitment,
}

/// Threshold to use for running DKG
pub fn dkg_threshold(participants_count: usize) -> usize {
    participants_count.saturating_sub(1) / 3
}
