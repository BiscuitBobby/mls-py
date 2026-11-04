use std::sync::{Arc, Mutex, MutexGuard};

use mls_rs::{
    group::{CommitEffect, ProposalSender, ReceivedMessage},
    MlsMessage, WireFormat,
};

use crate::client::{ClientInner, Config};
use crate::error::{map_upstream, Ctx, Error, ErrorCode, Result};
use crate::limits;

pub(crate) type MlsGroup = mls_rs::Group<Config>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lifecycle {
    Active,
    /// Terminal: a commit removed us. Stored state is deleted.
    Removed,
    /// Terminal: unrecoverable state error (e.g. persisting failed) or the
    /// group was re-initialized. Stored state is deleted.
    Invalid,
}

pub(crate) struct GroupState {
    lifecycle: Lifecycle,
    /// `None` once terminal; dropping the upstream group drops its secrets.
    group: Option<MlsGroup>,
}

pub(crate) struct GroupShared {
    client: Arc<ClientInner>,
    group_id: Vec<u8>,
    state: Mutex<GroupState>,
}

impl GroupShared {
    pub(crate) fn new(client: Arc<ClientInner>, group: MlsGroup) -> Arc<Self> {
        Arc::new(Self {
            client,
            group_id: group.group_id().to_vec(),
            state: Mutex::new(GroupState {
                lifecycle: Lifecycle::Active,
                group: Some(group),
            }),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, GroupState>> {
        self.state.lock().map_err(|_| {
            Error::new(
                ErrorCode::InvalidGroupState,
                "group state lock poisoned by an earlier panic",
            )
        })
    }

    pub(crate) fn lifecycle(&self) -> Result<Lifecycle> {
        Ok(self.lock()?.lifecycle)
    }

    /// Move to a terminal state: drop the upstream group and delete the
    /// stored state so the group cannot be revived through `load_group`.
    fn terminate(&self, st: &mut GroupState, lifecycle: Lifecycle) {
        st.group = None;
        st.lifecycle = lifecycle;
        self.client.storage.delete_group(&self.group_id);
    }

    /// Persist after every successful state change. This bounds prior-epoch
    /// retention, deletes consumed key material, and guarantees `load_group`
    /// never returns a stale snapshot (which could re-use sender ratchet
    /// generations).
    fn persist(&self, st: &mut GroupState) -> Result<()> {
        let failed = match st.group.as_mut() {
            Some(g) => g.write_to_storage().is_err(),
            None => false,
        };
        if failed {
            self.terminate(st, Lifecycle::Invalid);
            return Err(Error::new(
                ErrorCode::Storage,
                "persisting group state failed; group is now invalid",
            ));
        }
        Ok(())
    }

    /// Undo whatever a failed upstream call changed in memory by reloading
    /// the stored state. Invariant: whenever the lock is released, storage
    /// holds exactly the in-memory state (persist on success, restore on
    /// failure), so this restores the pre-call state.
    fn restore(&self, st: &mut GroupState) {
        match self.client.mls.load_group(&self.group_id) {
            Ok(g) => st.group = Some(g),
            Err(_) => self.terminate(st, Lifecycle::Invalid),
        }
    }

    /// Run a state-changing operation on an active group with the
    /// persist-on-success / restore-on-failure discipline. The closure may
    /// request a terminal transition instead of persisting.
    fn mutate<T>(
        &self,
        f: impl FnOnce(&mut MlsGroup) -> Result<(T, Option<Lifecycle>)>,
    ) -> Result<T> {
        let mut st = self.lock()?;
        let g = st.active()?;
        match f(g) {
            Ok((value, None)) => {
                self.persist(&mut st)?;
                Ok(value)
            }
            Ok((value, Some(terminal))) => {
                self.terminate(&mut st, terminal);
                Ok(value)
            }
            Err(e) => {
                self.restore(&mut st);
                Err(e)
            }
        }
    }
}

impl GroupState {
    fn active(&mut self) -> Result<&mut MlsGroup> {
        match (self.lifecycle, self.group.as_mut()) {
            (Lifecycle::Active, Some(g)) => Ok(g),
            (Lifecycle::Removed, _) => Err(Error::new(
                ErrorCode::InvalidGroupState,
                "this member was removed from the group",
            )),
            _ => Err(Error::new(
                ErrorCode::InvalidGroupState,
                "group is in an unrecoverable state",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Application,
    Commit,
    Proposal,
    Other,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Application => "application",
            EventKind::Commit => "commit",
            EventKind::Proposal => "proposal",
            EventKind::Other => "other",
        }
    }
}

/// Result of processing one inbound message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub kind: EventKind,
    /// Decrypted application data (`Application` only).
    pub data: Option<Vec<u8>>,
    /// Authenticated (not encrypted) data carried with the message.
    pub aad: Vec<u8>,
    /// Sender's leaf index, `None` for non-member senders.
    pub sender_index: Option<u32>,
    /// Epoch after processing.
    pub epoch: u64,
    /// True if this commit removed us; the group is now terminal.
    pub removed: bool,
}

/// Handle to one MLS group. At most one live handle exists per group id per
/// client; all methods take `&self` and serialize on an internal lock.
pub struct Group {
    shared: Arc<GroupShared>,
}

fn invalid_arg(message: &'static str) -> Error {
    Error::new(ErrorCode::InvalidArgument, message)
}

fn no_pending(g: &MlsGroup) -> Result<()> {
    if g.has_pending_commit() {
        return Err(Error::new(
            ErrorCode::PendingCommit,
            "a commit is pending; apply_pending() or discard_pending() first",
        ));
    }
    Ok(())
}

fn to_bytes(m: &MlsMessage) -> Result<Vec<u8>> {
    m.to_bytes().map_err(|e| map_upstream(Ctx::Local, &e))
}

impl Group {
    pub(crate) fn from_shared(shared: Arc<GroupShared>) -> Self {
        Self { shared }
    }

    fn client(&self) -> &ClientInner {
        &self.shared.client
    }

    pub fn group_id(&self) -> &[u8] {
        &self.shared.group_id
    }

    pub fn is_active(&self) -> Result<bool> {
        Ok(self.shared.lifecycle()? == Lifecycle::Active)
    }

    pub fn epoch(&self) -> Result<u64> {
        let mut st = self.shared.lock()?;
        Ok(st.active()?.current_epoch())
    }

    pub fn leaf_index(&self) -> Result<u32> {
        let mut st = self.shared.lock()?;
        Ok(st.active()?.current_member_index())
    }

    pub fn cipher_suite(&self) -> Result<u16> {
        let mut st = self.shared.lock()?;
        Ok(st.active()?.cipher_suite().into())
    }

    pub fn has_pending_commit(&self) -> Result<bool> {
        let mut st = self.shared.lock()?;
        Ok(st.active()?.has_pending_commit())
    }

    /// `(leaf_index, identity)` for every current member, by leaf index.
    pub fn members(&self) -> Result<Vec<(u32, Vec<u8>)>> {
        let mut st = self.shared.lock()?;
        let g = st.active()?;
        Ok(g.roster()
            .members_iter()
            .map(|m| {
                let id = m
                    .signing_identity
                    .credential
                    .as_basic()
                    .map(|b| b.identifier.clone())
                    .unwrap_or_default();
                (m.index, id)
            })
            .collect())
    }

    /// Commit adding the member owning `key_package`. Returns
    /// `(commit, welcome)`; the commit stays pending until `apply_pending`.
    pub fn add(&self, key_package: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        self.client().check_size(key_package)?;
        let kp =
            MlsMessage::from_bytes(key_package).map_err(|e| map_upstream(Ctx::KeyPackage, &e))?;
        if kp.wire_format() != WireFormat::KeyPackage {
            return Err(Error::new(
                ErrorCode::InvalidKeyPackage,
                "input is not a key package",
            ));
        }
        self.shared.mutate(|g| {
            no_pending(g)?;
            if kp.cipher_suite() != Some(g.cipher_suite()) {
                return Err(Error::new(
                    ErrorCode::UnsupportedCipherSuite,
                    "key package uses a different cipher suite than the group",
                ));
            }
            let out = g
                .commit_builder()
                .add_member(kp)
                .map_err(|e| map_upstream(Ctx::KeyPackage, &e))?
                .build()
                .map_err(|e| map_upstream(Ctx::KeyPackage, &e))?;
            let commit = to_bytes(&out.commit_message)?;
            let welcome = match out.welcome_messages.as_slice() {
                [w] => to_bytes(w)?,
                _ => return Err(Error::new(ErrorCode::Other, "expected exactly one welcome")),
            };
            Ok(((commit, welcome), None))
        })
    }

    /// Commit removing the member at `leaf_index` (pending until applied).
    pub fn remove(&self, leaf_index: u32) -> Result<Vec<u8>> {
        self.shared.mutate(|g| {
            no_pending(g)?;
            if leaf_index == g.current_member_index() {
                return Err(invalid_arg(
                    "a member cannot remove itself with a commit; another member must remove it",
                ));
            }
            if g.member_at_index(leaf_index).is_none() {
                return Err(invalid_arg("no member at that leaf index"));
            }
            let out = g
                .commit_builder()
                .remove_member(leaf_index)
                .map_err(|e| map_upstream(Ctx::Local, &e))?
                .build()
                .map_err(|e| map_upstream(Ctx::Local, &e))?;
            Ok((to_bytes(&out.commit_message)?, None))
        })
    }

    /// Commit with no new proposals: refreshes our own leaf key (post-compromise
    /// security) and includes any proposals received by reference.
    pub fn commit(&self) -> Result<Vec<u8>> {
        self.shared.mutate(|g| {
            no_pending(g)?;
            let out = g
                .commit(Vec::new())
                .map_err(|e| map_upstream(Ctx::Local, &e))?;
            Ok((to_bytes(&out.commit_message)?, None))
        })
    }

    /// Apply exactly the stored pending commit (local transition only).
    pub fn apply_pending(&self) -> Result<()> {
        self.shared.mutate(|g| {
            if !g.has_pending_commit() {
                return Err(Error::new(ErrorCode::NoPendingCommit, "no pending commit"));
            }
            g.apply_pending_commit()
                .map_err(|e| map_upstream(Ctx::Local, &e))?;
            Ok(((), None))
        })
    }

    pub fn discard_pending(&self) -> Result<()> {
        self.shared.mutate(|g| {
            if !g.has_pending_commit() {
                return Err(Error::new(ErrorCode::NoPendingCommit, "no pending commit"));
            }
            g.clear_pending_commit();
            Ok(((), None))
        })
    }

    pub fn encrypt(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if data.len().saturating_add(aad.len()) > self.client().max_message_size {
            return Err(Error::new(
                ErrorCode::InputTooLarge,
                "data and aad exceed max_message_size",
            ));
        }
        self.shared.mutate(|g| {
            no_pending(g)?;
            let msg = g
                .encrypt_application_message(data, aad.to_vec())
                .map_err(|e| map_upstream(Ctx::Local, &e))?;
            Ok((to_bytes(&msg)?, None))
        })
    }

    pub fn export_secret(&self, label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>> {
        if label.len() > limits::MAX_EXPORT_LABEL_LEN {
            return Err(invalid_arg("label must be at most 255 bytes"));
        }
        if context.len() > limits::MAX_EXPORT_CONTEXT_LEN {
            return Err(invalid_arg("context must be at most 65536 bytes"));
        }
        if length == 0 || length > limits::MAX_EXPORT_LEN {
            return Err(invalid_arg("length must be in 1..=1024"));
        }
        let mut st = self.shared.lock()?;
        let g = st.active()?;
        let secret = g
            .export_secret(label, context, length)
            .map_err(|e| map_upstream(Ctx::Local, &e))?;
        Ok(secret.as_bytes().to_vec())
    }

    /// Process one inbound handshake or application message.
    ///
    /// A rejected message leaves the group state exactly as it was (restored
    /// from storage), except `storage` errors, after which the group is
    /// invalid.
    pub fn process(&self, message: &[u8]) -> Result<Event> {
        self.client().check_size(message)?;
        let msg = MlsMessage::from_bytes(message).map_err(|e| map_upstream(Ctx::Message, &e))?;
        match msg.wire_format() {
            WireFormat::PublicMessage | WireFormat::PrivateMessage => {}
            _ => {
                return Err(Error::new(
                    ErrorCode::InvalidMessage,
                    "not a group message (use Client.join for welcomes)",
                ))
            }
        }
        if msg.group_id() != Some(self.shared.group_id.as_slice()) {
            return Err(Error::new(
                ErrorCode::InvalidMessage,
                "message is for a different group",
            ));
        }

        self.shared.mutate(|g| {
            let received = g
                .process_incoming_message(msg)
                .map_err(|e| map_upstream(Ctx::Message, &e))?;
            let epoch = g.current_epoch();
            let mut event = Event {
                kind: EventKind::Other,
                data: None,
                aad: Vec::new(),
                sender_index: None,
                epoch,
                removed: false,
            };
            let mut terminal = None;
            match received {
                ReceivedMessage::ApplicationMessage(d) => {
                    event.kind = EventKind::Application;
                    event.data = Some(d.data().to_vec());
                    event.aad = d.authenticated_data;
                    event.sender_index = Some(d.sender_index);
                }
                ReceivedMessage::Commit(d) => {
                    event.kind = EventKind::Commit;
                    event.sender_index = (!d.is_external).then_some(d.committer);
                    event.aad = d.authenticated_data;
                    match d.effect {
                        CommitEffect::NewEpoch(_) => {}
                        CommitEffect::Removed { new_epoch, .. } => {
                            event.epoch = new_epoch.epoch;
                            event.removed = true;
                            terminal = Some(Lifecycle::Removed);
                        }
                        // Not supported in v0.1: the group cannot be used further.
                        CommitEffect::ReInit(_) => terminal = Some(Lifecycle::Invalid),
                    }
                }
                ReceivedMessage::Proposal(p) => {
                    event.kind = EventKind::Proposal;
                    event.aad = p.authenticated_data;
                    event.sender_index = match p.sender {
                        ProposalSender::Member(i) => Some(i),
                        _ => None,
                    };
                }
                _ => {}
            }
            Ok((event, terminal))
        })
    }
}

/// Never prints secrets or upstream state.
impl core::fmt::Debug for Group {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Group")
            .field("group_id_len", &self.shared.group_id.len())
            .finish_non_exhaustive()
    }
}
