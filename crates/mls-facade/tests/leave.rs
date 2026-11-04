//! `Group::leave`: RFC 9420 self-removal via a by-reference Remove proposal
//! that another member commits. Every scenario runs once per allowlisted suite.

use mls_facade::{
    Client, ErrorCode, EventKind, Group, DEFAULT_MAX_MESSAGE_SIZE, SUPPORTED_CIPHER_SUITES,
};

fn client(name: &str, cs: u16) -> Client {
    Client::new(name.as_bytes(), cs, DEFAULT_MAX_MESSAGE_SIZE).unwrap()
}

fn code<T: std::fmt::Debug>(r: mls_facade::Result<T>) -> ErrorCode {
    r.unwrap_err().code
}

/// Alice, Bob and Carol in one group, all at the same epoch.
fn trio(cs: u16) -> (Vec<Client>, Group, Group, Group) {
    let (alice, bob, carol) = (client("alice", cs), client("bob", cs), client("carol", cs));
    let ag = alice.create_group().unwrap();
    let (_, w) = ag.add(&bob.key_package().unwrap()).unwrap();
    ag.apply_pending().unwrap();
    let bg = bob.join(&w).unwrap();
    let (c, w) = ag.add(&carol.key_package().unwrap()).unwrap();
    ag.apply_pending().unwrap();
    bg.process(&c).unwrap();
    let cg = carol.join(&w).unwrap();
    (vec![alice, bob, carol], ag, bg, cg)
}

fn for_each_suite(f: impl Fn(u16)) {
    for &cs in SUPPORTED_CIPHER_SUITES {
        f(cs);
    }
}

#[test]
fn leave_is_committed_by_another_member() {
    for_each_suite(|cs| {
        let (clients, ag, bg, cg) = trio(cs);
        let proposal = bg.leave().unwrap();
        assert!(bg.leave_pending().unwrap());
        assert_eq!(
            bg.epoch().unwrap(),
            2,
            "a proposal does not change the epoch"
        );

        // While leaving, nothing that would cancel or bypass the leave.
        assert_eq!(code(bg.leave()), ErrorCode::LeavePending);
        assert_eq!(code(bg.commit()), ErrorCode::LeavePending);
        assert_eq!(code(bg.encrypt(b"x", b"")), ErrorCode::LeavePending);
        assert_eq!(code(bg.remove(0)), ErrorCode::LeavePending);
        let kp = client("dave", cs).key_package().unwrap();
        assert_eq!(code(bg.add(&kp)), ErrorCode::LeavePending);
        assert!(bg.leave_pending().unwrap(), "refused calls keep the leave");

        for g in [&ag, &cg] {
            let ev = g.process(&proposal).unwrap();
            assert_eq!(ev.kind, EventKind::Proposal);
            assert_eq!(ev.sender_index, Some(1));
            assert!(!g.leave_pending().unwrap());
            assert_eq!(code(g.encrypt(b"x", b"")), ErrorCode::CommitRequired);
        }

        let commit = cg.commit().unwrap();
        cg.apply_pending().unwrap();
        let ev = ag.process(&commit).unwrap();
        assert!(!ev.removed);
        for g in [&ag, &cg] {
            assert_eq!(
                g.members().unwrap(),
                vec![(0, b"alice".to_vec()), (2, b"carol".to_vec())]
            );
        }

        let ev = bg.process(&commit).unwrap();
        assert!(ev.removed);
        assert!(!bg.is_active().unwrap());
        assert_eq!(code(bg.leave_pending()), ErrorCode::InvalidGroupState);
        let gid = bg.group_id().to_vec();
        drop(bg);
        assert_eq!(code(clients[1].load_group(&gid)), ErrorCode::GroupNotFound);

        // The rest of the group carries on.
        let ct = ag.encrypt(b"after", b"").unwrap();
        assert_eq!(
            cg.process(&ct).unwrap().data.as_deref(),
            Some(&b"after"[..])
        );
    });
}

#[test]
fn leave_is_void_after_a_commit_that_does_not_remove() {
    for_each_suite(|cs| {
        let (_c, ag, bg, cg) = trio(cs);
        let _lost = bg.leave().unwrap(); // never delivered
        let commit = ag.commit().unwrap();
        ag.apply_pending().unwrap();
        cg.process(&commit).unwrap();
        let ev = bg.process(&commit).unwrap();
        assert!(!ev.removed);
        assert!(
            !bg.leave_pending().unwrap(),
            "new epoch clears the proposal"
        );
        // Bob is still a member and can ask again.
        let proposal = bg.leave().unwrap();
        ag.process(&proposal).unwrap();
        let commit = ag.commit().unwrap();
        ag.apply_pending().unwrap();
        assert!(bg.process(&commit).unwrap().removed);
    });
}

#[test]
fn leave_survives_reload() {
    for_each_suite(|cs| {
        let (clients, _ag, bg, _cg) = trio(cs);
        bg.leave().unwrap();
        let gid = bg.group_id().to_vec();
        drop(bg);
        let bg = clients[1].load_group(&gid).unwrap();
        assert!(bg.leave_pending().unwrap());
        assert_eq!(code(bg.commit()), ErrorCode::LeavePending);
    });
}

#[test]
fn leave_preconditions() {
    for_each_suite(|cs| {
        let alone = client("solo", cs).create_group().unwrap();
        assert_eq!(code(alone.leave()), ErrorCode::InvalidGroupState);
        assert!(alone.is_active().unwrap());

        let (_c, ag, _bg, _cg) = trio(cs);
        ag.commit().unwrap();
        assert_eq!(code(ag.leave()), ErrorCode::PendingCommit);
        ag.discard_pending().unwrap();
        ag.leave().unwrap();
    });
}

#[test]
fn own_leave_proposal_echo_is_harmless() {
    for_each_suite(|cs| {
        let (_c, ag, bg, _cg) = trio(cs);
        let proposal = bg.leave().unwrap();
        // A delivery service echoing the proposal back: accepted once,
        // reported as our own proposal, leave still pending.
        let ev = bg.process(&proposal).unwrap();
        assert_eq!((ev.kind, ev.sender_index), (EventKind::Proposal, Some(1)));
        assert!(bg.leave_pending().unwrap());
        ag.process(&proposal).unwrap();
        let commit = ag.commit().unwrap();
        ag.apply_pending().unwrap();
        assert!(bg.process(&commit).unwrap().removed);
    });
}
