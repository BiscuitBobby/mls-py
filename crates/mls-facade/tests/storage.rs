//! Durable SQLite storage (`ClientOptions::storage`). Every scenario runs
//! once per allowlisted suite.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use mls_facade::{
    Client, ClientOptions, ErrorCode, MemberVerifier, DEFAULT_MAX_MESSAGE_SIZE,
    SUPPORTED_CIPHER_SUITES,
};

fn durable(name: &str, cs: u16, path: &Path) -> mls_facade::Result<Client> {
    Client::with_options(
        name.as_bytes(),
        ClientOptions {
            cipher_suite: cs,
            storage: Some(path.to_path_buf()),
            ..Default::default()
        },
    )
}

fn memory(name: &str, cs: u16) -> Client {
    Client::new(name.as_bytes(), cs, DEFAULT_MAX_MESSAGE_SIZE).unwrap()
}

fn code<T: std::fmt::Debug>(r: mls_facade::Result<T>) -> ErrorCode {
    r.unwrap_err().code
}

fn for_each_suite(f: impl Fn(u16, PathBuf)) {
    for &cs in SUPPORTED_CIPHER_SUITES {
        let dir = tempfile::tempdir().unwrap();
        f(cs, dir.path().join("client.db"));
    }
}

fn count(path: &Path, table: &str) -> i64 {
    let c = rusqlite::Connection::open(path).unwrap();
    c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn group_survives_restart() {
    for_each_suite(|cs, path| {
        let bob = memory("bob", cs);
        let (gid, bg) = {
            let alice = durable("alice", cs, &path).unwrap();
            let ag = alice.create_group().unwrap();
            let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
            ag.apply_pending().unwrap();
            let bg = bob.join(&w).unwrap();
            let ct = ag.encrypt(b"before", b"").unwrap();
            bg.process(&ct).unwrap();
            (ag.group_id().to_vec(), bg)
        }; // alice's client and group dropped: lock released

        let alice = durable("alice", cs, &path).unwrap();
        assert_eq!(alice.group_ids().unwrap(), vec![gid.clone()]);
        let ag = alice.load_group(&gid).unwrap();
        assert_eq!(ag.epoch().unwrap(), bg.epoch().unwrap());
        let ct = ag.encrypt(b"after restart", b"").unwrap();
        assert_eq!(
            bg.process(&ct).unwrap().data.as_deref(),
            Some(&b"after restart"[..])
        );
        let ct = bg.encrypt(b"reply", b"").unwrap();
        assert_eq!(
            ag.process(&ct).unwrap().data.as_deref(),
            Some(&b"reply"[..])
        );
        assert_eq!(
            ag.export_secret(b"x", b"", 32).unwrap(),
            bg.export_secret(b"x", b"", 32).unwrap()
        );
    });
}

#[test]
fn key_package_survives_restart() {
    for_each_suite(|cs, path| {
        let kp = durable("bob", cs, &path).unwrap().key_package().unwrap();
        let alice = memory("alice", cs);
        let ag = alice.create_group().unwrap();
        let (_c, w) = ag.add(&kp).unwrap();
        ag.apply_pending().unwrap();
        let bob = durable("bob", cs, &path).unwrap();
        let bg = bob.join(&w).unwrap();
        assert_eq!(bg.members().unwrap().len(), 2);
        // The consumed key package is gone: the same Welcome cannot be used again.
        drop(bg);
        bob.delete_group(ag.group_id()).unwrap();
        assert_eq!(code(bob.join(&w)), ErrorCode::InvalidWelcome);
    });
}

#[derive(Default)]
struct KeysOf(Mutex<Vec<(Vec<u8>, Vec<u8>)>>);
impl MemberVerifier for KeysOf {
    fn verify(&self, identity: &[u8], key: &[u8]) -> bool {
        self.0
            .lock()
            .unwrap()
            .push((identity.to_vec(), key.to_vec()));
        true
    }
}

#[test]
fn signing_key_is_stable_across_restarts() {
    for_each_suite(|cs, path| {
        let seen = Arc::new(KeysOf::default());
        let bob = Client::with_options(
            b"bob",
            ClientOptions {
                cipher_suite: cs,
                verifier: Some(seen.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        let kp1 = durable("alice", cs, &path).unwrap().key_package().unwrap();
        let kp2 = durable("alice", cs, &path).unwrap().key_package().unwrap();
        // Bob sees both key packages carry the same signature key.
        for kp in [kp1, kp2] {
            bob.create_group().unwrap().add(&kp).unwrap();
        }
        let keys: std::collections::HashSet<_> = seen
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(i, _)| i == b"alice")
            .map(|(_, k)| k.clone())
            .collect();
        assert_eq!(keys.len(), 1);
    });
}

#[test]
fn one_client_per_storage() {
    for_each_suite(|cs, path| {
        let a = durable("alice", cs, &path).unwrap();
        assert_eq!(code(durable("alice", cs, &path)), ErrorCode::Storage);
        let g = a.create_group().unwrap();
        drop(a);
        // A live group keeps the client's storage (and its lock).
        assert_eq!(code(durable("alice", cs, &path)), ErrorCode::Storage);
        drop(g);
        durable("alice", cs, &path).unwrap();
    });
}

#[test]
fn storage_is_bound_to_identity_and_suite() {
    for_each_suite(|cs, path| {
        drop(durable("alice", cs, &path).unwrap());
        assert_eq!(code(durable("bob", cs, &path)), ErrorCode::InvalidArgument);
        let other = *SUPPORTED_CIPHER_SUITES.iter().find(|&&s| s != cs).unwrap();
        assert_eq!(
            code(durable("alice", other, &path)),
            ErrorCode::InvalidArgument
        );
        durable("alice", cs, &path).unwrap();
    });
}

#[test]
fn removal_deletes_group_and_epochs_from_disk() {
    for_each_suite(|cs, path| {
        let alice = memory("alice", cs);
        let ag = alice.create_group().unwrap();
        let bob = durable("bob", cs, &path).unwrap();
        let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        let bg = bob.join(&w).unwrap();
        for _ in 0..3 {
            let c = ag.commit().unwrap();
            ag.apply_pending().unwrap();
            bg.process(&c).unwrap();
        }
        assert!(count(&path, "epoch") > 0, "prior epochs are stored");
        let rm = ag.remove(1).unwrap();
        ag.apply_pending().unwrap();
        assert!(bg.process(&rm).unwrap().removed);
        assert_eq!(count(&path, "mls_group"), 0);
        assert_eq!(
            count(&path, "epoch"),
            0,
            "epoch secrets must not outlive the group"
        );
        assert!(bob.group_ids().unwrap().is_empty());
    });
}

#[test]
fn prior_epoch_retention_matches_memory() {
    for_each_suite(|cs, path| {
        let alice = memory("alice", cs);
        let ag = alice.create_group().unwrap();
        let bob = durable("bob", cs, &path).unwrap();
        let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        let bg = bob.join(&w).unwrap();
        let mut olds = Vec::new();
        for _ in 0..5 {
            olds.push(ag.encrypt(b"old", b"").unwrap());
            let c = ag.commit().unwrap();
            ag.apply_pending().unwrap();
            bg.process(&c).unwrap();
        }
        let res: Vec<_> = olds
            .iter()
            .map(|m| bg.process(m).map(|_| ()).map_err(|e| e.code))
            .collect();
        use ErrorCode::InvalidEpoch as E;
        assert_eq!(res, vec![Err(E), Err(E), Ok(()), Ok(()), Ok(())]);
    });
}

#[test]
fn failed_message_restores_from_disk() {
    for_each_suite(|cs, path| {
        let alice = memory("alice", cs);
        let ag = alice.create_group().unwrap();
        let bob = durable("bob", cs, &path).unwrap();
        let (_c, w) = ag.add(&bob.key_package().unwrap()).unwrap();
        ag.apply_pending().unwrap();
        let bg = bob.join(&w).unwrap();
        let ct = ag.encrypt(b"genuine", b"").unwrap();
        let mut bad = ct.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(bg.process(&bad).is_err());
        assert_eq!(
            bg.process(&ct).unwrap().data.as_deref(),
            Some(&b"genuine"[..])
        );
    });
}

#[test]
fn pending_commit_survives_restart() {
    for_each_suite(|cs, path| {
        let gid = {
            let alice = durable("alice", cs, &path).unwrap();
            let ag = alice.create_group().unwrap();
            ag.commit().unwrap(); // bytes "lost" in the crash
            ag.group_id().to_vec()
        };
        let alice = durable("alice", cs, &path).unwrap();
        let ag = alice.load_group(&gid).unwrap();
        assert!(ag.has_pending_commit().unwrap());
        ag.discard_pending().unwrap();
        assert_eq!(ag.epoch().unwrap(), 0);
    });
}

#[cfg(unix)]
#[test]
fn files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    for_each_suite(|cs, path| {
        let _c = durable("alice", cs, &path).unwrap();
        for p in [
            path.clone(),
            PathBuf::from(format!("{}.lock", path.display())),
        ] {
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{}", p.display());
        }
    });
}

#[test]
fn unusable_path_is_a_storage_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-dir").join("client.db");
    assert_eq!(code(durable("alice", 1, &path)), ErrorCode::Storage);
}

/// Pins the upstream behaviour behind the facade's explicit
/// `foreign_keys=ON`: upstream relies on `ON DELETE CASCADE` to remove a
/// group's epoch rows (prior-epoch secrets) but never enables foreign keys.
/// It works with the bundled SQLite only because libsqlite3-sys compiles it
/// with `SQLITE_DEFAULT_FOREIGN_KEYS=1`; with SQLite's own default (off, as
/// in system libraries used by the provider's non-bundled features) the
/// epoch rows survive `delete_group`.
#[test]
fn upstream_epoch_cleanup_depends_on_build_default() {
    use mls_rs::GroupStateStorage;
    use mls_rs_core::group::{EpochRecord, GroupState};
    use mls_rs_provider_sqlite::{
        connection_strategy::{ConnectionStrategy, FileConnectionStrategy},
        SqLiteDataStorageEngine, SqLiteDataStorageError,
    };

    /// Upstream's file strategy with SQLite's documented default.
    struct SystemDefault(PathBuf);
    impl ConnectionStrategy for SystemDefault {
        fn make_connection(&self) -> Result<rusqlite::Connection, SqLiteDataStorageError> {
            let c = FileConnectionStrategy::new(&self.0).make_connection()?;
            c.pragma_update(None, "foreign_keys", "OFF").unwrap();
            Ok(c)
        }
    }

    fn epochs_left_after_delete<CS: ConnectionStrategy>(cs: CS, path: &Path) -> i64 {
        let engine = SqLiteDataStorageEngine::new(cs).unwrap();
        let mut gs = engine.group_state_storage().unwrap();
        let state = GroupState {
            id: b"group".to_vec(),
            data: b"snapshot".to_vec().into(),
        };
        gs.write(
            state,
            vec![EpochRecord::new(1, b"epoch-secret".to_vec().into())],
            vec![],
        )
        .unwrap();
        gs.delete_group(b"group").unwrap();
        assert_eq!(count(path, "mls_group"), 0);
        count(path, "epoch")
    }

    let dir = tempfile::tempdir().unwrap();
    let bundled = dir.path().join("bundled.db");
    let system = dir.path().join("system.db");
    assert_eq!(
        epochs_left_after_delete(FileConnectionStrategy::new(&bundled), &bundled),
        0
    );
    assert_eq!(
        epochs_left_after_delete(SystemDefault(system.clone()), &system),
        1,
        "upstream now deletes epochs explicitly; the facade's pragma is defence in depth only"
    );
}
