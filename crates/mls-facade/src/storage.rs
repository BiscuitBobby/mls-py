//! Group-state and key-package storage: process-local memory (default) or a
//! durable SQLite file (upstream `mls-rs-provider-sqlite`, bundled SQLite).
//!
//! The SQLite backend hardens upstream's connections:
//! - `foreign_keys=ON`: upstream's schema relies on `ON DELETE CASCADE` to
//!   remove a group's prior-epoch rows when the group is deleted, but never
//!   enables foreign keys. The bundled SQLite happens to default them on
//!   (libsqlite3-sys sets `SQLITE_DEFAULT_FOREIGN_KEYS=1`); SQLite's own
//!   default is off, and then the epoch secrets stay in the file (pinned in
//!   tests/storage.rs). Set explicitly and checked, so cleanup never
//!   depends on build flags.
//! - `secure_delete=ON`: deleted rows are overwritten in the database file.
//! - `synchronous=FULL` with the default rollback journal: a successful
//!   operation is on disk before its output is returned, so a crash cannot
//!   roll state back to before a message was sent (sender-generation reuse).
//! - an exclusive lock file, so two clients (in this or another process)
//!   never use one database at the same time.

use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use mls_rs::{
    error::{AnyError, IntoAnyError},
    storage_provider::in_memory::{InMemoryGroupStateStorage, InMemoryKeyPackageStorage},
    GroupStateStorage, KeyPackageStorage,
};
use mls_rs_core::{
    group::{EpochRecord, GroupState},
    key_package::KeyPackageData,
};
use mls_rs_provider_sqlite::{
    connection_strategy::ConnectionStrategy,
    storage::{SqLiteApplicationStorage, SqLiteGroupStateStorage, SqLiteKeyPackageStorage},
    SqLiteDataStorageEngine, SqLiteDataStorageError,
};
use rusqlite::{Connection, OpenFlags};
use zeroize::Zeroizing;

use crate::error::{Error, ErrorCode, Result};

/// Prior epochs kept for late messages (same as the in-memory default).
const EPOCH_RETENTION: u64 = 3;

fn storage_err(message: &'static str) -> Error {
    Error::new(ErrorCode::Storage, message)
}

#[derive(Debug)]
pub(crate) struct StoreError(AnyError);

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("storage backend error")
    }
}

impl std::error::Error for StoreError {}

impl IntoAnyError for StoreError {
    fn into_dyn_error(
        self,
    ) -> core::result::Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self.0))
    }
}

fn wrap<E: IntoAnyError>(e: E) -> StoreError {
    StoreError(e.into_any_error())
}

fn never(e: Infallible) -> StoreError {
    match e {}
}

#[derive(Clone)]
pub(crate) enum GroupStore {
    Memory(InMemoryGroupStateStorage),
    Sqlite(SqLiteGroupStateStorage),
}

#[derive(Clone)]
pub(crate) enum KeyStore {
    Memory(InMemoryKeyPackageStorage),
    Sqlite(SqLiteKeyPackageStorage),
}

impl GroupStateStorage for GroupStore {
    type Error = StoreError;

    fn state(
        &self,
        group_id: &[u8],
    ) -> core::result::Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        match self {
            Self::Memory(s) => GroupStateStorage::state(s, group_id).map_err(never),
            Self::Sqlite(s) => GroupStateStorage::state(s, group_id).map_err(wrap),
        }
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> core::result::Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        match self {
            Self::Memory(s) => GroupStateStorage::epoch(s, group_id, epoch_id).map_err(never),
            Self::Sqlite(s) => GroupStateStorage::epoch(s, group_id, epoch_id).map_err(wrap),
        }
    }

    fn write(
        &mut self,
        state: GroupState,
        inserts: Vec<EpochRecord>,
        updates: Vec<EpochRecord>,
    ) -> core::result::Result<(), Self::Error> {
        match self {
            Self::Memory(s) => GroupStateStorage::write(s, state, inserts, updates).map_err(never),
            Self::Sqlite(s) => GroupStateStorage::write(s, state, inserts, updates).map_err(wrap),
        }
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> core::result::Result<Option<u64>, Self::Error> {
        match self {
            Self::Memory(s) => GroupStateStorage::max_epoch_id(s, group_id).map_err(never),
            Self::Sqlite(s) => GroupStateStorage::max_epoch_id(s, group_id).map_err(wrap),
        }
    }
}

impl KeyPackageStorage for KeyStore {
    type Error = StoreError;

    fn delete(&mut self, id: &[u8]) -> core::result::Result<(), Self::Error> {
        match self {
            Self::Memory(s) => KeyPackageStorage::delete(s, id).map_err(never),
            Self::Sqlite(s) => KeyPackageStorage::delete(s, id).map_err(wrap),
        }
    }

    fn insert(
        &mut self,
        id: Vec<u8>,
        pkg: KeyPackageData,
    ) -> core::result::Result<(), Self::Error> {
        match self {
            Self::Memory(s) => KeyPackageStorage::insert(s, id, pkg).map_err(never),
            Self::Sqlite(s) => KeyPackageStorage::insert(s, id, pkg).map_err(wrap),
        }
    }

    fn get(&self, id: &[u8]) -> core::result::Result<Option<KeyPackageData>, Self::Error> {
        match self {
            Self::Memory(s) => KeyPackageStorage::get(s, id).map_err(never),
            Self::Sqlite(s) => KeyPackageStorage::get(s, id).map_err(wrap),
        }
    }
}

impl GroupStore {
    /// Delete a group and (for SQLite, through the cascade) its epochs.
    pub(crate) fn delete_group(&self, group_id: &[u8]) -> Result<()> {
        match self {
            Self::Memory(s) => {
                s.delete_group(group_id);
                Ok(())
            }
            Self::Sqlite(s) => s
                .delete_group(group_id)
                .map_err(|_| storage_err("deleting stored group state failed")),
        }
    }

    pub(crate) fn group_ids(&self) -> Result<Vec<Vec<u8>>> {
        let mut ids = match self {
            Self::Memory(s) => s.stored_groups(),
            Self::Sqlite(s) => s
                .group_ids()
                .map_err(|_| storage_err("listing stored groups failed"))?,
        };
        ids.sort();
        Ok(ids)
    }
}

/// The signing identity this storage belongs to.
pub(crate) struct StoredIdentity {
    pub(crate) identity: Vec<u8>,
    pub(crate) cipher_suite: u16,
    pub(crate) public_key: Vec<u8>,
    pub(crate) secret_key: Zeroizing<Vec<u8>>,
}

const KEY_PREFIX: &str = "mls_py.v1.";
const K_IDENTITY: &str = "mls_py.v1.identity";
const K_SUITE: &str = "mls_py.v1.cipher_suite";
const K_PUBLIC: &str = "mls_py.v1.signature_public_key";
const K_SECRET: &str = "mls_py.v1.signature_secret_key";

pub(crate) struct Backend {
    pub(crate) groups: GroupStore,
    pub(crate) keys: KeyStore,
    app: Option<SqLiteApplicationStorage>,
    /// Held for the lifetime of the client (and its groups).
    _lock: Option<File>,
}

impl Backend {
    pub(crate) fn memory() -> Result<Self> {
        Ok(Self {
            groups: GroupStore::Memory(
                InMemoryGroupStateStorage::new()
                    .with_max_epoch_retention(EPOCH_RETENTION as usize)
                    .map_err(|_| Error::new(ErrorCode::Other, "storage setup failed"))?,
            ),
            keys: KeyStore::Memory(InMemoryKeyPackageStorage::new()),
            app: None,
            _lock: None,
        })
    }

    pub(crate) fn sqlite(path: &Path) -> Result<Self> {
        let lock = acquire_lock(path)?;
        create_private_file(path)?;
        let engine = SqLiteDataStorageEngine::new(Hardened(path.to_path_buf()))
            .map_err(|_| storage_err("opening storage failed"))?;
        let groups = engine
            .group_state_storage()
            .map_err(|_| storage_err("opening storage failed"))?
            .with_max_epoch_retention(EPOCH_RETENTION);
        let keys = engine
            .key_package_storage()
            .map_err(|_| storage_err("opening storage failed"))?;
        // Expired key packages can never be used to join; drop their keys.
        keys.delete_expired()
            .map_err(|_| storage_err("cleaning up expired key packages failed"))?;
        let app = engine
            .application_data_storage()
            .map_err(|_| storage_err("opening storage failed"))?;
        Ok(Self {
            groups: GroupStore::Sqlite(groups),
            keys: KeyStore::Sqlite(keys),
            app: Some(app),
            _lock: Some(lock),
        })
    }

    pub(crate) fn is_durable(&self) -> bool {
        self.app.is_some()
    }

    /// The stored signing identity, if this is an existing durable store.
    pub(crate) fn load_identity(&self) -> Result<Option<StoredIdentity>> {
        let Some(app) = &self.app else {
            return Ok(None);
        };
        let get = |k| {
            app.get(k)
                .map(|v| v.map(Zeroizing::new))
                .map_err(|_| storage_err("reading the client record failed"))
        };
        match (
            get(K_IDENTITY)?,
            get(K_SUITE)?,
            get(K_PUBLIC)?,
            get(K_SECRET)?,
        ) {
            (None, None, None, None) => Ok(None),
            (Some(identity), Some(suite), Some(public), Some(secret)) => {
                let suite: [u8; 2] = suite
                    .as_slice()
                    .try_into()
                    .map_err(|_| storage_err("stored client record is corrupt"))?;
                Ok(Some(StoredIdentity {
                    identity: identity.to_vec(),
                    cipher_suite: u16::from_be_bytes(suite),
                    public_key: public.to_vec(),
                    secret_key: secret,
                }))
            }
            _ => Err(storage_err("stored client record is incomplete")),
        }
    }

    /// Record the signing identity of a new durable store (one transaction).
    pub(crate) fn save_identity(&self, id: &StoredIdentity) -> Result<()> {
        let Some(app) = &self.app else {
            return Ok(());
        };
        use mls_rs_provider_sqlite::storage::Item;
        let items = [
            Item::new(K_IDENTITY.into(), id.identity.clone()),
            Item::new(K_SUITE.into(), id.cipher_suite.to_be_bytes().to_vec()),
            Item::new(K_PUBLIC.into(), id.public_key.clone()),
            Item::new(K_SECRET.into(), id.secret_key.to_vec()),
        ];
        debug_assert!(items.iter().all(|i| i.key().starts_with(KEY_PREFIX)));
        app.transact_insert(&items)
            .map(|_| ())
            .map_err(|_| storage_err("writing the client record failed"))
    }
}

/// Upstream's file strategy plus the pragmas described in the module docs.
struct Hardened(PathBuf);

impl ConnectionStrategy for Hardened {
    fn make_connection(&self) -> core::result::Result<Connection, SqLiteDataStorageError> {
        let engine = |e: rusqlite::Error| SqLiteDataStorageError::SqlEngineError(e.into());
        let c = Connection::open_with_flags(
            &self.0,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(engine)?;
        c.pragma_update(None, "foreign_keys", "ON")
            .map_err(engine)?;
        c.pragma_update(None, "secure_delete", "ON")
            .map_err(engine)?;
        c.pragma_update(None, "synchronous", "FULL")
            .map_err(engine)?;
        c.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(engine)?;
        let fk: i64 = c
            .pragma_query_value(None, "foreign_keys", |r| r.get(0))
            .map_err(engine)?;
        if fk != 1 {
            return Err(SqLiteDataStorageError::SqlEngineError(
                "SQLite build without foreign key support".into(),
            ));
        }
        Ok(c)
    }
}

fn private_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o
}

/// Create the database file owner-only before SQLite opens it (SQLite gives
/// its journal files the database file's permissions). An existing file is
/// left as it is.
fn create_private_file(path: &Path) -> Result<()> {
    private_options()
        .open(path)
        .map(drop)
        .map_err(|_| storage_err("cannot create or open the storage file"))
}

fn acquire_lock(path: &Path) -> Result<File> {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    let f = private_options()
        .open(PathBuf::from(name))
        .map_err(|_| storage_err("cannot create the storage lock file"))?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(storage_err(
            "storage is in use by another client (in this or another process)",
        )),
        Err(std::fs::TryLockError::Error(_)) => Err(storage_err("cannot lock the storage file")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With the hardened connections, a deleted group leaves neither rows
    /// nor its bytes in the database file.
    #[test]
    fn deleted_group_is_gone_from_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        let marker = b"MARKER-0123456789-SECRET".to_vec();
        {
            let b = Backend::sqlite(&path).unwrap();
            let mut gs = b.groups.clone();
            let state = GroupState {
                id: b"g".to_vec(),
                data: marker.clone().into(),
            };
            gs.write(
                state,
                vec![EpochRecord::new(1, marker.clone().into())],
                vec![],
            )
            .unwrap();
            let raw = std::fs::read(&path).unwrap();
            assert!(raw.windows(marker.len()).any(|w| w == marker.as_slice()));
            b.groups.delete_group(b"g").unwrap();
        }
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(marker.len()).any(|w| w == marker.as_slice()),
            "deleted secrets must be overwritten (secure_delete)"
        );
        let c = Connection::open(&path).unwrap();
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM epoch", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "epochs cascade with the group (foreign_keys)");
    }
}
