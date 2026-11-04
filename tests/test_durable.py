import os
import sys

import pytest

import mls_py
from conftest import code_of


def test_restart_restores_groups(make_client, tmp_path):
    db = tmp_path / "alice.db"
    bob = make_client(b"bob")
    alice = make_client(b"alice", storage=db)
    ag = alice.create_group()
    _c, w = ag.add(bob.key_package())
    ag.apply_pending()
    bg = bob.join(w)
    gid = ag.group_id
    del ag, alice  # releases the lock

    alice = make_client(b"alice", storage=str(db))
    assert alice.group_ids() == [gid]
    ag = alice.load_group(gid)
    assert bg.process(ag.encrypt(b"after restart")).data == b"after restart"
    assert ag.process(bg.encrypt(b"reply")).data == b"reply"


def test_key_package_survives_restart(make_client, tmp_path):
    db = tmp_path / "bob.db"
    kp = make_client(b"bob", storage=db).key_package()
    alice = make_client(b"alice")
    ag = alice.create_group()
    _c, w = ag.add(kp)
    ag.apply_pending()
    bob = make_client(b"bob", storage=db)
    assert len(bob.join(w).members) == 2


def test_storage_is_exclusive_and_bound(make_client, tmp_path):
    db = tmp_path / "c.db"
    c = make_client(b"carol", storage=db)
    assert code_of(make_client, b"carol", storage=db) == "storage"
    g = c.create_group()
    del c
    assert code_of(make_client, b"carol", storage=db) == "storage"  # group holds it
    del g
    assert code_of(make_client, b"dave", storage=db) == "invalid_argument"
    make_client(b"carol", storage=db)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_files_are_owner_only(make_client, tmp_path):
    db = tmp_path / "p.db"
    _c = make_client(b"p", storage=db)
    for p in (db, tmp_path / "p.db.lock"):
        assert os.stat(p).st_mode & 0o777 == 0o600


def test_bad_storage_argument(make_client, tmp_path):
    with pytest.raises(TypeError):
        make_client(b"x", storage=123)
    assert code_of(make_client, b"x", storage=tmp_path / "missing" / "x.db") == "storage"
