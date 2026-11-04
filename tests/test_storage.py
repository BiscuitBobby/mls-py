import gc

from conftest import code_of


def _pair(make_client):
    # Built locally (not via the fixture) so `del` really drops the handle.
    alice, bob = make_client(b"alice"), make_client(b"bob")
    ag = alice.create_group()
    _c, w = ag.add(bob.key_package())
    ag.apply_pending()
    return alice, ag, bob, bob.join(w)


def test_load_group_after_release(make_client):
    alice, ag, _b, bg = _pair(make_client)
    gid = ag.group_id
    assert code_of(alice.load_group, gid) == "group_already_loaded"
    bg.process(ag.encrypt(b"before"))
    del ag
    gc.collect()
    ag = alice.load_group(gid)
    assert ag.epoch == 1
    # Latest state, so no sender-ratchet reuse after reload.
    assert bg.process(ag.encrypt(b"after")).data == b"after"


def test_pending_commit_survives_reload(make_client):
    alice, ag, _b, bg = _pair(make_client)
    gid = ag.group_id
    c = ag.commit()
    del ag
    gc.collect()
    ag = alice.load_group(gid)
    assert ag.has_pending_commit
    ag.apply_pending()
    bg.process(c)
    assert ag.export_secret(b"", b"", 8) == bg.export_secret(b"", b"", 8)


def test_key_package_single_use(make_client):
    alice, bob = make_client(b"alice"), make_client(b"bob")
    kp = bob.key_package()
    g1, g2 = alice.create_group(), alice.create_group()
    _c1, w1 = g1.add(kp)
    _c2, w2 = g2.add(kp)
    bob.join(w1)
    assert code_of(bob.join, w2) == "invalid_welcome"
    assert code_of(bob.join, w1) == "invalid_welcome"


def test_group_outlives_client_and_multiple_groups(pair):
    alice, ag, bob, bg = pair
    ag2 = alice.create_group()
    _c, w = ag2.add(bob.key_package())
    ag2.apply_pending()
    bg2 = bob.join(w)
    del alice, bob
    gc.collect()
    assert bg.process(ag.encrypt(b"g1")).data == b"g1"
    assert bg2.process(ag2.encrypt(b"g2")).data == b"g2"
    assert code_of(bg.process, ag2.encrypt(b"x")) == "invalid_message"


def test_many_key_packages(make_client):
    c = make_client(b"c")
    kps = {c.key_package() for _ in range(50)}
    assert len(kps) == 50
