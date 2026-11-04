from conftest import code_of


def test_pending_commit_lifecycle(pair, make_client):
    _a, ag, _b, bg = pair
    carol = make_client(b"carol")
    assert code_of(ag.apply_pending) == "no_pending_commit"
    assert code_of(ag.discard_pending) == "no_pending_commit"

    ag.add(carol.key_package())
    assert ag.has_pending_commit and ag.epoch == 1
    assert code_of(ag.encrypt, b"x") == "pending_commit"
    assert code_of(ag.add, carol.key_package()) == "pending_commit"
    assert code_of(ag.remove, 1) == "pending_commit"
    assert code_of(ag.commit) == "pending_commit"
    ag.discard_pending()
    assert not ag.has_pending_commit and ag.epoch == 1

    commit = ag.commit()
    ag.apply_pending()
    assert ag.epoch == 2
    assert bg.process(commit).epoch == 2


def test_competing_commit_clears_pending(pair):
    _a, ag, _b, bg = pair
    alice_commit = ag.commit()
    bob_commit = bg.commit()
    bg.apply_pending()
    assert ag.process(bob_commit).epoch == 2
    assert ag.has_pending_commit is False
    assert code_of(ag.apply_pending) == "no_pending_commit"
    assert code_of(bg.process, alice_commit) == "invalid_epoch"  # stale bytes
    assert ag.export_secret(b"", b"", 16) == bg.export_secret(b"", b"", 16)


def test_own_commit_echo_applies(pair):
    _a, ag, _b, bg = pair
    c = ag.commit()
    assert ag.process(c).kind == "commit"
    assert not ag.has_pending_commit and ag.epoch == 2
    bg.process(c)
    assert ag.export_secret(b"", b"", 16) == bg.export_secret(b"", b"", 16)


def test_duplicates(pair):
    _a, ag, _b, bg = pair
    ct = ag.encrypt(b"once")
    bg.process(ct)
    assert code_of(bg.process, ct) == "invalid_message"
    c = ag.commit()
    ag.apply_pending()
    bg.process(c)
    assert code_of(bg.process, c) == "invalid_epoch"
    assert bg.process(ag.encrypt(b"ok")).data == b"ok"


def test_rejected_messages_keep_state_intact(pair):
    _a, ag, _b, bg = pair
    ct = ag.encrypt(b"genuine", b"aad-value")
    t1 = bytearray(ct)
    t1[-1] ^= 1
    t2 = bytearray(ct)
    i = ct.index(b"aad-value")
    t2[i] ^= 1
    assert code_of(bg.process, bytes(t1)) == "invalid_message"
    assert code_of(bg.process, bytes(t2)) == "invalid_message"
    assert bg.process(ct).data == b"genuine"


def test_old_epoch_messages(pair):
    _a, ag, _b, bg = pair
    olds = []
    for _ in range(5):
        olds.append(ag.encrypt(b"old"))
        c = ag.commit()
        ag.apply_pending()
        bg.process(c)
    results = []
    for m in olds:
        try:
            bg.process(m)
            results.append("ok")
        except Exception as e:  # noqa: BLE001
            results.append(e.code)
    # Three prior epochs are retained; older ones are gone.
    assert results == ["invalid_epoch", "invalid_epoch", "ok", "ok", "ok"]
