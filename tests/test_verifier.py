import sys
import threading

import pytest

import mls_py
from conftest import code_of


def test_verifier_sees_identities_and_keys(make_client):
    seen = []

    def verify(identity, key):
        assert type(identity) is bytes and type(key) is bytes
        seen.append((identity, key))
        return True

    alice = make_client(b"alice", verifier=verify)
    bob = make_client(b"bob")
    ag = alice.create_group()
    ag.add(bob.key_package())
    ids = {i for i, _ in seen}
    assert {b"alice", b"bob"} <= ids
    keys = {k for i, k in seen if i == b"bob"}
    assert len(keys) == 1 and len(next(iter(keys))) > 0


def test_rejections_leave_state_unchanged(make_client):
    alice = make_client(b"alice", verifier=lambda i, k: i != b"mallory")
    ag = alice.create_group()
    assert code_of(ag.add, make_client(b"mallory").key_package()) == "identity_rejected"
    assert not ag.has_pending_commit and ag.epoch == 0

    # A joiner rejects a Welcome whose group contains an unacceptable member.
    mallory = make_client(b"mallory")
    mg = mallory.create_group()
    bob = make_client(b"bob", verifier=lambda i, k: i != b"mallory")
    _c, w = mg.add(bob.key_package())
    mg.apply_pending()
    assert code_of(bob.join, w) == "identity_rejected"


@pytest.mark.parametrize("result", [1, "yes", None, b"\x01", [True]])
def test_only_true_accepts(make_client, result):
    alice = make_client(b"alice", verifier=lambda i, k: result)
    assert code_of(alice.create_group) == "identity_rejected"


def test_exception_rejects_and_is_reported(make_client, monkeypatch):
    reported = []
    monkeypatch.setattr(sys, "unraisablehook", lambda u: reported.append(u.exc_type))

    def boom(identity, key):
        raise ValueError("directory unavailable")

    alice = make_client(b"alice", verifier=boom)
    assert code_of(alice.create_group) == "identity_rejected"
    assert ValueError in reported


def test_reentry_from_verifier_is_refused(make_client, monkeypatch):
    errors = []
    monkeypatch.setattr(sys, "unraisablehook", lambda u: errors.append(u.exc_value))
    holder = {}

    def reenter(identity, key):
        holder["client"].key_package()  # must not deadlock
        return True

    alice = make_client(b"alice", verifier=reenter)
    holder["client"] = alice
    assert code_of(alice.create_group) == "identity_rejected"
    assert any(isinstance(e, RuntimeError) for e in errors)
    # Outside the callback the client works normally.
    alice.key_package()
    holder.clear()  # break the cycle through the verifier (see README)


def test_verifier_argument_validation(make_client):
    with pytest.raises(TypeError):
        make_client(b"alice", verifier=42)
    make_client(b"alice", verifier=None).create_group()


def test_verifier_runs_while_other_threads_use_python(make_client):
    calls = []
    lock = threading.Lock()

    def verify(identity, key):
        with lock:
            calls.append(identity)
        return True

    host = make_client(b"host", verifier=verify)
    hg = host.create_group()
    joiners = [make_client(b"m%d" % i, verifier=verify) for i in range(4)]
    welcomes = []
    for j in joiners:
        _c, w = hg.add(j.key_package())
        hg.apply_pending()
        welcomes.append(w)
    # Only the last Welcome is current, but every join runs the verifier on
    # its own thread while the others hold or wait for the interpreter.
    results = [None] * len(joiners)

    def join(i):
        try:
            results[i] = joiners[i].join(welcomes[i]).epoch
        except mls_py.MlsError as e:
            results[i] = e.code

    threads = [threading.Thread(target=join, args=(i,)) for i in range(len(joiners))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
        assert not t.is_alive()
    assert all(r is not None for r in results)
    assert b"host" in calls
