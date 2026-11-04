import mls_py


def test_create_join_and_message(pair, suite):
    _a, ag, _b, bg = pair
    assert ag.group_id == bg.group_id
    assert ag.epoch == bg.epoch == 1
    assert ag.cipher_suite == bg.cipher_suite == suite
    ct = ag.encrypt(b"hello")
    assert isinstance(ct, bytes)
    ev = bg.process(ct)
    assert ev.kind == "application"
    assert ev.data == b"hello"
    assert ev.aad == b""
    assert ev.sender_index == 0
    assert ev.epoch == 1
    assert ev.removed is False


def test_aad_round_trip_and_is_not_encrypted(pair):
    _a, ag, _b, bg = pair
    ct = ag.encrypt(b"body", b"routing-header")
    assert b"routing-header" in ct  # authenticated, NOT encrypted
    assert b"body" not in ct
    ev = bg.process(ct)
    assert (ev.data, ev.aad) == (b"body", b"routing-header")


def test_export_secret_agrees(pair):
    _a, ag, _b, bg = pair
    for label in (b"", b"app"):
        s = ag.export_secret(label, b"ctx", 32)
        assert len(s) == 32
        assert s == bg.export_secret(label, b"ctx", 32)
    assert ag.export_secret(b"a", b"", 32) != ag.export_secret(b"b", b"", 32)


def test_bytes_like_inputs_accepted(pair):
    _a, ag, _b, bg = pair
    ct = ag.encrypt(bytearray(b"ba"), bytearray(b"x"))
    assert bg.process(bytearray(ct)).data == b"ba"


def test_event_is_immutable_and_repr_hides_contents(pair):
    _a, ag, _b, bg = pair
    ev = bg.process(ag.encrypt(b"top secret", b"hidden aad"))
    r = repr(ev)
    assert "top secret" not in r and "hidden aad" not in r
    assert "data_len=10" in r
    try:
        ev.data = b"x"  # type: ignore[misc]
    except AttributeError:
        pass
    else:
        raise AssertionError("Event must be immutable")
    ev2 = ev
    assert ev == ev2 and hash(ev) == hash(ev2)


def test_members_and_leaf_index(pair):
    _a, ag, _b, bg = pair
    assert ag.members == [(0, b"alice"), (1, b"bob")]
    assert (ag.leaf_index, bg.leaf_index) == (0, 1)


def test_module_constants():
    assert 1 in mls_py.SUPPORTED_CIPHER_SUITES
    assert mls_py.DEFAULT_CIPHER_SUITE == 1
    assert mls_py.DEFAULT_MAX_MESSAGE_SIZE == 16 * 2**20
    assert "invalid_message" in mls_py.ERROR_CODES
    assert mls_py.__version__ == "0.1.0"


def test_objects_not_picklable(pair):
    import pickle

    alice, ag, _b, _bg = pair
    for obj in (alice, ag):
        try:
            pickle.dumps(obj)
        except Exception:
            continue
        raise AssertionError("client/group state must not be picklable")
