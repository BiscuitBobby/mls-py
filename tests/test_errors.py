import pytest

import mls_py
from conftest import code_of


def test_error_shape():
    with pytest.raises(mls_py.MlsError) as ei:
        mls_py.Client(b"")
    e = ei.value
    assert e.code == "invalid_argument"
    assert isinstance(e.message, str)
    assert e.code in mls_py.ERROR_CODES
    assert str(e).startswith("invalid_argument: ")
    assert isinstance(e, Exception)


def test_client_argument_validation():
    mls_py.Client(b"x" * 256)
    assert code_of(mls_py.Client, b"x" * 257) == "invalid_argument"
    assert code_of(mls_py.Client, b"a", max_message_size=0) == "invalid_argument"
    assert code_of(mls_py.Client, b"a", max_message_size=-1) == "invalid_argument"
    for cs in (0, 3, 7, 65002, 65100, 2**16, -1, 2**80):
        assert code_of(mls_py.Client, b"a", cipher_suite=cs) == "unsupported_cipher_suite"
    with pytest.raises(TypeError):
        mls_py.Client("not-bytes")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        mls_py.Client(b"a", cipher_suite=True)  # bool is not an int here
    with pytest.raises(TypeError):
        mls_py.Client(b"a", 1)  # keyword-only


def test_int_arguments_fail_cleanly(pair):
    _a, ag, _b, _bg = pair
    for bad in (-1, 2**32, 2**100):
        assert code_of(ag.remove, bad) == "invalid_argument"
    assert code_of(ag.remove, 0) == "invalid_argument"  # self
    assert code_of(ag.remove, 9) == "invalid_argument"  # empty leaf
    with pytest.raises(TypeError):
        ag.remove(True)
    with pytest.raises(TypeError):
        ag.remove(1.0)


def test_export_secret_bounds(pair):
    _a, ag, _b, _bg = pair
    ag.export_secret(b"l" * 255, b"c" * 65536, 1024)
    assert code_of(ag.export_secret, b"l" * 256, b"", 16) == "invalid_argument"
    assert code_of(ag.export_secret, b"", b"c" * 65537, 16) == "invalid_argument"
    for n in (0, 1025, -1, 2**70):
        assert code_of(ag.export_secret, b"", b"", n) == "invalid_argument"


def test_invalid_inputs(pair, make_client):
    alice, ag, bob, bg = pair
    assert code_of(bob.join, b"garbage") == "invalid_welcome"
    assert code_of(bob.join, bob.key_package()) == "invalid_welcome"
    assert code_of(ag.add, b"garbage") == "invalid_key_package"
    assert code_of(ag.add, bob.key_package()) == "invalid_key_package"  # already a member
    ct = ag.encrypt(b"x")
    assert code_of(ag.add, ct) == "invalid_key_package"
    for m in (b"", b"\x00\x01zz", bob.key_package(), ct + b"\x00", ct[: len(ct) // 2]):
        assert code_of(bg.process, m) == "invalid_message"
    assert code_of(ag.process, ct) == "invalid_message"  # own message
    other = alice.create_group()
    assert code_of(ag.process, other.encrypt(b"x")) == "invalid_message"
    assert code_of(alice.load_group, b"") == "invalid_argument"
    assert code_of(alice.load_group, b"\x00" * 16) == "group_not_found"
    assert bg.process(ag.encrypt(b"still ok")).data == b"still ok"


def test_cross_suite_rejected():
    if len(mls_py.SUPPORTED_CIPHER_SUITES) < 2:
        pytest.skip("single-suite build")
    s1, s2 = mls_py.SUPPORTED_CIPHER_SUITES[:2]
    a = mls_py.Client(b"a", cipher_suite=s1)
    b = mls_py.Client(b"b", cipher_suite=s2)
    assert code_of(a.create_group().add, b.key_package()) == "unsupported_cipher_suite"
    g2 = mls_py.Client(b"a2", cipher_suite=s2).create_group()
    _c, w = g2.add(mls_py.Client(b"b2", cipher_suite=s2).key_package())
    assert code_of(a.join, w) == "unsupported_cipher_suite"


def test_input_size_limit(make_client):
    alice = make_client(b"alice")
    bob = make_client(b"bob", max_message_size=4096)
    assert bob.max_message_size == 4096
    ag = alice.create_group()
    _c, w = ag.add(bob.key_package())
    ag.apply_pending()
    bg = bob.join(w)
    assert code_of(bg.process, ag.encrypt(b"\x00" * 5000)) == "input_too_large"
    assert code_of(bg.encrypt, b"\x00" * 4097) == "input_too_large"
    assert code_of(bob.join, b"\x00" * 4097) == "input_too_large"
    assert code_of(bg.add, b"\x00" * 4097) == "input_too_large"
    assert bg.process(ag.encrypt(b"")).data == b""
