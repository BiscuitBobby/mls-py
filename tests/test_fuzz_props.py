"""Property tests: arbitrary bytes into every parsing entry point must yield
either a valid result or MlsError, never a crash or any other exception, and
must not corrupt group state."""

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import mls_py

SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])


def _fresh():
    a, b = mls_py.Client(b"alice"), mls_py.Client(b"bob")
    ag = a.create_group()
    _c, w = ag.add(b.key_package())
    ag.apply_pending()
    return a, ag, b, b.join(w)


A, AG, B, BG = _fresh()
SAMPLE_CT = AG.encrypt(b"sample", b"aad")
SAMPLE_COMMIT_SRC = _fresh()


def _expect_mls_error_or_ok(fn, data):
    try:
        fn(data)
    except mls_py.MlsError as e:
        assert e.code in mls_py.ERROR_CODES


@SETTINGS
@given(st.binary(max_size=4096))
def test_random_bytes_to_process(data):
    _expect_mls_error_or_ok(BG.process, data)


@SETTINGS
@given(st.binary(max_size=4096))
def test_random_bytes_to_join(data):
    _expect_mls_error_or_ok(B.join, data)


@SETTINGS
@given(st.binary(max_size=4096))
def test_random_bytes_to_add(data):
    _expect_mls_error_or_ok(lambda d: AG.add(d) and AG.discard_pending(), data)


@SETTINGS
@given(st.binary(max_size=1024))
def test_random_bytes_to_load_group(data):
    _expect_mls_error_or_ok(A.load_group, data)


@SETTINGS
@given(st.lists(st.tuples(st.integers(0, len(SAMPLE_CT) - 1), st.integers(1, 255)), min_size=1, max_size=4))
def test_mutated_ciphertext_never_crashes(mutations):
    data = bytearray(SAMPLE_CT)
    for i, x in mutations:
        data[i] ^= x
    _expect_mls_error_or_ok(BG.process, bytes(data))


def test_group_still_works_after_fuzzing():
    assert BG.process(AG.encrypt(b"alive")).data == b"alive"
