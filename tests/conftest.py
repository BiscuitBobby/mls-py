import pytest

import mls_py


@pytest.fixture(params=mls_py.SUPPORTED_CIPHER_SUITES, ids=lambda cs: f"suite{cs}")
def suite(request):
    return request.param


@pytest.fixture
def make_client(suite):
    def make(name: bytes, **kw):
        return mls_py.Client(name, cipher_suite=suite, **kw)

    return make


@pytest.fixture
def pair(make_client):
    """(alice, alice_group, bob, bob_group) with Bob added by Alice."""
    alice, bob = make_client(b"alice"), make_client(b"bob")
    ag = alice.create_group()
    _commit, welcome = ag.add(bob.key_package())
    ag.apply_pending()
    bg = bob.join(welcome)
    return alice, ag, bob, bg


def code_of(fn, *args, **kwargs):
    with pytest.raises(mls_py.MlsError) as ei:
        fn(*args, **kwargs)
    return ei.value.code
