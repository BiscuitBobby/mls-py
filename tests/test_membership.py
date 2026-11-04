from conftest import code_of


def test_three_member_sync(pair, make_client):
    _a, ag, _b, bg = pair
    carol = make_client(b"carol")
    commit, welcome = bg.add(carol.key_package())
    bg.apply_pending()
    cg = carol.join(welcome)
    ev = ag.process(commit)
    assert (ev.kind, ev.sender_index, ev.epoch) == ("commit", 1, 2)
    for sender, others in ((ag, (bg, cg)), (bg, (ag, cg)), (cg, (ag, bg))):
        ct = sender.encrypt(b"m")
        for o in others:
            assert o.process(ct).data == b"m"


def test_removal_is_terminal(pair, make_client):
    _a, ag, bob, bg = pair
    carol = make_client(b"carol")
    c, w = ag.add(carol.key_package())
    ag.apply_pending()
    bg.process(c)
    cg = carol.join(w)

    rm = ag.remove(1)
    ag.apply_pending()
    cg.process(rm)
    ev = bg.process(rm)
    assert ev.removed and ev.kind == "commit" and ev.epoch == 3
    assert bg.is_active is False

    ct = ag.encrypt(b"after removal")
    assert cg.process(ct).data == b"after removal"
    assert code_of(bg.process, ct) == "invalid_group_state"
    assert code_of(bg.encrypt, b"x") == "invalid_group_state"
    assert code_of(lambda: bg.epoch) == "invalid_group_state"

    # The removed handle is still alive (held by the fixture); it owns no
    # stored state, so there is nothing to load.
    assert code_of(bob.load_group, bg.group_id) == "group_not_found"


def test_rejoin_after_removal(pair):
    _a, ag, bob, bg = pair
    rm = ag.remove(1)
    ag.apply_pending()
    assert bg.process(rm).removed
    _c, w = ag.add(bob.key_package())
    ag.apply_pending()
    bg2 = bob.join(w)
    assert bg2.process(ag.encrypt(b"back")).data == b"back"


def test_sender_index_after_membership_change(pair, make_client):
    _a, ag, _b, bg = pair
    carol = make_client(b"carol")
    c, w = ag.add(carol.key_package())
    ag.apply_pending()
    bg.process(c)
    cg = carol.join(w)
    rm = ag.remove(1)
    ag.apply_pending()
    cg.process(rm)
    assert ag.process(cg.encrypt(b"c")).sender_index == 2
    assert ag.members == [(0, b"alice"), (2, b"carol")]

