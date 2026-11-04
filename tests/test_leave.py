from conftest import code_of


def test_leave_committed_by_another_member(pair, make_client):
    _a, ag, _b, bg = pair
    proposal = bg.leave()
    assert bg.leave_pending is True
    for call in (bg.leave, bg.commit, lambda: bg.encrypt(b"x"), lambda: bg.remove(0)):
        assert code_of(call) == "leave_pending"
    assert code_of(bg.add, make_client(b"dave").key_package()) == "leave_pending"

    ev = ag.process(proposal)
    assert (ev.kind, ev.sender_index) == ("proposal", 1)
    assert code_of(ag.encrypt, b"x") == "commit_required"
    commit = ag.commit()
    ag.apply_pending()
    assert ag.members == [(0, b"alice")]

    ev = bg.process(commit)
    assert ev.removed and not bg.is_active


def test_leave_void_after_commit_without_removal(pair):
    _a, ag, _b, bg = pair
    bg.leave()  # never delivered
    commit = ag.commit()
    ag.apply_pending()
    assert bg.process(commit).removed is False
    assert bg.leave_pending is False
    ag.process(bg.leave())
    commit = ag.commit()
    ag.apply_pending()
    assert bg.process(commit).removed is True


def test_leave_preconditions(make_client, pair):
    alone = make_client(b"solo").create_group()
    assert code_of(alone.leave) == "invalid_group_state"
    _a, ag, _b, _bg = pair
    ag.commit()
    assert code_of(ag.leave) == "pending_commit"
