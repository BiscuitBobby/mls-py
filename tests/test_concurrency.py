import threading
import time
from concurrent.futures import ThreadPoolExecutor

import mls_py


def test_concurrent_encrypt_process_export(pair):
    _a, ag, _b, bg = pair
    with ThreadPoolExecutor(max_workers=8) as ex:
        msgs = [m for ms in ex.map(lambda i: [ag.encrypt(b"%d-%d" % (i, j)) for j in range(25)], range(8)) for m in ms]
    assert len(msgs) == 200

    def consume(chunk):
        ag.export_secret(b"", b"", 16)
        return sum(1 for m in chunk if bg.process(m).kind == "application")

    with ThreadPoolExecutor(max_workers=8) as ex:
        got = sum(ex.map(consume, [msgs[i : i + 25] for i in range(0, 200, 25)]))
    assert got == 200


def test_runtime_released_during_operations(make_client):
    """Another Python thread keeps running while MLS work happens."""
    alice = make_client(b"alice")
    group = alice.create_group()
    joiners = [make_client(b"m%d" % i) for i in range(40)]
    ticks = 0
    stop = threading.Event()

    def ticker():
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            time.sleep(0)

    t = threading.Thread(target=ticker)
    t.start()
    try:
        for j in joiners:
            group.add(j.key_package())
            group.apply_pending()
    finally:
        stop.set()
        t.join()
    assert ticks > 0
    assert len(group.members) == 41


def test_concurrent_calls_after_removal(pair):
    _a, ag, _b, bg = pair
    rm = ag.remove(1)
    ag.apply_pending()
    errors = []

    def spam():
        for _ in range(50):
            try:
                bg.encrypt(b"x")
            except mls_py.MlsError as e:
                errors.append(e.code)

    threads = [threading.Thread(target=spam) for _ in range(4)]
    for t in threads:
        t.start()
    ev = bg.process(rm)
    for t in threads:
        t.join()
    assert ev.removed
    assert set(errors) <= {"invalid_group_state"}
    assert not bg.is_active


def test_drop_client_while_group_in_use(pair):
    alice, ag, _b, bg = pair
    stop = threading.Event()
    out = []

    def worker():
        while not stop.is_set():
            out.append(bg.process(ag.encrypt(b"w")).data)

    t = threading.Thread(target=worker)
    t.start()
    del alice
    time.sleep(0.05)
    stop.set()
    t.join()
    assert out and all(d == b"w" for d in out)
