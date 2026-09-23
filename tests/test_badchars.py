import pytest
import keystone

from ropnroll.core import badchars, loader, scanner
from ropnroll.solve.pool import GadgetPool
from tests.helpers import write_minimal_pe


def test_parse_bad_chars_accepts_common_formats():
    assert badchars.parse_bad_chars("000a0d") == frozenset({0, 0x0A, 0x0D})
    assert badchars.parse_bad_chars("00,0a,0d") == frozenset({0, 0x0A, 0x0D})
    assert badchars.parse_bad_chars("00 0a 0d") == frozenset({0, 0x0A, 0x0D})
    assert badchars.parse_bad_chars("\\x00\\x0a\\x0d") == frozenset({0, 0x0A, 0x0D})


def test_parse_bad_chars_none_and_empty():
    assert badchars.parse_bad_chars(None) == frozenset()
    assert badchars.parse_bad_chars("") == frozenset()


def test_parse_bad_chars_rejects_odd_length():
    with pytest.raises(ValueError):
        badchars.parse_bad_chars("0")


def test_value_bad_bytes_little_endian():
    # 0x0a sits in the second-lowest byte of this value's little-endian encoding
    assert badchars.value_bad_bytes(0x0A000001, 4, frozenset({0x0A})) == [0x0A]
    assert badchars.value_bad_bytes(0x01020304, 4, frozenset({0x0A})) == []


def test_has_bad_bytes_empty_bad_set_is_always_ok():
    assert badchars.has_bad_bytes(0, 8, frozenset()) is False
    assert badchars.has_bad_bytes(0xFFFFFFFFFFFFFFFF, 8, frozenset()) is False


def _synthetic_pool(tmp_path, code_asm: str, base: int = 0x400000):
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    enc, _ = ks.asm(code_asm)
    path = str(tmp_path / "badchars.exe")
    write_minimal_pe(path, "x86_64", bytes(enc), base=base)
    img = loader.load(path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(max_insns=3))
    pool = GadgetPool(use_cache=False)
    pool.add(img, gadgets)
    return pool, img


def test_pool_all_excludes_gadget_addresses_with_bad_chars(tmp_path):
    # a run of single-instruction "pop <reg> ; ret" gadgets -- each one's
    # bytes differ (so none get deduped against each other), giving several
    # gadgets at distinct addresses to filter between.
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10"]
    code = "\n".join(f"pop {r} ; ret" for r in regs)
    pool, img = _synthetic_pool(tmp_path, code)
    baseline = pool.all()
    assert baseline

    victim = next(b for g in baseline for b in g.address.to_bytes(8, "little") if b != 0)
    pool.bad_chars = frozenset({victim})
    filtered = pool.all()

    assert len(filtered) < len(baseline)
    assert all(victim not in g.address.to_bytes(8, "little") for g in filtered)


def test_pool_all_unaffected_when_no_bad_chars_set(tmp_path):
    pool, img = _synthetic_pool(tmp_path, "ret\n" * 5)
    assert pool.all() == pool.all()  # stable, no filtering applied by default
    assert pool.bad_chars == frozenset()


def test_chain_bad_char_warnings_flags_literal_target(tmp_path):
    """A user-supplied call target/argument can't be fixed by picking a
    different gadget -- chain_bad_char_warnings should still surface it."""
    from ropnroll.solve.callchain import build_call

    pool, img = _synthetic_pool(tmp_path, "pop rcx ; ret")
    bad = frozenset({0x0A})
    # target's low byte is 0x0a -- must show up as a warning regardless of
    # which gadgets got used to set up the call.
    res = build_call(pool, target=0x40200A, args=[0x1337])
    assert res.ok
    warnings = badchars.chain_bad_char_warnings(res.chain, bad)
    assert any("0x40200a" in w for w in warnings)


def test_chain_bad_char_warnings_empty_when_bad_chars_empty(tmp_path):
    from ropnroll.solve.callchain import build_call

    pool, img = _synthetic_pool(tmp_path, "pop rcx ; ret")
    res = build_call(pool, target=0x40200A, args=[0x1337])
    assert res.ok
    assert badchars.chain_bad_char_warnings(res.chain, frozenset()) == []
