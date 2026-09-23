from ropnroll.core import pattern


def test_create_known_prefix():
    # the exact, well-known Metasploit/mona pattern_create prefix
    assert pattern.create(30) == b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9"


def test_create_length_exact():
    for n in (0, 1, 3, 100, 1000):
        assert len(pattern.create(n)) == n


def test_create_wraps_after_period():
    # requesting more than PERIOD bytes must repeat, not raise or truncate
    long = pattern.create(pattern.PERIOD + 30)
    assert len(long) == pattern.PERIOD + 30
    assert long[: 30] == long[pattern.PERIOD: pattern.PERIOD + 30]


def test_offset_round_trip_hex_value():
    buf = pattern.create(pattern.PERIOD)
    for off in (0, 17, 4321, pattern.PERIOD - 4):
        chunk = buf[off: off + 4]
        value = int.from_bytes(chunk, "little")
        assert pattern.offset(hex(value)) == off


def test_offset_round_trip_8_byte_width():
    buf = pattern.create(pattern.PERIOD)
    off = 555
    chunk = buf[off: off + 8]
    value = int.from_bytes(chunk, "little")
    assert pattern.offset(hex(value), width=8) == off


def test_offset_literal_substring():
    buf = pattern.create(200)
    substr = buf[50:56].decode("ascii")
    assert pattern.offset(substr, literal=True) == 50


def test_offset_rejects_non_hex_without_literal_flag():
    import pytest
    with pytest.raises(ValueError):
        pattern.offset("zzzzzzzz")


def test_offset_not_found():
    assert pattern.offset("zzzzzzzz", literal=True) is None


def test_offset_infers_width_from_hex_digit_count():
    buf = pattern.create(pattern.PERIOD)
    off = 42
    value32 = int.from_bytes(buf[off: off + 4], "little")
    value64 = int.from_bytes(buf[off: off + 8], "little")
    assert pattern.offset(f"0x{value32:08x}") == off
    assert pattern.offset(f"0x{value64:016x}") == off
