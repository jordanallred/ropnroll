from ropnroll.core import loader, scanner
from ropnroll.core.cache import EffectDiskCache, GadgetScanCache
from ropnroll.core.scanner import SCANNER_VERSION, _scan_key
from ropnroll.semantics.effect import EKind, GadgetEffect, MemEffect, RegEffect
from ropnroll.semantics.engine import SEMANTIC_ENGINE_VERSION, SemanticEngine


def _sample_effect() -> GadgetEffect:
    return GadgetEffect(
        reg_effects={
            "rdi": RegEffect(kind=EKind.LOAD, src="rsp", k=1, c=8, size=8),
            "rax": RegEffect(kind=EKind.ADD, src="rbx", k=1, c=5, size=8),
        },
        mem_writes=[
            MemEffect(
                addr=RegEffect(kind=EKind.COPY, src="rsp", size=8),
                value=RegEffect(kind=EKind.CONST, c=0x41, size=8),
                size=8,
                is_write=True,
            )
        ],
        mem_reads=[],
        sp_delta=16,
        ok=True,
        notes="",
    )


def test_gadget_effect_dict_roundtrip():
    eff = _sample_effect()
    restored = GadgetEffect.from_dict(eff.to_dict())
    assert restored == eff


def test_disk_cache_roundtrip(tmp_path):
    eff = _sample_effect()
    raw = b"\x5f\xc3"  # arbitrary gadget bytes, not actually disassembled here
    cache = EffectDiskCache("deadbeef", version=1, root=tmp_path)
    assert cache.get(raw) is None
    cache.put(raw, eff)
    cache.flush()

    reloaded = EffectDiskCache("deadbeef", version=1, root=tmp_path)
    got = reloaded.get(raw)
    assert got == eff


def test_disk_cache_version_mismatch_is_cold(tmp_path):
    eff = _sample_effect()
    raw = b"\x5f\xc3"
    cache = EffectDiskCache("deadbeef", version=1, root=tmp_path)
    cache.put(raw, eff)
    cache.flush()

    newer = EffectDiskCache("deadbeef", version=2, root=tmp_path)
    assert newer.get(raw) is None


def test_scan_cache_roundtrip(tmp_path):
    opts = scanner.ScanOptions(max_insns=4)
    key = _scan_key(opts)
    entries = [(0x10, b"\x5f\xc3", "RET"), (0x100, b"\x58\xc3", "RET")]
    cache = GadgetScanCache("deadbeef", key, SCANNER_VERSION, root=tmp_path)
    assert cache.get() is None
    cache.put(entries)

    reloaded = GadgetScanCache("deadbeef", key, SCANNER_VERSION, root=tmp_path)
    assert reloaded.get() == entries


def test_scan_cache_version_mismatch_is_cold(tmp_path):
    opts = scanner.ScanOptions(max_insns=4)
    key = _scan_key(opts)
    cache = GadgetScanCache("deadbeef", key, SCANNER_VERSION, root=tmp_path)
    cache.put([(0x10, b"\x5f\xc3", "RET")])

    newer = GadgetScanCache("deadbeef", key, SCANNER_VERSION + 1, root=tmp_path)
    assert newer.get() is None


def test_scan_cache_option_mismatch_is_cold(tmp_path):
    cache = GadgetScanCache(
        "deadbeef",
        _scan_key(scanner.ScanOptions(max_insns=4)),
        SCANNER_VERSION,
        root=tmp_path,
    )
    cache.put([(0x10, b"\x5f\xc3", "RET")])

    other = GadgetScanCache(
        "deadbeef",
        _scan_key(scanner.ScanOptions(max_insns=6)),
        SCANNER_VERSION,
        root=tmp_path,
    )
    assert other.get() is None


def test_scan_image_warm_cache_matches_fresh_scan(ntdll_path):
    # relies on the autouse _isolated_ropnroll_cache_dir fixture (conftest.py)
    # so this doesn't read/write the developer's real cache.
    img = loader.load(ntdll_path)
    opts = scanner.ScanOptions(max_insns=4)

    fresh = scanner.scan_image(img, opts, use_cache=False)
    assert fresh

    warm = scanner.scan_image(img, opts, use_cache=True)
    assert [(g.address, g.raw, g.terminator) for g in warm] == [
        (g.address, g.raw, g.terminator) for g in fresh
    ]

    cached_only = scanner.scan_image(img, opts, use_cache=True)
    assert [(g.address, g.raw, g.text, g.terminator) for g in cached_only] == [
        (g.address, g.raw, g.text, g.terminator) for g in fresh
    ]


def test_semantic_engine_warm_cache_matches_fresh_computation(ntdll_path, tmp_path):
    img = loader.load(ntdll_path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(max_insns=4))[:25]
    assert gadgets

    from ropnroll.core.archinfo import get_archinfo

    ai = get_archinfo(img.arch, img.little_endian)

    fresh_engine = SemanticEngine(img, ai, disk_cache=None)
    fresh = {g.raw: fresh_engine.compute(g) for g in gadgets}

    cache = EffectDiskCache(img.sha256, SEMANTIC_ENGINE_VERSION, root=tmp_path)
    warm_engine = SemanticEngine(img, ai, disk_cache=cache)
    for g in gadgets:
        warm_engine.compute(g)
    cache.flush()

    reloaded_cache = EffectDiskCache(img.sha256, SEMANTIC_ENGINE_VERSION, root=tmp_path)
    cold_engine = SemanticEngine(img, ai, disk_cache=reloaded_cache)
    for g in gadgets:
        assert cold_engine.compute(g) == fresh[g.raw]
