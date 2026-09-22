from ropnroll.core import loader, scanner
from ropnroll.core.cache import EffectDiskCache
from ropnroll.semantics.effect import EKind, GadgetEffect, MemEffect, RegEffect
from ropnroll.semantics.engine import SEMANTIC_ENGINE_VERSION, SemanticEngine


def _sample_effect() -> GadgetEffect:
    return GadgetEffect(
        reg_effects={
            "rdi": RegEffect(kind=EKind.LOAD, src="rsp", k=1, c=8, size=8),
            "rax": RegEffect(kind=EKind.ADD, src="rbx", k=1, c=5, size=8),
        },
        mem_writes=[MemEffect(addr=RegEffect(kind=EKind.COPY, src="rsp", size=8),
                               value=RegEffect(kind=EKind.CONST, c=0x41, size=8),
                               size=8, is_write=True)],
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


def test_semantic_engine_warm_cache_matches_fresh_computation(libc_path, tmp_path):
    img = loader.load(libc_path)
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
