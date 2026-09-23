"""A chain built against a module whose real runtime base isn't known yet
(no leak, no --base) must stay symbolic -- (module, offset) instead of a
baked address -- so the exploit script can resolve base + offset once it
actually has a leak, instead of the tool silently baking in the file's own
linker-preferred-base address (see solve/chain.py's ChainWord)."""

import pytest

from ropnroll.cli.main import _load_pool
from ropnroll.core import loader, output, scanner
from ropnroll.core.archinfo import get_archinfo
from ropnroll.core.gadget import Gadget, Terminator
from ropnroll.solve import callchain
from ropnroll.solve.chain import Chain, ChainWord
from ropnroll.solve.pool import GadgetPool
from tests.helpers import write_minimal_pe

PE_FIXTURE = "tests/fixtures/pe/cli-64.exe"


# ---- Image.base_known ------------------------------------------------


def test_pie_pe_defaults_to_base_unknown():
    img = loader.load(PE_FIXTURE)
    assert img.pie is True
    assert img.base_known is False


def test_nonpie_pe_defaults_to_base_known(tmp_path):
    path = str(tmp_path / "nopie.exe")
    write_minimal_pe(path, "x86_64", b"\xc3")  # single `ret`, no /DYNAMICBASE
    img = loader.load(path)
    assert img.pie is False
    assert img.base_known is True


def test_rebase_marks_base_known():
    img = loader.load(PE_FIXTURE)
    assert img.base_known is False
    rebased = img.rebase(0x7FFB00000000)
    assert rebased.base_known is True
    assert rebased.image_base == 0x7FFB00000000


def test_rebase_preserves_offset_from_base():
    """Offset from a module's own base must survive rebase() -- it's the
    whole reason (module, offset) is a stable thing to hand an exploit
    script: base + offset stays correct no matter what base you learn."""
    img = loader.load(PE_FIXTURE)
    addr = img.image_base + 0x4242
    offset = addr - img.image_base
    rebased = img.rebase(0x7FFB00000000)
    assert (rebased.image_base + offset) - rebased.image_base == offset


# ---- GadgetPool.image_of ----------------------------------------------


def test_pool_image_of_roundtrips():
    img = loader.load(PE_FIXTURE)
    pool = GadgetPool()
    pool.add(img, [])
    assert pool.image_of(img.path) is img
    assert pool.image_of("no/such/path") is None


# ---- Chain / ChainWord tagging (pure, no real scanning needed) --------


def _fake_gadget(module: str, address: int, text: str = "pop rax ; ret") -> Gadget:
    return Gadget(
        address=address,
        raw=b"\x58\xc3",
        text=text,
        insns=[],
        terminator=Terminator.RET,
        module=module,
    )


def _pool_with(img) -> GadgetPool:
    pool = GadgetPool()
    pool.add(img, [])
    return pool


def test_append_gadget_block_tags_symbolic_when_base_unknown():
    img = loader.load(PE_FIXTURE)  # pie=True -> base_known=False
    pool = _pool_with(img)
    ai = get_archinfo("x86_64")
    g = _fake_gadget(img.path, img.image_base + 0x1000)
    from ropnroll.semantics.effect import GadgetEffect

    eff = GadgetEffect(ok=True, sp_delta=8, reg_effects={}, mem_writes=[], mem_reads=[])

    chain = Chain(ai=ai)
    chain.append_gadget_block(g, eff, {}, pool=pool)
    word = chain.words[0]
    assert word.value == g.address
    assert word.module == img.path
    assert word.offset == g.address - img.image_base


def test_append_gadget_block_resolved_when_base_known():
    img = loader.load(PE_FIXTURE).rebase(0x7FFB00000000)  # base_known=True
    pool = _pool_with(img)
    ai = get_archinfo("x86_64")
    g = _fake_gadget(img.path, img.image_base + 0x1000)
    from ropnroll.semantics.effect import GadgetEffect

    eff = GadgetEffect(ok=True, sp_delta=8, reg_effects={}, mem_writes=[], mem_reads=[])

    chain = Chain(ai=ai)
    chain.append_gadget_block(g, eff, {}, pool=pool)
    word = chain.words[0]
    assert word.value == g.address
    assert word.module is None
    assert word.offset is None


def test_set_last_gadget_tags_symbolic():
    img = loader.load(PE_FIXTURE)
    pool = _pool_with(img)
    ai = get_archinfo("x86_64")
    g = _fake_gadget(img.path, img.image_base + 0x2000, "syscall ; ret")

    chain = Chain(ai=ai)
    chain.words.append(ChainWord(None, "placeholder"))
    chain.set_last_gadget(pool, g, "syscall gadget")
    word = chain.words[-1]
    assert word.module == img.path
    assert word.offset == g.address - img.image_base


def test_extend_preserves_symbolic_tag():
    img = loader.load(PE_FIXTURE)
    pool = _pool_with(img)
    ai = get_archinfo("x86_64")
    g = _fake_gadget(img.path, img.image_base + 0x3000)

    a = Chain(ai=ai)
    a.words.append(ChainWord(None, "-> next"))
    b = Chain(ai=ai)
    b.set_last_gadget(pool, g, "next gadget")
    a.extend(b)
    assert a.words[-1].module == img.path
    assert a.words[-1].offset == g.address - img.image_base


def test_no_pool_means_no_tagging():
    """Without a pool (e.g. a caller that never had one), words are plain
    values -- exactly today's behavior, not a new failure mode."""
    ai = get_archinfo("x86_64")
    g = _fake_gadget("some/module", 0x1000)
    from ropnroll.semantics.effect import GadgetEffect

    eff = GadgetEffect(ok=True, sp_delta=8, reg_effects={}, mem_writes=[], mem_reads=[])
    chain = Chain(ai=ai)
    chain.append_gadget_block(g, eff, {})
    assert chain.words[0].module is None


# ---- build_call: the actual "leak later, resolve at exploit time" path


def test_call_target_symbolic_without_base_then_resolved_after_rebase():
    pool, images = _load_pool([PE_FIXTURE], scanner.ScanOptions(), use_cache=False)
    img = images[0]
    target = img.image_base + 0x1234
    res = callchain.build_call(pool, target=target, args=[], target_module=img.path)
    call_word = next(w for w in res.chain.words if w.label.startswith("call target"))
    assert call_word.value == target
    assert call_word.module == img.path
    assert call_word.offset == 0x1234

    new_base = 0x7FFB00000000
    pool2, images2 = _load_pool(
        [PE_FIXTURE],
        scanner.ScanOptions(),
        use_cache=False,
        base=[f"{PE_FIXTURE}={hex(new_base)}"],
    )
    img2 = images2[0]
    target2 = img2.image_base + 0x1234
    res2 = callchain.build_call(pool2, target=target2, args=[], target_module=img2.path)
    call_word2 = next(w for w in res2.chain.words if w.label.startswith("call target"))
    assert call_word2.value == target2
    assert call_word2.module is None
    assert call_word2.offset is None


# ---- output.py: export formats ----------------------------------------


def _mixed_chain():
    ai = get_archinfo("x86_64")
    chain = Chain(ai=ai)
    chain.words.append(
        ChainWord(
            0x1400013AC,
            "0x1400013ac: pop rcx ; ret",
            module="kernel32.dll",
            offset=0x13AC,
        )
    )
    chain.words.append(ChainWord(0x41414141, "rcx = 0x41414141"))
    return chain


def test_to_pwntools_emits_symbolic_expression_and_todo_header():
    text = output.to_pwntools(_mixed_chain())
    assert "kernel32_base = 0  # TODO: leaked runtime base of kernel32.dll" in text
    assert "kernel32_base + 0x13ac" in text
    assert "0x41414141" in text


def test_to_json_includes_module_and_offset():
    import json

    words = json.loads(output.to_json(_mixed_chain()))
    assert words[0]["module"] == "kernel32.dll"
    assert words[0]["offset"] == 0x13AC
    assert words[1]["module"] is None


def test_to_raw_refuses_unresolved_chain():
    with pytest.raises(ValueError, match="kernel32.dll"):
        output.to_raw(_mixed_chain())


def test_to_c_array_refuses_unresolved_chain():
    with pytest.raises(ValueError, match="kernel32.dll"):
        output.to_c_array(_mixed_chain())


def test_to_raw_works_once_fully_resolved():
    ai = get_archinfo("x86_64")
    chain = Chain(ai=ai)
    chain.words.append(ChainWord(0x1400013AC, "resolved word"))
    data = output.to_raw(chain)
    assert len(data) == 8
    assert int.from_bytes(data, "little") == 0x1400013AC


def test_unresolved_modules_dedupes_and_preserves_order():
    ai = get_archinfo("x86_64")
    chain = Chain(ai=ai)
    chain.words.append(ChainWord(1, "a", module="b.dll", offset=1))
    chain.words.append(ChainWord(2, "b", module="a.dll", offset=2))
    chain.words.append(ChainWord(3, "c", module="b.dll", offset=3))
    assert output.unresolved_modules(chain) == ["b.dll", "a.dll"]


def test_stack_layout_renders_symbolic_words_without_crashing():
    text = output.stack_layout(_mixed_chain())
    assert "kernel32_base + 0x13ac" in text
