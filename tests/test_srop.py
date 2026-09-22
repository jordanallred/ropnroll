from ropnroll.core import loader, scanner
from ropnroll.solve.pool import GadgetPool
from ropnroll.solve.srop import build_srop_execve, emulate_srop_chain, verify_srop_frame


def test_srop_execve_binsh(libc_path):
    img = loader.load(libc_path)
    gadgets = scanner.scan_image(img, scanner.ScanOptions(max_insns=6))
    pool = GadgetPool()
    pool.add(img, gadgets)

    binsh = None
    for seg in img.segments:
        if not seg.executable and seg.readable:
            idx = seg.data.find(b"/bin/sh\x00")
            if idx != -1:
                binsh = seg.vaddr + idx
                break
    assert binsh is not None

    res = build_srop_execve(pool, path_ptr=binsh, argv_ptr=0, envp_ptr=0)
    assert res.ok, res.solve.log
    # only a single gadget needed (rax=15 popper) -- SROP's whole point
    assert len([w for w in res.chain.words if w.label.startswith("0x") and "pop" in w.label]) <= 1

    expect = {"rax": 59, "rdi": binsh, "rsi": 0, "rdx": 0}
    assert verify_srop_frame(res.chain, res.frame_offset_words, expect)

    ok, result = emulate_srop_chain(img, res.chain, expect)
    assert ok, result
