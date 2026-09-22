from ropnroll.core import loader
from ropnroll.solve.onegadget import find_one_gadgets


def test_finds_empirically_confirmed_one_gadget(libc_path):
    img = loader.load(libc_path)
    rep = find_one_gadgets(img, max_insns=5000)
    assert rep.searched_sites > 0
    assert len(rep.candidates) >= 1
    c = rep.candidates[0]
    assert c.string in (b"/bin/sh\x00", b"/bin/bash\x00", b"/bin/dash\x00")
    assert c.instructions_run > 0
