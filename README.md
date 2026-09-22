# ropnroll

A ROP/JOP gadget finder and **automatic exploit-chain synthesizer**. You give it
a binary (and optionally a library it links against); it gives you a verified,
ready-to-fire chain for "call this function with these arguments," "make this
syscall," "pop a shell via a single sigreturn frame," "pivot the stack," or a
raw semantic gadget search — grounded in real CPU emulation at every step, not
a modeled instruction set.

Built for the case in the brief: you already have an arbitrary read/write
primitive (or a straightforward stack overflow) and want the rest of exploit
construction — register setup, calling convention, ASLR-aware addressing,
chain correctness — handled for you. It's been fired for real against a live
process (see [Live-fire demo](#live-fire-demo)), not just checked against a
static binary.

## Support matrix

Honest, not aspirational — "tested" means an automated test in `tests/`
actually exercises it against a real binary, every run.

| | ELF (Linux) | PE (Windows) |
|---|---|---|
| **x86-64** | ✅ tested — scanner, solver, call/syscall/SROP chains, live-fire exploit, verifier | ✅ tested — loading, mitigations (incl. Control Flow Guard), scanning, MS x64 ABI (RCX/RDX/R8/R9 + shadow space) |
| **x86 (32-bit)** | 🟡 wired up, scanner-level tested; solver/chain builders share the same code path as x86-64 but aren't exercised by an automated test against a real 32-bit target | ✅ tested — loading, mitigations, scanning (cdecl/stdcall stack-arg calling convention) |
| **ARM32 / ARM64** | 🟡 scanner + semantic engine wired up (shares the Unicorn-measured-effects design with x86), not exercised by an automated test against a real ARM binary this session | — |
| **MIPS32 / MIPS64** | 🟡 scanner + semantic engine wired up, including branch-delay-slot handling; not exercised by an automated test this session | — |
| **RISC-V / PowerPC / Thumb** | ❌ not supported | — |

SROP is Linux x86-64 only (it's a Linux kernel ABI detail, not portable). The
one-gadget finder and libc.rip lookup are scoped to x86/x86-64. Everything in
the ✅ row has a corresponding test in `tests/` that runs against a real
binary — not a mock — every time the suite runs.

## Why another one of these

Market research before writing any code, plus a live head-to-head:

| Tool | Approach | Notable limitation ropnroll targets |
|---|---|---|
| **Ropper** / **ROPgadget** | Syntactic/regex gadget search | No semantics at all — you read disassembly and build chains by hand |
| **angrop** (angr) | Symbolic execution via claripy | Powerful but slow (minutes on libc-sized targets per public benchmarks), no standalone CLI |
| **ROPium** | Custom IR + semantic queries (`rax=rbx+8`) | Gadget-level chaining only; no concrete verification, no JOP synthesis |
| **Ropinator** | Z3-backed solver + "affine executor" fast path, TUI + MCP server | Closest competitor — see below |
| **wedp** | WinDbg plugin for interactive Windows exploit dev | Different category: live-debugger-assisted workflow, not offline gadget/chain synthesis |
| **one_gadget** | Curated, per-glibc-version static analysis of source | Needs a maintained version database; ropnroll's `onegadget` instead concretely emulates forward from shell-string references, no database, works on whatever you hand it |
| **libc-database** / pwntools `libcdb` | Local database you build and query | ropnroll's `libcid` hits libc.rip directly — no local DB to maintain |

**Ropinator specifically** (`pip install ropinator`) is the tool ropnroll has the
most in common with, so I installed it and ran it head-to-head rather than
guessing. On `libc.so.6` at matched depth: Ropinator found 63,964 gadgets in
20s wall-clock (using ~2m39s of CPU across threads); ropnroll found 34,235 in
15.9s single-threaded, pure Python. The gap isn't random — **13,971 (~22%) of
Ropinator's results contain a mid-body conditional jump** (`je`, `jne`, ...),
which ropnroll's scanner deliberately excludes: a gadget whose body can branch
away before reaching its own terminator isn't a gadget you can rely on to do
what its disassembly suggests. That's a real trade — fewer total matches for a
hard reliability guarantee on every one that's returned.

Where ropnroll tries to actually add something new, not just re-implement:

1. **Semantics measured by real emulation, not modeled.** Every gadget's
   effect (which register gets what value, which memory gets written) is
   determined by actually running it in Unicorn across several input vectors
   and fitting the relation — correct for whatever the silicon does,
   automatically, with no per-opcode IR to write or get wrong.
2. **Concrete chain verification.** Once a chain is built, ropnroll re-emulates
   the *whole thing* against the real target's mapped memory and reports
   pass/fail per goal register, plus exactly which gadget faulted. This isn't
   a nicety — building this tool, the verifier (and a live-fire test against
   a real process) caught five real bugs in the solver, none of which would
   have been caught by inspection. See "How this was validated."
3. **A register/call/syscall solver that goes past one hop.** Backward-
   chaining search with memoization and a work budget, not just "pop-style
   gadget or bail" — finds multi-gadget indirection paths (`pop reg1` →
   `mov reg2, reg1` → `mov target, reg2`) when no direct popper exists, and
   explicitly rejects any candidate that turns out to be a disguised stack
   pivot or that touches memory through an uncontrolled register.
4. **SROP as a first-class goal**, not an afterthought: one sigreturn frame
   can set *every* register in a single step, including chaining straight
   into execve with zero conventional gadgets beyond a single `pop rax`.
5. **JOP is actually synthesized, not just tagged.** `ropnroll jop` finds
   *dispatcher* gadgets in the Bletsch et al. sense — an indirect jump/call
   through a register that the same gadget also advances by a constant — by
   asking the semantic engine directly, and can build the function-pointer
   table that turns one into an arbitrary-length JOP chain.
6. **CET/CFG-aware by construction.** Under Intel CET-IBT or Windows Control
   Flow Guard, an indirect branch may only land on an approved entry point.
   The JOP dispatcher builder checks a PE's real Guard CF function table
   (read via LIEF) instead of silently producing a chain that dies on the
   first hop on a hardened target.
7. **Empirical one-gadget discovery.** No curated glibc-version database:
   finds every place the binary's own code loads a shell-string pointer, and
   concretely emulates forward (with syscalls it can't service — `clone`,
   `mmap` — faked plausibly so real code paths like modern glibc's
   `posix_spawn`-based `system()` can be walked) to confirm a real execve
   fires. A hit is observed, not guessed.
8. **libc identification** against libc.rip from as few as 2–3 leaked symbol
   offsets, with the exact build's full symbol table and a download link, in
   one call.
9. **Live-target orchestration.** Attach to a running process via
   `/proc/<pid>/maps` (no ptrace, no special privileges), rebase gadget pools
   to the *actual* runtime addresses, and hand back an `Image` the rest of
   the tool uses exactly like a static file. `examples/live_fire_demo.py`
   uses this to build a chain and pop a real shell in a real subprocess.

What I'm *not* claiming to beat Ropinator on: it already ships a TUI and an
MCP server for agent-native use, and covers RISC-V/PowerPC/Thumb, which this
project doesn't attempt (see the support matrix above — a deliberate scope
decision, not an oversight). It's also a shipped, presumably battle-tested
tool; this was built and tested in one sitting against real binaries and a
real live process, not years of field use.

## Install

```bash
pip install -e .
```

Needs `capstone`, `lief`, `unicorn`, `rich` — all pulled in automatically.
`libcid` uses the standard library's `urllib` (no extra dependency).

## Usage

```bash
# security/mitigation report (NX, PIE, RELRO, canary, CFG for PE...)
ropnroll security ./target

# raw gadget listing (like Ropper/ROPgadget, but conditional-jump-free by default)
ropnroll scan ./target --regex "pop r.i"

# semantic search, ROPium-style DSL
ropnroll search ./target ./libc.so.6 --query "rdi=rax+8"

# stack pivots / JOP dispatcher gadgets
ropnroll pivot ./target
ropnroll jop ./libc.so.6

# build + verify a ret2libc call, emit a pwntools-ready payload
ropnroll call ./target ./libc.so.6 --target system --args 0x1cc42f \
    --verify --emit pwntools

# build + verify a direct execve("/bin/sh", NULL, NULL) syscall chain
ropnroll syscall ./libc.so.6 --nr 59 --args 0x1cc42f,0,0 --verify --emit pwntools

# a sigreturn frame that pops a shell with a single gadget, period
ropnroll srop ./libc.so.6 --args 0x1cc42f,0,0 --verify --emit pwntools

# empirically confirmed one-gadgets (no curated database)
ropnroll onegadget ./libc.so.6

# identify a libc build from a couple of leaked symbol offsets
ropnroll libcid --symbol system=0x58750 --symbol read=0x11bd20 --download /tmp/libc.so.6
```

`call`, `syscall`, and `srop` accept multiple binaries (target + libc) and
pool their gadgets together, same as a real exploit would pull from both.

## Live-fire demo

`examples/live_fire_demo.py` doesn't just build a chain — it spawns the real
vulnerable test binary, attaches to it, reads its *actual* runtime memory map
(standing in for whatever leak primitive gets you the same information
against a real target), rebases ropnroll's gadget pool to those live
addresses, builds a ret2libc chain with the solver, delivers it through the
real stack overflow, and confirms a real shell by running a command in it and
reading the output back:

```
[*] live binary base : 0x555555554000
[*] live libc   base : 0x7ffff7c00000
[*] building the call chain with ropnroll's own solver (not hand-picked)...
    pop-style: pop rdi ; ret @ 0x7ffff7d0c08d sets ['rdi']
[*] payload is 104 bytes (72 junk + 32 chain)
[+] SHELL CONFIRMED -- got real code execution via a chain ropnroll built itself
```

(This sandbox has ASLR disabled system-wide — no root available to change it
— so the "defeated" addresses happen to match the static file. The code path
reads live addresses from the live process either way, so the mechanism is
real; there just isn't a randomized target to prove it against here.)

## How this was validated

Nothing here is asserted without having actually run it — against real
binaries, a real libc, and in one case a real running process:

- Scanner + semantic engine run against `/lib/x86_64-linux-gnu/libc.so.6` (a
  real, unmodified system libc), freshly-`gcc`-compiled x86-64 test binaries,
  and real 32-bit/64-bit Windows PE executables — loading, mitigation
  detection (including Control Flow Guard), and gadget scanning all
  confirmed.
- The register solver, call/syscall/SROP chain builders were used to build
  an actual `system("/bin/sh")` ret2libc chain, a direct `execve` syscall
  chain, and a single-gadget SROP execve chain — sourced *entirely* from
  libc's own gadgets, no hand-picked addresses — then concretely
  re-emulated against libc's real mapped memory via `--verify`. All pass.
- The one-gadget finder found and concretely confirmed a real one-gadget in
  system libc by emulating through actual modern glibc `posix_spawn`
  internals (not a toy code path).
- The libc.rip lookup was checked against a real leak of this exact libc's
  `system`/`read`/`printf` offsets and correctly identified the exact build,
  including the `/bin/sh` string offset matching what the scanner found
  independently.
- `examples/live_fire_demo.py` spawns the real vulnerable binary, attaches
  via `/proc/<pid>/maps`, and pops a real shell with a chain the solver
  built itself — the strongest verification available short of a randomized
  remote target.
- Along the way, **five real bugs were found and fixed by this same testing
  loop, not by inspection**: a terminator-classification bug that let
  byte-overlap coincidences masquerade as valid gadgets; a `leave`-based
  pivot gadget getting silently used as a plain register setter; a
  chain-assembly gap that left an unfilled word between gadgets; a solver
  combinatorial-blowup bug once stricter safety checks narrowed the search
  (fixed with memoization + a work budget); and a ret2libc stack-alignment
  gotcha (entering a function via `ret` instead of `call` needs the same
  rsp%16==8 residue, or its own callees crash on the first SSE instruction)
  that the live-fire demo caught by actually crashing until it was fixed.

## Design notes

- **Scanner** (`core/scanner.py`): classic backward-window technique for x86
  (misaligned/"unintended" gadgets included, like Ropper/ROPgadget), fixed-
  instruction-width backward stepping for ARM/ARM64/MIPS (including MIPS
  branch-delay-slot handling). Deliberately excludes conditional branches,
  privileged instructions, and segment-register writes from gadget bodies —
  each found because a gadget slipping through actually broke something
  downstream, not preemptively.
- **Semantic engine** (`semantics/engine.py`): per-gadget effects are inferred
  by running the gadget in Unicorn with several trial register values (basis
  includes 0, all-ones, and a few patterns to catch AND/OR/XOR/scale
  relations, not just copy/add) and fitting a closed-form relation to each
  output register and memory write. Results are exact, not guessed — a
  relation is only accepted if it holds across every trial.
- **Solver** (`solve/chain.py`): greedy multi-cover search over "pop"-style
  (load-from-stack) gadgets first; falls back to depth-bounded, memoized
  backward-chaining search for register-to-register indirection when no
  direct popper exists. Rejects any candidate that's a disguised stack pivot
  or touches memory through a register nothing set.
- **Windows ABI awareness**: x86-64 PE targets automatically get the
  Microsoft calling convention (RCX/RDX/R8/R9 + 32 bytes of shadow space),
  not SysV's RDI/RSI/RDX/RCX/R8/R9 — picked from the binary's own format.
- **Stack-alignment correction**: `build_call` can take `bytes_before_chain`
  (how much padding precedes the chain in the final payload) and will insert
  a single bare `ret` gadget automatically if needed to keep a directly-
  entered function's incoming stack correctly aligned.

## Known limitations / roadmap (being upfront, not shipping silently)

- ARM/ARM64/MIPS share the same scanner/semantic-engine design as x86-64 and
  should work the same way, but aren't exercised by an automated test
  against a real binary this session — see the support matrix.
- RISC-V, PowerPC, and Thumb are explicitly out of scope (a deliberate call
  to focus on the architectures people actually hit, not a gap to fill
  later without reconsidering).
- Register-value solving is depth-bounded backward-chaining, not full
  BFS/constraint propagation like angrop — handles multi-hop indirection but
  isn't exhaustive.
- `onegadget`'s syscall-faking (for `clone`/`mmap`/etc.) is a pragmatic
  stand-in for real kernel behavior, not a full OS emulation layer — it gets
  far enough to find real gadgets through modern glibc, but an exotic code
  path could still need a syscall this doesn't stub correctly.
