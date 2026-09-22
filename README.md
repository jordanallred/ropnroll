# ropnroll

ropnroll is a command-line tool and Python library for finding return-oriented
programming (ROP) and jump-oriented programming (JOP) gadgets in binaries. It
supports instruction-pattern and semantic searches, builds function-call and
syscall chains, and can check generated chains with Unicorn emulation.

Use it to inspect binary mitigations, find gadgets with specific register effects,
and assemble chains for exploit-development research and CTF challenges.

## Why ropnroll

Most gadget tools infer a gadget's effect from a hand-written instruction model.
ropnroll instead *measures* it: every gadget runs for real on an emulated CPU
(Unicorn) with several input vectors, and a closed-form relation (constant,
copy, affine, bitwise) is fit to the outputs. If a relation fits every trial,
it's exact, not a guess -- and it's correct by construction for every
architecture Unicorn supports, including quirks a hand-rolled model would miss.

Chain synthesis uses a best-first (A*) search over candidate gadgets rather
than a fixed-width traversal, so it isn't limited to only the first few
shortest candidates at each step -- within its depth and work bounds, it finds
a minimum-gadget chain instead of giving up on one that a narrower search would
miss. Repeated analysis of the same binary (the normal workflow while building
an exploit) is backed by a persistent on-disk cache, so the second and later
`search`/`call`/`syscall` invocation against the same target is fast; see
`--no-cache` and `ROPNROLL_CACHE_DIR` below if you need to bypass or relocate it.

## Installation

Requires **Python 3.10 or newer**. Install from PyPI in a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install ropnroll
ropnroll --help
```

On Windows, activate the environment with `.venv\Scripts\Activate.ps1` in
PowerShell. Capstone, LIEF, Unicorn, and Rich are installed automatically.

If you use uv, you can run the CLI without a persistent installation:

```bash
uvx ropnroll --help
```

## Quick start

Replace `./target` with the path to a binary you want to inspect.

```bash
# Report binary mitigations, such as NX, PIE, and RELRO.
ropnroll security ./target

# List up to 20 gadgets.
ropnroll scan ./target --limit 20

# Find x86-64 gadgets by instruction text.
ropnroll scan ./target --regex 'pop rdi'

# Find x86-64 gadgets by their effect on registers.
ropnroll search ./target --query 'rdi=rax+8'
```

`scan` prints gadget addresses and disassembly. `search` uses emulation to infer
register effects; the query above asks for a gadget that sets `rdi` to `rax + 8`.
Matches depend on the instructions available in your binary.

Run `ropnroll <command> --help` for command options.

## Commands

| Command | Purpose |
| --- | --- |
| `security` | Report binary mitigations. |
| `scan` | List gadgets, optionally filtered by an instruction regex. |
| `search` | Search for register or memory effects using semantic queries. |
| `pivot` | Find stack-pivot gadgets. |
| `jop` | Find JOP dispatcher gadgets. |
| `call` | Build a chain that calls a function by symbol or address. |
| `syscall` | Build a chain for a syscall number and arguments. |
| `srop` | Build a Linux x86-64 sigreturn-oriented `execve` chain. |
| `onegadget` | Search for execution paths that reach `execve` in emulation. |
| `libcid` | Identify a libc build using symbol offsets via libc.rip. |

### Build and export a chain

For a binary that contains the `exit` symbol and suitable gadgets:

```bash
ropnroll call ./target --target exit --args 0 --verify --emit json --out chain.json
```

`--target` accepts a symbol name or numeric address. `--args` accepts
comma-separated integers. `--verify` prints an emulation report; inspect that
report before using the output. Export formats are `json`, `raw`, `c`, and
`pwntools`. Use `--out` to save a payload separately from console diagnostics.

You can pool gadgets from multiple binaries:

```bash
ropnroll search ./target ./libc.so.6 --query 'rdi=rax+8'
```

`call`, `syscall`, `srop`, `pivot`, and `jop` also accept multiple paths.
Addresses come from the loaded images; the CLI does not automatically discover
a running process's ASLR bases. Pointer arguments must refer to valid memory in
the intended target. The Python API provides live-process loading through
`ropnroll.orchestrate` on Linux.

### Identify libc

Supply offsets relative to libc's base, rather than absolute runtime addresses:

```bash
ropnroll libcid --symbol system=0x58750 --symbol read=0x11bd20
```

These are illustrative offsets; replace them with values from your libc.
This command requires internet access and sends the supplied symbol offsets to
libc.rip. Add `--download ./libc.so.6` to download the first matching build.

### Caching

Semantic effects (the expensive part -- several Unicorn runs per gadget) are
cached on disk per binary, keyed by its content hash, so repeated commands
against the same target reuse prior analysis instead of redoing it. Pass
`--no-cache` to any command to bypass the cache for that run. The cache lives
under `~/.cache/ropnroll` on Linux/macOS or `%LOCALAPPDATA%\ropnroll` on
Windows by default; set `ROPNROLL_CACHE_DIR` to relocate it.

## Supported targets and limitations

| Target | Scope |
| --- | --- |
| Linux x86-64 ELF | Primary target for scanning, semantic analysis, chain building, and verification. |
| Windows x86 / x86-64 PE | Loading, mitigation reporting, and scanning; calling-convention support is implemented. |
| x86 ELF (32-bit) | Scanner support; end-to-end chain coverage is limited. |
| ARM32, ARM64, MIPS32, MIPS64 | Scanner and semantic-engine implementations; not covered by real-binary architecture tests. |
| RISC-V, PowerPC, Thumb | Unsupported. |

- SROP is limited to Linux x86-64. Its verifier simulates sigreturn semantics.
- `onegadget` is limited to x86/x86-64 and uses syscall stubs, not a full OS.
- Semantic effects are inferred from a finite set of emulation trials, not
  formally proved for every possible input.
- Chain search (a best-first/A* search over candidate gadgets) has depth and
  work limits; within those bounds it finds a minimum-gadget chain if one
  exists, but a gadget-poor pool can still exhaust the budget without one.
- Chain verification uses the first supplied image; it does not fully validate
  chains spanning multiple images or guarantee success in a live process.

## Development

```bash
git clone https://github.com/jordanallred/ropnroll.git
cd ropnroll
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
```

For the Linux integration tests, use an x86-64 Linux environment with GCC and
system libc available. Tests that require missing fixtures or tools may skip.
The repository also includes Windows PE fixtures for loader and scanner tests.

The [live-process example](https://github.com/jordanallred/ropnroll/blob/main/examples/live_fire_demo.py)
shows how to build and deliver a chain against the included vulnerable test
program. It requires Linux x86-64, GCC, pwntools (`python -m pip install
pwntools`), and access to `/proc/<pid>/maps`.

## Help and contributions

Report bugs or suggest improvements in
[GitHub Issues](https://github.com/jordanallred/ropnroll/issues).
For bug reports, include the command, full error output, Python and ropnroll
versions, and the target's architecture and file format. Include a minimal
reproducer when possible.

Pull requests are welcome. Include relevant tests for behavior changes and run
the test suite before submitting.
