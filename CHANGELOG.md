# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.5] - 2026-09-23

### Fixed

- A symbolic (module/offset) chain word's `label` still embedded the
  binary's own preferred-base address (e.g. `0x1400025c1: pop rcx ; ret`)
  even though `value` was already null'd for exactly that word --
  `to_json`, `to_pwntools`, and `stack_layout` all echo `label` verbatim,
  so the address `value`/`to_raw` are guarded against leaked right back
  out through the one field nothing was checking. Labels for a still-
  symbolic word now show the base-invariant `module+offset` instead (e.g.
  `Socks4Server_03+0x25c1: pop rcx ; ret`), matching the address only once
  a real base is actually known.

### Changed

- CLI output is now Rich tables throughout instead of a mix of tables and
  hand-formatted lines: `scan`/`search` render gadgets as a table (with a
  quality legend) instead of one `console.print` per line, `security`/
  `pivot`/`jop` share one rounded-box table style, and status lines go
  through new `_ok`/`_warn`/`_fail` helpers for a consistent ✓/⚠/✗ prefix.
  `call`'s stack-layout output is now a colorized table -- placeholder
  (red), symbolic (yellow), resolved (green), unfilled (dim) -- backed by
  two new reusable helpers in `core/output.py`, `word_kind` and
  `word_value_str`, so a value's status is visible at a glance instead of
  requiring a second look at the surrounding text. Verification output
  (`--verify`) now uses a `Rule` header and a bordered PASS/FAIL `Panel`.

## [0.3.4] - 2026-09-23

### Added

- `PLACEHOLDER` (`0xfeedfacecafebabe`, `ropnroll.solve.chain.PLACEHOLDER`): a
  reserved sentinel to pass as an `--args`/target value ropnroll has no way
  to compute itself -- most commonly a pointer relative to the payload's
  own stack position. Every `--emit` format now recognizes it instead of
  treating it as a real literal: `json` sets `"placeholder": true` and
  nulls `value`, `pwntools` annotates the line with `PLACEHOLDER --
  resolve outside ropnroll`, and `raw`/`c` refuse to export until it's
  been patched out, the same way they already refuse for an unresolved
  `module`/`offset` word.

## [0.3.3] - 2026-09-23

### Fixed

- `to_json`: an unresolved chain word (tagged `module`/`offset` because its
  runtime base isn't known yet) also carried a numeric `value` -- the
  binary's own linker-preferred-base address, which looks like a resolved
  runtime address but isn't one. A consumer resolving `module`+`offset`
  itself could read `value` instead and silently bake in the wrong
  address once ASLR actually relocated the module. `value` is now `null`
  whenever `module`/`offset` are set, matching `to_pwntools`'s existing
  behavior.

## [0.3.2] - 2026-09-23

### Added

- README: terminal-recording GIFs demonstrating the recon workflow
  (`security`/`scan`/`pivot`) and chain-building (`call --verify`),
  captured from real CLI output. `scripts/generate_demo_gif.py`
  regenerates them.

## [0.3.1] - 2026-09-23

### Fixed

- `call --bytes-before-chain`: the x86-64 stack-alignment padding check
  compared the target word's offset against the wrong residue, so it
  silently never inserted a padding gadget for the common case of N
  single-slot `pop reg ; ret` gadgets -- chains built this way could
  enter the target function at the wrong 16-byte parity and fault the
  moment it (or anything it calls) used an aligned SSE stack access. Also
  fixes a related bogus-offset bug for zero-argument calls, and a pad-
  gadget lookup that searched for a gadget shape the scanner never
  produces.

### Added

- A warning when `--bytes-before-chain` is omitted on x86-64, instead of
  silently shipping a chain whose alignment was never corrected either
  way.

## [0.3.0] - 2026-09-23

### Added

- `pattern create`/`pattern offset` commands: Metasploit
  pattern_create/pattern_offset-style cyclic pattern generation and
  crash-offset lookup, for triaging overflow offsets before hunting for
  gadgets.
- `--bad-chars`: exclude gadgets whose own address would introduce a bad
  byte into a payload, and flag any resolved chain word (call target,
  literal argument) that still contains one. Distinct from `--bad-bytes`,
  which filters a gadget's instruction encoding at its fixed location.
- `benchmarks/` script comparing ropnroll's gadget-finding speed against
  ROPgadget and ropper.
- Project license (GPL-3.0-or-later), `CONTRIBUTING.md`, `SECURITY.md`,
  and GitHub issue/PR templates.

### Changed

- Focused ropnroll exclusively on Windows PE targets; ELF/Mach-O loading
  has been removed.
- Sped up x86 gadget scanning and closed gaps in Windows JOP/CFG detection.

## [0.2.0] - 2026-09-22

### Added

- Persistent, on-disk gadget-effect cache keyed by binary content hash, so
  repeated `search`/`call` runs against the same target reuse prior analysis.
- A best-first (A*) chain solver that searches for a minimum-gadget chain
  instead of stopping at the first few shortest candidates.

## [0.1.1] - 2026-09-22

### Changed

- Improved README and PyPI project metadata.

## [0.1.0] - 2026-09-22

### Added

- Initial release: `scan`, `search`, `pivot`, `jop`, `call`, and `security`
  commands.
- Semantic gadget-effect inference via Unicorn emulation.
- Function-call chain synthesis against MS x64/cdecl/stdcall calling
  conventions, with chain verification via emulation.
- CI/publish workflow: test on push/PR, publish to PyPI via trusted
  publishing on `v*` tags.

[0.3.2]: https://github.com/jordanallred/ropnroll/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/jordanallred/ropnroll/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/jordanallred/ropnroll/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jordanallred/ropnroll/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jordanallred/ropnroll/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jordanallred/ropnroll/releases/tag/v0.1.0
