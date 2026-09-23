# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.3.0]: https://github.com/jordanallred/ropnroll/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jordanallred/ropnroll/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jordanallred/ropnroll/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jordanallred/ropnroll/releases/tag/v0.1.0
