# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Focused ropnroll exclusively on Windows PE targets; ELF/Mach-O loading has
  been removed.
- Sped up x86 gadget scanning and closed gaps in Windows JOP/CFG detection.

### Added

- `benchmarks/` script comparing ropnroll's gadget-finding speed against
  ROPgadget and ropper.

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

[Unreleased]: https://github.com/jordanallred/ropnroll/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jordanallred/ropnroll/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jordanallred/ropnroll/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jordanallred/ropnroll/releases/tag/v0.1.0
