# Security Policy

ropnroll is an offensive-security tool for finding ROP/JOP gadgets and
building exploit chains against Windows PE binaries you already have
permission to test. This policy covers vulnerabilities *in ropnroll itself*
(the tool, its dependencies as pinned, and its build/publish pipeline) — not
the security of binaries you analyze with it.

## Supported versions

Only the latest release on PyPI is supported. Please upgrade before
reporting an issue.

## Reporting a vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Instead, report privately via [GitHub Security Advisories](https://github.com/jordanallred/ropnroll/security/advisories/new)
or by emailing jallredxc@gmail.com. Include:

- A description of the vulnerability and its impact.
- Steps to reproduce, including affected version and platform.
- Any proof-of-concept code, if applicable.

We aim to acknowledge reports within 5 business days and to release a fix
or mitigation as soon as reasonably possible, coordinating disclosure timing
with the reporter.
