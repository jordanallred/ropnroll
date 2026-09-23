# Contributing to ropnroll

Thanks for considering a contribution.

## Bug reports

Open an issue in [GitHub Issues](https://github.com/jordanallred/ropnroll/issues)
and include:

- The command you ran and its full output.
- Your Python and ropnroll versions (`python --version`, `ropnroll --version`).
- The target binary's architecture and file format.
- A minimal reproducer, if possible.

## Development setup

```powershell
git clone https://github.com/jordanallred/ropnroll.git
cd ropnroll
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
python -m pytest -q
```

Several tests scan `C:\Windows\System32\ntdll.dll` as a realistic, large PE
fixture; they skip automatically off Windows. The repository also includes
small, purpose-built PE fixtures under `tests/fixtures/pe/` for loader and
scanner tests that run on any platform.

## Submitting a pull request

- Keep changes focused; unrelated cleanup makes a PR harder to review.
- Include tests for behavior changes and make sure `python -m pytest -q`
  passes.
- Describe *why* the change is needed, not just what it does, in the PR
  description.

By submitting a pull request, you agree that your contribution will be
licensed under the project's [GPL-3.0-or-later license](LICENSE).
