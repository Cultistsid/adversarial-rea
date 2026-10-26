# Test Fixtures

Sample inputs used by the test suite so tests run without depending on arbitrary
files on the host.

## Files

- `sample-macho` — a real Mach-O binary (a copy of `/bin/ls`) used by integration
  tests to exercise `BinaryAnalyzer` against actual system tools (`nm`, `otool`,
  `strings`, `file`). It is a known-good, non-stripped-ish system binary, which
  gives tests predictable symbols, strings, and security metadata to assert on.

## Notes

- Unit tests should prefer the mock in `test/helpers/mock-analyzer.js` and avoid
  touching these fixtures, so they stay fast and host-independent.
- Integration tests may skip themselves when the required system tools are not
  present (e.g. `otool` is macOS-only).
