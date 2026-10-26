# Test Fixtures

Sample inputs used by the test suite so tests run without depending on arbitrary
files on the host.

## Files

- `sample-macho` — a real Mach-O binary (a copy of `/bin/ls`) retained as a
  sample. Current live-binary integration tests inspect the host `/bin/ls`.
- `flow-direct.flow.json`, `flow-constant.flow.json`, `flow-guarded.flow.json`,
  `flow-rejected.flow.json` — bounded declarative in-memory replay cases. No
  fixture is executed as a native program or used to verify a vulnerability.

## Notes

- Unit tests should prefer the mock in `test/helpers/mock-analyzer.js` and avoid
  touching these fixtures, so they stay fast and host-independent.
- Current live-binary integration tests require a macOS `/bin/ls` and the
  relevant host inspection tools; fixture-only unit tests do not.
