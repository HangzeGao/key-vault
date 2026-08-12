# Project working rules

- This system has not entered production. Do not preserve backward compatibility unless the user explicitly requests it.
- For every implementation change, inspect the affected path for obsolete compatibility branches, duplicate abstractions, deprecated formats, and unused feature switches. Remove them when the current design makes them unnecessary.
- Prefer one strict current contract and fail closed instead of accepting legacy empty values or silently translating obsolete representations.

## Mandatory delivery workflow

- Every task that changes code must end with one focused Git commit after the relevant verification passes. Do not leave completed code changes uncommitted, do not combine unrelated work in the same commit, and never stage unrelated user files.
- Before committing, inspect `git status` and the staged diff, run `git diff --check`, and report the verification performed. Documentation-only changes requested as a durable project rule must also be committed.
- After each commit, count commits on the current branch that are ahead of its upstream with `git rev-list --count @{upstream}..HEAD`. Push the current branch when that count reaches 5 or more. A successful push resets this delivery counter because the upstream catches up. If no upstream exists, publish the branch on the fifth local commit. Do not wait for a sixth commit.
- Never push a change that has not passed its required verification. If the fifth commit cannot safely be pushed because verification, credentials, network access, or remote checks fail, keep the commit, report the blocker explicitly, and retry the push as the first delivery action once the blocker is removed.

## Large-change regression and hardening gate

- Treat a change as large when it modifies 10 or more implementation/test files, changes 500 or more implementation lines, crosses two or more runtime boundaries, or changes cryptography, protocol framing, key lifecycle, persistence/schema, replay/state transitions, authentication/authorization, audit, or recovery behavior. Security-critical changes are large regardless of line count.
- Before committing a large change, run the repository's complete regression gate (`make release-gate` when available), not only focused unit tests. The gate must include all language test suites, the 95% coverage requirements, frontend tests/build when affected, and the ground-to-flight end-to-end vectors when TC behavior is affected.
- Add or update hardening tests proportional to the change: invalid and boundary inputs, fail-closed behavior, rollback/replay/state corruption, interrupted persistence, authorization failures, secret non-disclosure and zeroization, as applicable. A passing old test suite alone is not sufficient evidence for new security-sensitive behavior.
- Use the configured remote integration environment for tests that cannot be reproduced locally or that depend on its toolchain/runtime. Record the final gate result and coverage in the handoff. Do not weaken, skip, or exclude a failing gate merely to create a commit or reach the push threshold.
