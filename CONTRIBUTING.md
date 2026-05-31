# Contributing to AgentHusk

AgentHusk is intentionally small: a local-first scanner for risky residue in AI coding-agent storage. It does not intentionally modify scanned source artifacts; it writes requested local reports. Contributions should preserve that boundary.

## Setup

Requires Node.js 20 or later.

```sh
git clone <your-fork-url>
cd agenthusk
npm test
npm run check
node src/cli.js demo
```

To exercise a real scan, run:

```sh
node src/cli.js scan
```

Inspect generated reports locally. Do not attach reports to public issues without reviewing and redacting their metadata.

## Before opening a pull request

- Keep scans read-only against agent storage.
- Treat `0600` artifact modes as POSIX hardening, not Windows ACL enforcement.
- Do not add network calls, uploads, or telemetry to the scanning path.
- Never add a real credential to source, tests, fixtures, issues, or pull-request descriptions.
- Use synthetic values that are obviously non-production when testing detection rules.
- Add tests for detection changes and for redaction behavior.
- Document user-visible changes and new scan roots.
- Run `npm test` and `npm run check`.

## Detection-rule changes

A useful rule catches meaningful residue without making reports noisy. For each rule change:

1. Add a synthetic positive case.
2. Add a nearby negative or placeholder case.
3. Verify that reports contain a fingerprint but not the matched source value.
4. Note likely false positives and false negatives in the pull request.

Do not broaden a regular expression only to improve demo output. Prefer a narrow, explainable rule.

## Agent adapters

Support for an agent currently starts with a known local storage root. When adding one:

1. Document the directory and the platform assumptions.
2. Keep traversal bounded and avoid following symlinks.
3. Avoid parsing or executing agent-provided commands.
4. Add synthetic fixtures for agent-specific residue when needed.
5. Update the supported-agent table in `README.md`.

Plugin-specific adapters are planned; see `docs/ROADMAP.md`.

## Security reports

For suspected vulnerabilities, follow `SECURITY.md`. Do not disclose sensitive details in a public issue.

## Pull requests

Keep pull requests focused. Explain the user-visible behavior, security implications, tests run, and remaining limitations. A clean scan is never a claim that a machine is safe, so avoid language that implies complete coverage or prevention.
