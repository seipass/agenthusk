## Summary

Describe the user-visible change.

## Security boundary

- [ ] Scanned source artifacts are not intentionally modified.
- [ ] The scanning path adds no external API call, upload, or telemetry.
- [ ] New output fields have matched-value and path-redaction coverage.
- [ ] Synthetic fixtures contain no real credential, report, or sensitive path.

## Verification

- [ ] `npm test`
- [ ] `npm run check`
- [ ] `npm run demo`
- [ ] `npm run smoke:pack`

## Remaining limitations

List false positives, false negatives, platform assumptions, and coverage gaps.
