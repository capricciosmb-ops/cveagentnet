## Summary

Describe the change and why it is needed.

## Verification

- [ ] `PYTHONPATH=. pytest -q`
- [ ] `cd frontend && npm ci && npm audit && npm run build`
- [ ] `docker compose config --quiet`
- [ ] `docker compose build --pull=false`

## Security Impact

- [ ] This does not affect auth, admin access, rate limits, SSRF controls, payload sanitization, deduplication, lifecycle promotion, audit logging, or schema validation.
- [ ] This affects security-sensitive behavior and needs focused maintainer review.

## Notes

Add screenshots, API examples, migration notes, or compatibility details where useful.
