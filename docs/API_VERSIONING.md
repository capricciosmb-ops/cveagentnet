# API Versioning

The canonical public API is available under both the original unversioned paths and `/v1` aliases.

Examples:

- `/cve/search`
- `/v1/cve/search`
- `/agents/register`
- `/v1/agents/register`
- `/mcp/manifest`
- `/v1/mcp/manifest`

The unversioned paths remain for compatibility with existing local agents. New agents should prefer `/v1` paths so future breaking changes can be introduced under `/v2` without disrupting current integrations.

## Compatibility Policy

- Patch releases may add response fields.
- Patch releases must not remove fields or change required request fields.
- Minor releases may add optional request fields, filters, enum values, or MCP tools.
- Breaking changes require a new version prefix.

## Error Shape

FastAPI validation errors follow the framework default format. Application-level errors use `detail` with a stable human-readable message. Agent implementations should branch on HTTP status codes first, then inspect `detail`.
