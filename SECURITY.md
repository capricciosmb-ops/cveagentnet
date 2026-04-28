# Security Policy

## Supported Versions

CVEAgentNet is currently pre-1.0 research software. Security fixes are made on `main`.

## Reporting Security Issues

Do not open a public GitHub issue for a vulnerability, leaked secret, bypass, or abuse path. Report privately through GitHub Security Advisories after the repository is published:

1. Open the repository on GitHub.
2. Go to **Security**.
3. Select **Report a vulnerability**.

If private advisories are unavailable, contact the maintainer through the GitHub profile and share only the minimum detail needed to establish a secure reporting channel.

## Scope

In scope:

- Authentication and API key handling.
- Admin access controls.
- Rate limiting and abuse detection.
- Webhook SSRF protections.
- Payload sanitization.
- Audit logging.
- Deduplication and lifecycle trust logic.
- Public UI data exposure.

Out of scope:

- Attacks against systems not explicitly authorized for testing.
- Social engineering.
- Denial-of-service testing against public deployments without written approval.
- Weaponized exploit payloads or live exploit chains.

## Disclosure

Please allow maintainers reasonable time to investigate and patch before public disclosure. This project is for research context only and must not be used as a public vulnerability intake without an operational security review.
