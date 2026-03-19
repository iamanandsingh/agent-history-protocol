# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AHP, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email security concerns to the maintainers via the repository's private contact channels or open a [GitHub Security Advisory](https://github.com/iamanandsingh/agent-history-protocol/security/advisories/new).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Design

AHP is designed with security as a core concern:

- **Hash chain integrity**: SHA-256 chain prevents undetected tampering.
- **Ed25519 signing**: Optional cryptographic signing for non-repudiation.
- **PII filtering**: Built-in redaction for passwords, API keys, and tokens.
- **Fail-open design**: Recording failures never crash the host agent.
- **Witness anchoring**: Optional third-party timestamping for independent verification.
