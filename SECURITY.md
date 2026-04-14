# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability privately:
- GitHub Security Advisories: repository → Security tab → "Report a vulnerability"

Response timeline:
- Initial response within 7 days
- Fix or mitigation plan shared within 30 days
- Credit given to the reporter upon release (if desired)

## Scope

This library parses untrusted `.ar1cs` binary files. Areas of particular interest:

- Memory safety or parser bugs in `ArcsFile::read`
- Checksum verification bypass
- Safety contract violations in the public API
