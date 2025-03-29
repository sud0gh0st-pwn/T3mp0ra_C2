# Security Policy

## Supported Versions

Since Tempora is a security-focused C2 framework, we take security vulnerabilities very seriously. Below are the versions currently receiving security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.2.x   | :white_check_mark: |
| 1.1.x   | :white_check_mark: |
| 1.0.x   | :x:                |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We appreciate your efforts to responsibly disclose your findings and will make every effort to acknowledge your contributions.

### How to Report

Please report security vulnerabilities by emailing us at:
**[security@yourprojectdomain.com](mailto:security@yourprojectdomain.com)**

Please include the following information:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact of the vulnerability
- Any suggested mitigation or remediation steps
- Your name/handle for acknowledgment (optional)

### What to Expect

- **Initial Response**: We aim to acknowledge receipt of your vulnerability report within 48 hours.
- **Status Updates**: We will keep you informed about the progress towards fixing the vulnerability.
- **Disclosure Timeline**: We follow a 90-day disclosure timeline, providing sufficient time to address the vulnerability before any public disclosure.

### Handling Process

1. **Confirmation**: Our security team will verify the vulnerability and determine its impact.
2. **Remediation**: We will develop and test a fix for the vulnerability.
3. **Release**: A security update will be released for all supported versions.
4. **Acknowledgment**: With your permission, we will acknowledge your contribution in the release notes.

### Bug Bounty

At this time, we do not offer a bug bounty program. However, we do publicly acknowledge security researchers who report valid vulnerabilities if they wish to be credited.

## Security Features and Considerations

Since Tempora is designed for secure communications, here are some important security considerations:

- All communications are encrypted using RSA for key exchange and Fernet for symmetric encryption
- Message integrity is verified using HMAC
- Comprehensive logging is enabled by default to help detect potential security incidents
- We recommend running the C2 server on a secure, isolated system
- All client-server communications should be over encrypted channels

## Ethical Usage

Tempora is designed for educational and authorized security testing purposes only. Usage of Tempora for attacking targets without prior mutual consent is illegal and prohibited.

## Security Updates

Security advisories will be published via:
- GitHub Security Advisories
- Release notes
- Our official Twitter account: [@TemporaC2](https://twitter.com/temporac2)

---

Thank you for helping keep Tempora and its users safe!
