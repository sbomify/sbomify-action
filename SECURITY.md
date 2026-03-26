# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in sbomify-action, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please send an email to **security@sbomify.com** with:

- A description of the vulnerability
- Steps to reproduce the issue
- Any potential impact assessment
- Suggested fix (if you have one)

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Scope

This security policy covers:

- The sbomify-action GitHub Action
- The sbomify-action CLI tool (published to PyPI)
- The sbomify-action Docker image
- CI/CD workflow configurations in this repository

## Security Best Practices for Users

When using sbomify-action in your workflows:

1. **Pin the action to a specific commit SHA** (e.g., `sbomify/sbomify-action@b67da9dc77fba8b8a1107b427b746e99f92fdcb2`) rather than `@master`
2. **Use minimum required permissions** in your workflow `permissions:` block
3. **Store API tokens as GitHub secrets** — never hardcode them in workflow files
4. **Review SBOM outputs** before uploading to ensure no sensitive information is included
