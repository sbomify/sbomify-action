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

1. **Pin the action to the commit SHA of a release tag** (e.g., `sbomify/sbomify-action@<full-commit-sha>  # vX`, using the full 40-character SHA that tag `vX` points to) rather than `@master` or a commit on master. Release tags after v26.10.2 point to a commit that pins the Docker image by digest; every commit on master runs `:latest`
2. **Use minimum required permissions** in your workflow `permissions:` block
3. **Store API tokens as GitHub secrets** — never hardcode them in workflow files
4. **Review SBOM outputs** before uploading to ensure no sensitive information is included

## Verifying the Docker Image

Each image published from master or a release carries a SLSA build provenance attestation and a keyless cosign signature, both made by this repository's `image-build.yml` workflow. Images published before these were added carry neither. To verify a version, or the digest that a release tag pins:

```bash
gh attestation verify oci://ghcr.io/sbomify/sbomify-action:<version> \
  --repo sbomify/sbomify-action --signer-workflow sbomify/sbomify-action/.github/workflows/image-build.yml
gh attestation verify oci://docker.io/sbomifyhub/sbomify-action:<version> \
  --repo sbomify/sbomify-action --signer-workflow sbomify/sbomify-action/.github/workflows/image-build.yml

cosign verify ghcr.io/sbomify/sbomify-action:<version> \
  --certificate-identity https://github.com/sbomify/sbomify-action/.github/workflows/image-build.yml@refs/heads/master \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

`image-build.yml` is a reusable workflow, so `gh` needs `--signer-workflow` to accept its attestation, and the flag also stops a signature from any other workflow in this repository from passing. The signature is stored as an OCI 1.1 referrer in cosign v3's bundle format, so verify it with cosign v3 or later; v2 looks for the legacy `.sig` tag and finds nothing. `cosign verify` works the same way for `docker.io/sbomifyhub/sbomify-action`. The image index also holds BuildKit's own provenance and an SBOM for each platform; to read them, run `docker buildx imagetools inspect <image> --format '{{json .Provenance}}'` (or `.SBOM`).
