ARG UV_VERSION=0.10.8
ARG BUN_VERSION=1.3.10

# Define tool versions
ARG BOMCTL_VERSION=0.4.3
ARG SYFT_VERSION=1.42.3
ARG CARGO_CYCLONEDX_VERSION=0.5.9
ARG CRANE_VERSION=0.21.5
ARG COSIGN_VERSION=3.0.6

FROM python:3.13-slim-trixie AS fetcher

# Use Docker's automatic platform detection
ARG TARGETARCH

# Re-declare global ARGs needed in this stage
ARG BOMCTL_VERSION
ARG SYFT_VERSION
ARG CRANE_VERSION
ARG COSIGN_VERSION

WORKDIR /tmp


RUN apt-get update && \
    apt-get install -y curl unzip

# NOTE: Trivy installation removed - temporarily disabled due to security vulnerabilities

# Install bomctl (uses linux_amd64 / linux_arm64 naming)
RUN curl -sL \
        -o bomctl_${BOMCTL_VERSION}_linux_${TARGETARCH}.tar.gz \
        "https://github.com/bomctl/bomctl/releases/download/v${BOMCTL_VERSION}/bomctl_${BOMCTL_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    curl -sL \
        -o bomctl_checksum.txt \
        "https://github.com/bomctl/bomctl/releases/download/v${BOMCTL_VERSION}/bomctl_${BOMCTL_VERSION}_checksums.txt" && \
    sha256sum --ignore-missing -c bomctl_checksum.txt && \
    tar xvfz bomctl_${BOMCTL_VERSION}_linux_${TARGETARCH}.tar.gz && \
    chmod +x /tmp/bomctl && \
    mv bomctl /usr/local/bin && \
    rm -rf /tmp/*

# Install Syft (uses linux_amd64 / linux_arm64 naming)
RUN curl -sL \
        -o syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz \
        "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" && \
    curl -sL \
        -o syft_checksum.txt \
        "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_checksums.txt" && \
    sha256sum --ignore-missing -c syft_checksum.txt && \
    tar xvfz syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz && \
    chmod +x /tmp/syft && \
    mv syft /usr/local/bin && \
    rm -rf /tmp/*

# Install crane (uses Linux_x86_64 / Linux_arm64 naming)
RUN CRANE_ARCH=$([ "${TARGETARCH}" = "amd64" ] && echo "x86_64" || echo "${TARGETARCH}") && \
    curl -fsSL \
        -o go-containerregistry_Linux_${CRANE_ARCH}.tar.gz \
        "https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/go-containerregistry_Linux_${CRANE_ARCH}.tar.gz" && \
    curl -fsSL \
        -o crane_checksums.txt \
        "https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/checksums.txt" && \
    sha256sum --ignore-missing -c crane_checksums.txt && \
    tar xvfz go-containerregistry_Linux_${CRANE_ARCH}.tar.gz crane && \
    chmod +x /tmp/crane && \
    mv crane /usr/local/bin && \
    rm -rf /tmp/*

# Install cosign (uses linux-amd64 / linux-arm64 naming)
RUN curl -fsSL \
        -o cosign-linux-${TARGETARCH} \
        "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${TARGETARCH}" && \
    curl -fsSL \
        -o cosign_checksums.txt \
        "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign_checksums.txt" && \
    sha256sum --ignore-missing -c cosign_checksums.txt && \
    chmod +x cosign-linux-${TARGETARCH} && \
    mv cosign-linux-${TARGETARCH} /usr/local/bin/cosign && \
    rm -rf /tmp/*

# Node/Bun stage for cdxgen
FROM oven/bun:${BUN_VERSION}-debian@sha256:367842b35abbdf23f39e23c71f3a08eee940ff2679a14e08a5afcf4a1436cd89 AS node-fetcher

WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# cargo-cyclonedx builder stage
# Downloads pre-built binary for amd64, compiles from source for arm64
FROM rust:1-slim AS rust-builder

ARG TARGETARCH
ARG CARGO_CYCLONEDX_VERSION

RUN apt-get update && apt-get install -y curl xz-utils && \
    if [ "${TARGETARCH}" = "amd64" ]; then \
        curl -sL \
            -o cargo-cyclonedx-x86_64-unknown-linux-gnu.tar.xz \
            "https://github.com/CycloneDX/cyclonedx-rust-cargo/releases/download/cargo-cyclonedx-${CARGO_CYCLONEDX_VERSION}/cargo-cyclonedx-x86_64-unknown-linux-gnu.tar.xz" && \
        curl -sL \
            -o cargo-cyclonedx-x86_64-unknown-linux-gnu.tar.xz.sha256 \
            "https://github.com/CycloneDX/cyclonedx-rust-cargo/releases/download/cargo-cyclonedx-${CARGO_CYCLONEDX_VERSION}/cargo-cyclonedx-x86_64-unknown-linux-gnu.tar.xz.sha256" && \
        sha256sum -c cargo-cyclonedx-x86_64-unknown-linux-gnu.tar.xz.sha256 && \
        tar xvf cargo-cyclonedx-x86_64-unknown-linux-gnu.tar.xz && \
        mv cargo-cyclonedx-x86_64-unknown-linux-gnu/cargo-cyclonedx /usr/local/cargo/bin/ && \
        chmod +x /usr/local/cargo/bin/cargo-cyclonedx; \
    else \
        cargo install cargo-cyclonedx@${CARGO_CYCLONEDX_VERSION}; \
    fi

# UV binary stage
FROM ghcr.io/astral-sh/uv:${UV_VERSION}@sha256:88234bc9e09c2b2f6d176a3daf411419eb0370d450a08129257410de9cfafd2a AS uv-fetcher

# Python builder stage
FROM python:3.13-slim-trixie AS builder

ARG VERSION=0.0.0

# Install build dependencies
RUN apt-get update && \
    apt-get install -y build-essential libxml2-dev libxslt-dev

COPY --from=uv-fetcher /uv /uvx /usr/local/bin/

WORKDIR /app
COPY . /app/

# Override version from build arg
RUN sed -i "s/^version = [\"'].*/version = \"${VERSION}\"/" pyproject.toml

# Build and install using UV
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN uv venv /opt/venv
# Use --active so uv installs into the existing VIRTUAL_ENV (/opt/venv) instead of .venv
# Use --frozen to avoid lockfile validation after version override
RUN uv sync --frozen --active
RUN rm -rf dist/ && uv build
RUN uv pip install dist/sbomify_action-*.whl

# Final stage
FROM python:3.13-slim-trixie

# Build arguments for dynamic labels (passed at build time)
ARG VERSION=0.0.0
ARG COMMIT_SHA=unknown
ARG BUILD_DATE=unknown
ARG VCS_REF=unknown

# OCI Image Labels (https://github.com/opencontainers/image-spec/blob/main/annotations.md)
LABEL org.opencontainers.image.title="sbomify action" \
      org.opencontainers.image.description="Generate, enrich, and manage Software Bill of Materials (SBOM) for your projects" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${COMMIT_SHA}" \
      org.opencontainers.image.ref.name="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/sbomify/sbomify-action" \
      org.opencontainers.image.url="https://sbomify.com" \
      org.opencontainers.image.documentation="https://github.com/sbomify/sbomify-action#readme" \
      org.opencontainers.image.vendor="sbomify" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="sbomify <hello@sbomify.com>" \
      org.opencontainers.image.base.name="python:3.13-slim-trixie"

# Additional metadata labels
LABEL com.sbomify.maintainer="sbomify <hello@sbomify.com>" \
      com.sbomify.company="sbomify" \
      com.sbomify.company.url="https://sbomify.com" \
      com.sbomify.vcs.type="git" \
      com.sbomify.vcs.url="https://github.com/sbomify/sbomify-action.git" \
      com.sbomify.vcs.branch="${VCS_REF}" \
      com.sbomify.vcs.commit="${COMMIT_SHA}"

# Note: Java/Maven is installed on-demand at runtime when processing Java/Scala projects
# This reduces the base image size by ~330MB for non-Java workloads

# Copy tools from fetcher
COPY --from=fetcher /usr/local/bin/bomctl /usr/local/bin/
COPY --from=fetcher /usr/local/bin/syft /usr/local/bin/
COPY --from=fetcher /usr/local/bin/crane /usr/local/bin/
COPY --from=fetcher /usr/local/bin/cosign /usr/local/bin/
# cargo-cyclonedx: pre-built for amd64, compiled for arm64
COPY --from=rust-builder /usr/local/cargo/bin/cargo-cyclonedx /usr/local/bin/
COPY --from=node-fetcher /usr/local/bin/bun /usr/local/bin/
COPY --from=node-fetcher /app/node_modules /app/node_modules
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/app/node_modules/.bin:/opt/venv/bin:$PATH"

# Make 'node' and 'npm' invoke 'bun' so tools that expect them actually run bun (compatibility shim)
RUN ln -s /usr/local/bin/bun /usr/local/bin/node && \
    ln -s /usr/local/bin/bun /usr/local/bin/npm

# Initialize Conan profile for C/C++ package metadata lookups
# This creates a default profile based on the container's compiler/OS settings
RUN conan profile detect --force

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Runtime version information (from build args)
ENV SBOMIFY_GITHUB_ACTION_VERSION=${VERSION}
ENV SBOMIFY_GITHUB_ACTION_COMMIT_SHA=${COMMIT_SHA}
ENV SBOMIFY_GITHUB_ACTION_VCS_REF=${VCS_REF}

CMD ["sbomify-action"]
