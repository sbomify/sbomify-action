ARG UV_VERSION=0.10.8

# Define tool versions
ARG SYFT_VERSION=1.46.0
ARG CARGO_CYCLONEDX_VERSION=0.5.9

FROM python:3.14-slim-trixie AS fetcher

# Use Docker's automatic platform detection
ARG TARGETARCH

# Re-declare global ARGs needed in this stage
ARG SYFT_VERSION

WORKDIR /tmp


RUN apt-get update && \
    apt-get install -y curl unzip

# NOTE: Trivy installation removed - temporarily disabled due to security vulnerabilities

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
FROM python:3.14-slim-trixie AS builder

ARG VERSION=0.0.0

# Install build dependencies
RUN apt-get update && \
    apt-get install -y build-essential libxml2-dev libxslt-dev

# pipdeptree is a meson/cargo package from 4.0.0 on and publishes no linux
# aarch64 wheels, so on arm64 uv builds it from the sdist and needs a Rust
# toolchain. Reuse the pinned one from rust-builder rather than pulling a
# second (and differently versioned) toolchain from apt.
# Only bin/ is copied: on arm64 rust-builder runs `cargo install`, so
# CARGO_HOME also holds registry/git crate caches that are useless here.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo
ENV PATH="/usr/local/cargo/bin:$PATH"
COPY --from=rust-builder /usr/local/rustup /usr/local/rustup
COPY --from=rust-builder /usr/local/cargo/bin /usr/local/cargo/bin

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
# Use --no-dev because uv syncs the `dev` dependency-group by default, which
# shipped mypy, pytest, pre-commit, coverage and ruff into the published image
# (218MB -> 91MB for /opt/venv). Nothing in the runtime path imports them.
RUN uv sync --frozen --active --no-dev
# Resolve tools/go.mod and tools/Cargo.lock into literal versions before the
# wheel is built. The lockfiles are not part of the package and the runtime
# image has no Go or Cargo toolchain, so the release must carry the versions
# it was built against -- see scripts/freeze_tool_versions.py.
RUN python scripts/freeze_tool_versions.py && python scripts/freeze_tool_versions.py --check
RUN rm -rf dist/ && uv build
RUN uv pip install dist/sbomify_action-*.whl

# Final stage
FROM python:3.14-slim-trixie

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

# git is needed at runtime: the wizard reads repo facts (remote name,
# branch, visibility) from the bind-mounted workspace, and slim images
# don't ship it. Without it those facts silently degrade to folder-name
# and "unknown" visibility.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Note: Java/Maven is installed on-demand at runtime when processing Java/Scala projects
# This reduces the base image size by ~330MB for non-Java workloads

# Copy tools from fetcher
COPY --from=fetcher /usr/local/bin/syft /usr/local/bin/
# cargo-cyclonedx: pre-built for amd64, compiled for arm64
COPY --from=rust-builder /usr/local/cargo/bin/cargo-cyclonedx /usr/local/bin/
COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

# Initialize Conan profile for C/C++ package metadata lookups
# This creates a default profile based on the container's compiler/OS settings
RUN conan profile detect --force

# Marks our own image. Runtime tools are fetched on demand only in here,
# where we decide what the toolchain is. A pip install keeps whatever the
# user has: silently downloading cdxgen there would change which generator
# wins and quietly alter the SBOM they get.
ENV SBOMIFY_IN_CONTAINER=1

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Advertise 24-bit colour so the Textual wizard renders the sbomify brand
# palette correctly. `docker run -it` allocates a TTY with TERM=xterm and
# never sets COLORTERM, so Rich/Textual would otherwise detect only the
# 16-colour "standard" system and downsample the brand hex colours
# (#141035, #8A7DFF, …) to muddy ANSI greys. COLORTERM is the deciding
# lever: Docker never sets it implicitly, so this image value is the
# effective default (a runtime `-e COLORTERM=…` still overrides it).
ENV COLORTERM=truecolor

# Runtime version information (from build args)
ENV SBOMIFY_GITHUB_ACTION_VERSION=${VERSION}
ENV SBOMIFY_GITHUB_ACTION_COMMIT_SHA=${COMMIT_SHA}
ENV SBOMIFY_GITHUB_ACTION_VCS_REF=${VCS_REF}

# nosemgrep: missing-user  # GitHub Action container must run as root to access the mounted workspace
CMD ["sbomify-action"]
