ARG UV_VERSION=0.12.5


# UV binary stage
FROM ghcr.io/astral-sh/uv:${UV_VERSION}@sha256:e85be844203885286c60ffad8a858d48afb6c5a5c237ca0e67f12e74b8f174b1 AS uv-fetcher

# Python builder stage
FROM python:3.14-slim-trixie AS builder

ARG VERSION=0.0.0

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
# Resolve uv.lock and the JVM plugin manifests into literal versions before
# the wheel is built. Those files are not part of the package, so a release
# must carry the versions it was built against rather than expecting to read
# them later -- see scripts/freeze_tool_versions.py.
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
      org.opencontainers.image.base.name="python:3.14-slim-trixie"

# Additional metadata labels
LABEL com.sbomify.maintainer="sbomify <hello@sbomify.com>" \
      com.sbomify.company="sbomify" \
      com.sbomify.company.url="https://sbomify.com" \
      com.sbomify.vcs.type="git" \
      com.sbomify.vcs.url="https://github.com/sbomify/sbomify-action.git" \
      com.sbomify.vcs.branch="${VCS_REF}" \
      com.sbomify.vcs.commit="${COMMIT_SHA}"

# git is needed at runtime and is deliberately baked in rather than fetched
# like the generators are. Nearly every path wants it: the wizard reads repo
# facts (remote name, branch, visibility) from the bind-mounted workspace,
# submodule resolution runs it directly, and run_command threads
# git_safe_directory_env() into *every* subprocess because the generators
# shell out to tools that run git themselves -- composer establishing its
# root package version, cargo, go. Slim images don't ship it, and without it
# those facts silently degrade to folder-name and "unknown" visibility.
#
# So this is the one dependency that should never be lazy-loaded: a tool
# needed by almost every run is not a tool to go and fetch mid-run.
# dist-upgrade first: the base image digest lags the Debian security
# archive, so packages preinstalled in the base (util-linux, openssl)
# would otherwise ship at whatever patch level the digest froze.
RUN apt-get update && \
    apt-get dist-upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Note: Java/Maven is installed on-demand at runtime when processing Java/Scala projects
# This reduces the base image size by ~330MB for non-Java workloads

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

# A home that stays writable whatever uid the caller supplies.
#
# The image still runs as root by default -- GitHub requires that of a
# container action -- but plenty of callers override it. Jenkins' Docker
# Pipeline plugin passes `-u <uid>:<gid>` by default, and anyone running
# `docker run --user` locally does the same. A uid with no passwd entry gets
# HOME=/, which it cannot write.
#
# That is not a cosmetic problem. cosign keeps its TUF trust root in
# $HOME/.sigstore, so it cannot verify a bundle's attestation, and refusing
# an unverifiable binary is a hard stop by design. Measured against the
# published image with `-u 1000:1000`: every ecosystem that fetches a bundle
# (Go, Rust, .NET, Dart, JVM, npm, PHP) fails with
#
#     Attestation verification failed ... mkdir /.sigstore: permission denied
#
# and only Python survives, because cyclonedx-py is in the venv and needs no
# bundle. The failure reads as a supply-chain problem rather than a
# permissions one, which is why it went unnoticed.
#
# World-writable rather than group-writable: the uid arrives at run time, so
# no narrower grant covers it. What lives here is a per-run cache and the
# trust root, inside a single-tenant ephemeral container. Deliberately NOT
# `--gid 0`: measured against this image, primary gid 0 grants access to
# exactly three apt/dpkg lock files and nothing else, and it is overridden
# anyway the moment a caller passes `--user`.
RUN useradd --uid 1001 --user-group --create-home --home-dir /home/sbomify --shell /bin/bash sbomify
ENV HOME=/home/sbomify

# Initialize Conan profile for C/C++ package metadata lookups
# This creates a default profile based on the container's compiler/OS settings
#
# CONAN_HOME rather than the default ~/.conan2 resolved at build time: that
# lands in /root, which is mode 700 and unreadable to any other uid. Conan
# also creates .conan.db lazily on first use, so the directory has to be
# writable, not merely readable, or every pkg:conan/* lookup degrades to a
# warning.
#
# Kept under $HOME rather than a second world-writable tree in /opt: that
# one would contain conan's executable plugins (profile.py,
# compatibility.py), which is a code-execution surface this does not need.
ENV CONAN_HOME=/home/sbomify/.conan2
RUN conan profile detect --force && chmod -R a+rwX /home/sbomify

# Marks our own image, which two behaviours key off:
#   - runtime tools are fetched on demand only in here, where we decide the
#     toolchain; a pip install keeps whatever the user has
#   - a generator that claims an input and then fails is a defect we shipped,
#     so the orchestrator aborts rather than quietly substituting a
#     lower-priority tool and hiding it
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
