ARG UV_VERSION=0.12.1


# UV binary stage
FROM ghcr.io/astral-sh/uv:${UV_VERSION}@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded AS uv-fetcher

# Python builder stage
FROM python:3.14-slim-trixie AS builder

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

# git is needed at runtime: the wizard reads repo facts (remote name,
# branch, visibility) from the bind-mounted workspace, and slim images
# don't ship it. Without it those facts silently degrade to folder-name
# and "unknown" visibility.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Note: Java/Maven is installed on-demand at runtime when processing Java/Scala projects
# This reduces the base image size by ~330MB for non-Java workloads

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

# Initialize Conan profile for C/C++ package metadata lookups
# This creates a default profile based on the container's compiler/OS settings
RUN conan profile detect --force

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
