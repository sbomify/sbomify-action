# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

sbomify action is an SBOM (Software Bill of Materials) generation, enrichment, augmentation, and management tool for CI/CD pipelines. It supports CycloneDX and SPDX formats, generates SBOMs from lockfiles and Docker images, enriches them with metadata from package registries, and uploads to various destinations.

**Key facts:** Python 3.11+, published to PyPI as `sbomify-action`, also available as Docker image and GitHub Action.

## Development Commands

```bash
# Install dependencies
uv sync --locked --dev

# Run linting
uv run ruff check sbomify_action tests

# Run format check
uv run ruff format --check sbomify_action tests

# Run type checker
uv run mypy sbomify_action

# Run tests (fails under 80% coverage)
uv run pytest

# Run one file — add --no-cov, or the 80% gate fails on the partial run
uv run pytest tests/test_serialization.py --no-cov
```

The three checks above `pytest` are exactly what the `Sanity Checks` CI job
runs, in that order. Run all four before pushing — mypy in particular fails
CI on things the linter is happy with, such as returning `Any` from a
function annotated to return `bool`.

## Architecture

The project uses a **Protocol + Registry + Factory** pattern across four main subsystems (see `docs/adr/0002-plugin-architecture.md`).

### Protocol Interface

Each plugin implements:
- Properties: `name`, `priority`
- Methods: `supports(input) -> bool`, `execute(input, context) -> NormalizedOutput`

### Priority Model (Native-First with Generic Fallback)

| Priority | Category             | Rationale                                   |
|----------|----------------------|---------------------------------------------|
| 1-20     | Native/Authoritative | Direct from ecosystem's official source     |
| 21-50    | Primary Aggregators  | Well-maintained multi-ecosystem services    |
| 51-80    | Local Extraction     | No external API calls, parse available data |
| 81-100   | Fallback Sources     | Rate-limited or less reliable sources       |

### Subsystems

1. **Generation** (`sbomify_action/_generation/`) - Converts lockfiles/Docker images to SBOMs
   - Plugins: `cyclonedx_py`, `cargo_cyclonedx`, `cdxgen`, `trivy`, `syft`

2. **Enrichment** (`sbomify_action/_enrichment/`) - Fetches package metadata from registries
   - Sources: `pypi`, `pubdev`, `debian`, `license_db`, `lifecycle`, `conan`, `cratesio`, `depsdev`, `ecosystems`, `repology`
   - All sources output to `NormalizedMetadata` dataclass

3. **Augmentation** (`sbomify_action/_augmentation/`) - Adds organizational metadata
   - Providers: `json_config` (sbomify.json), `sbomify_api`, `github`, `gitlab`, `bitbucket`, `teamcity`
   - Auto-detects VCS info from CI environment

4. **Upload** (`sbomify_action/_upload/`) - Uploads SBOMs to destinations
   - Destinations: `sbomify`, `dependency_track`

**Note:** By relying on third-party sources, SBOM generation is not guaranteed to be deterministic. The same input may produce different outputs depending on external source availability or data changes.

### CLI Pipeline (`sbomify_action/cli/main.py`)

Three-step orchestration: Generate/Validate → Augment → Enrich → Upload

Each step maintains an audit trail with timestamps for compliance.

### Key Modules

- `console.py` - Rich-formatted CLI output, audit trail formatting
- `serialization.py` - CycloneDX/SPDX serialization
- `validation.py` - JSON schema validation for SBOMs
- `additional_packages.py` - Inject additional packages into SBOMs
- `exceptions.py` - Custom exception hierarchy

## Development Rules

- Never edit lockfiles manually - use `uv` for dependency management
- Always run tests before committing
- Maintain 80%+ test coverage — `--cov-fail-under=80` in `addopts` enforces
  it, so `pytest` goes red below the line. The margin is thin (80.04% at the
  time of writing), so a chunk of new code without tests will trip it
- Use `git --no-pager` for git operations
- Never create summary/documentation files unless explicitly requested

## Audit your own diff before you commit

Read every hunk of `git --no-pager diff` and `git --no-pager diff --staged`
before committing. A hunk that does not serve the change you were asked to
make is noise, and noise is expensive: it buries the real change in review,
churns `git blame`, and turns a three-line fix into a two-hundred-line pull
request nobody can check.

**Revert any hunk whose only effect is one of these:**

- Rewrapping prose, comments or docstrings to a different width, joining lines
  onto one line, or splitting one line across several.
- Blank lines, trailing whitespace or a trailing newline added or removed in
  code you did not otherwise change.
- Reordering imports, dict keys or function definitions with no functional
  reason.
- Swapping quote style, `.format()` for an f-string, or `List[str]` for
  `list[str]` on lines the task did not touch. The modern syntax below is the
  rule for code you write, not a licence to sweep the file.
- Renaming a local, reordering parameters or restyling a conditional because
  you prefer it the other way.
- Re-serialising a JSON or YAML file with different indentation or key order.
  SBOM fixtures under `tests/test-data/` are byte-for-byte inputs: a
  re-indented fixture is a thousand-line diff that changes nothing.
- Touching `uv.lock` or `bun.lock` by hand. Regenerate with `uv` or `bun`, or
  leave them alone.

**The formatters own the shape of a file, you do not.** `ruff format` and the
pre-commit hooks are the only things allowed to reformat, and what they change
belongs in the diff. If one of them rewrites a file far past your edit, that
file was unformatted before you arrived: put the reformat in its own commit
and say so in the message. The same goes for a cleanup that is genuinely worth
doing. A rename, a reorder, a dead-code removal — each is its own commit,
never folded into the change under review.

Two commands catch most of it. `git --no-pager diff --stat`: if the line count
is much larger than the change you would describe in one sentence, there is
reformatting in there. `git --no-pager diff -w`: if that is much smaller than
the plain diff, the gap is whitespace churn to revert.

## Git Commit Identity

Worktree environments may have no inherited `user.name`/`user.email`. **Never run `git config` to set identity.** Pass identity via environment variables on the commit command instead:

```bash
GIT_AUTHOR_NAME="..." GIT_AUTHOR_EMAIL="..." \
GIT_COMMITTER_NAME="..." GIT_COMMITTER_EMAIL="..." git commit ...
```

When committing on behalf of the repo maintainer, match the identity used on their existing *feature-branch* commits (`git --no-pager log --format='%an <%ae>'` on a feature branch) — not the `@users.noreply.github.com` identity that appears on squash-merged commits on master.

## Wizard TUI (Textual) Design Rules

The wizard (`sbomify_action/cli/wizard/`) must be **fit-to-viewport, never scrolling** — scrolling is not a normal TUI paradigm, and a scrolling page hides the primary CTA (e.g. a Start button pushed off-screen). Make content fit the terminal via progressive disclosure, not scrollbars.

The responsive system lives in `screens/_base.py` (`_apply_responsive`, breakpoint constants) plus `styles.tcss`. `WizardScreen.on_resize` toggles classes on the screen:

- `-tiny` (below 80×24): swap the whole body for a centered "resize your terminal" prompt
- `-compact` (below the roomy bound): flatten padding, slim buttons to 1 row, inputs to a 2-row underline, drop per-screen subtitles and explanatory prose
- `-no-art` / `-no-preview`: each decorative/secondary element gets its **own** size bound so it shows whenever it fits, not only on huge terminals
- Roomy (≥100×63): full comfortable layout

Tag droppable rationale/compliance prose with class `wizard-help` (hidden in compact); keep warnings/status as `wizard-muted` (always shown). Split long forms into fit-to-viewport pages via `PagedFormScreen` (`screens/_paged.py`) — panels stay mounted so input values persist across pages. **80×24 is the supported minimum; verify every screen fits there.**

## User-Facing Help Text

Help text that explains *what* a setting does should also explain *why* the user would care — usually by naming the compliance frameworks that require the underlying SBOM field (NTIA minimum elements, CISA, EU CRA, EO 14028, FDA, PCI DSS, NIS2, BSI TR-03183, NIST 800-53/171, UK Software Security Code of Practice). Avoid bare technical descriptions like "AUGMENT=true reads contact_profile_id off the backend" — they tell the user nothing about why it matters.

If the sbomify marketing site repo is checked out as a sibling (`../sbomify.com`), treat its Hugo content as the source of truth for tone and framing: `content/compliance/*.md` (per-framework field requirements), `content/zero-to-hero.md` (augmentation framing, canonical enrichment-source list), `content/what-is-sbom.md` (format/regulation context).

## Dependabot

`dependabot.yml` supports `exclude-paths` (per-update-block glob list, shipped by GitHub in Aug 2025) — use it to keep test fixtures (e.g. `tests/test-data/**`) out of version-update scans. Caveats: it does **not** affect security-update PRs, and the uv dependency-graph builder ignores it (open bug dependabot/dependabot-core#15102), so fixture-derived security alerts may persist and need manual dismissal.

## Python Best Practices

This project targets Python 3.11+. Use modern Python features:

- **Type hints**: Use built-in generics (`list[str]`, `dict[str, int]`) instead of `typing.List`, `typing.Dict`
- **Union types**: Use `X | Y` syntax instead of `Union[X, Y]` or `Optional[X]` (use `X | None`)
- **f-strings**: Always prefer f-strings over `.format()` or `%` formatting
- **Pattern matching**: Use `match`/`case` statements where appropriate for complex conditionals
- **Walrus operator**: Use `:=` for assignment expressions when it improves readability
