"""``run_generation`` — the optional final wizard step.

Everything up to and including apply only *sets up* CI: it creates the
components/product on sbomify and writes ``.github/workflows/sboms.yml``.
The first real SBOM is normally minted later, when that workflow runs in
the GitHub runner.

But when the wizard itself runs somewhere the SBOM generators are
installed — most notably the sbomify Docker image, which bundles
syft / cdxgen / cargo-cyclonedx alongside the CLI — and the user has
already authenticated, we have everything we need to generate and upload
the very first SBOM(s) right here. This module drives that.

It deliberately shells out to the same ``sbomify-action`` pipeline the
GitHub Action runs (``python -m sbomify_action.cli.main`` with the same
env vars ``ci_emitter`` bakes into the workflow), rather than calling
``run_pipeline`` in-process. Two reasons:

  - ``run_pipeline`` writes Rich output straight to stdout and calls
    ``sys.exit`` on failure; both would corrupt / kill the Textual TUI.
  - A subprocess mirrors CI exactly (same cwd-as-repo-root, same env
    contract, same tool resolution), so a green run here is a genuine
    end-to-end test of the setup the wizard just produced.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Literal

from sbomify_action.cli.wizard.ci_emitter import augmentation_to_env
from sbomify_action.cli.wizard.discovery import slugify
from sbomify_action.cli.wizard.state import WizardState
from sbomify_action.tool_checks import check_tool_for_input

LogKind = Literal["info", "success", "warning", "error"]
LogFn = Callable[[LogKind, str], None]


def _noop(_kind: LogKind, _message: str) -> None:
    """Default log sink — used when no UI is attached (eg. tests)."""


@dataclass(frozen=True)
class GenerationJob:
    """One (component, format) the wizard can generate + upload now.

    Mirrors a single matrix row in the emitted workflow: one lockfile
    rendered into one SBOM format for one sbomify component.
    """

    component_name: str
    component_id: str
    lockfile_rel: str
    """Repo-relative lockfile path — passed verbatim as ``LOCK_FILE`` with
    the child's cwd set to the repo root, exactly like the runner."""
    lockfile_name: str
    """Basename only — what the tool-availability probe keys on."""
    sbom_format: str
    available: bool
    """True iff a generator for this lockfile is installed right now. Jobs
    that aren't available are surfaced as a 'skipped' warning rather than
    attempted (and failing noisily)."""


def plan_generation_jobs(state: WizardState) -> list[GenerationJob]:
    """Expand the applied plan into one job per (component, format).

    Reads ``state.component_ids`` (populated by apply) so every job
    carries the *real* component id the upload needs. A planned component
    with no resolved id — eg apply hadn't run, or it failed for that one —
    is skipped: there's nothing to upload it against.
    """
    plan = state.plan
    formats = plan.sbom_formats or ["cyclonedx"]
    jobs: list[GenerationJob] = []
    for planned in plan.create_components:
        comp_id = state.component_ids.get(planned.lockfile.rel_path)
        if not comp_id:
            continue
        name = planned.lockfile.path.name
        available_tools, _missing = check_tool_for_input("lock_file", name)
        available = bool(available_tools)
        for fmt in formats:
            jobs.append(
                GenerationJob(
                    component_name=planned.name,
                    component_id=comp_id,
                    lockfile_rel=str(planned.lockfile.rel_path),
                    lockfile_name=name,
                    sbom_format=fmt,
                    available=available,
                )
            )
    return jobs


def generation_available(state: WizardState) -> bool:
    """Whether to offer the final 'generate & upload now' step at all.

    True only when at least one applied component's lockfile has a
    generator installed. When nothing can be generated — eg the wizard is
    running from a plain ``pip install`` rather than the sbomify Docker
    image — the offer is hidden and the user goes straight to Done; the CI
    workflow they just configured still generates SBOMs in the container.

    Dry-run never created real components (the ids are synthetic
    placeholders), so there's nothing to upload — return False there too.
    """
    if state.is_dry_run:
        return False
    if state.api is None or not state.require_api().token:
        # No in-memory token to authenticate the upload (eg the user
        # somehow reached here without authenticating). Don't offer a step
        # that can only fail.
        return False
    return any(job.available for job in plan_generation_jobs(state))


def _detect_version(repo_root: Path) -> str | None:
    """Short git SHA for ``COMPONENT_VERSION``, mirroring the trunk/manual
    workflow's ``git rev-parse --short HEAD``. None when not a git repo (or
    git isn't available) — the pipeline accepts an unset version."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def run_generation(
    state: WizardState,
    *,
    api_base_url: str,
    repo_root: Path,
    log: LogFn = _noop,
) -> tuple[int, int]:
    """Generate + upload an SBOM for every runnable job.

    Returns ``(succeeded, total_attempted)`` so the caller can render a
    "uploaded N/M" summary. Each job runs the ``sbomify-action`` pipeline
    as a subprocess whose stdout/stderr stream into ``log`` line by line.
    Output SBOM files land in a throwaway temp dir — the value here is the
    upload to sbomify, not littering the working tree.
    """
    token = state.require_api().token
    if not token:
        log("error", "No API token available — cannot upload.")
        return (0, 0)

    all_jobs = plan_generation_jobs(state)
    jobs = [j for j in all_jobs if j.available]
    for skipped in (j for j in all_jobs if not j.available):
        log(
            "warning",
            f"Skipping {skipped.component_name} ({skipped.lockfile_rel}, {skipped.sbom_format}) — "
            "no generator installed for this lockfile.",
        )

    if not jobs:
        return (0, 0)

    augment = augmentation_to_env(state.plan.augmentation)
    enrich = state.plan.enrich
    version = _detect_version(repo_root)

    succeeded = 0
    with TemporaryDirectory(prefix="sbomify-wizard-") as tmp:
        output_dir = Path(tmp)
        for idx, job in enumerate(jobs, start=1):
            log(
                "info",
                f"[{idx}/{len(jobs)}] Generating {job.sbom_format} SBOM for {job.component_name} ({job.lockfile_rel})…",
            )
            ok = _run_one(
                job,
                token=token,
                api_base_url=api_base_url,
                repo_root=repo_root,
                augment=augment,
                enrich=enrich,
                version=version,
                output_dir=output_dir,
                log=log,
            )
            if ok:
                succeeded += 1
                log("success", f"Generated + uploaded {job.sbom_format} SBOM for {job.component_name}.")
            else:
                log("error", f"Failed to generate/upload {job.sbom_format} SBOM for {job.component_name}.")

    return (succeeded, len(jobs))


def _run_one(
    job: GenerationJob,
    *,
    token: str,
    api_base_url: str,
    repo_root: Path,
    augment: str,
    enrich: bool,
    version: str | None,
    output_dir: Path,
    log: LogFn,
) -> bool:
    """Run the pipeline for a single job; True on a clean exit.

    The env contract is the same one ``ci_emitter`` bakes into the emitted
    workflow's ``env:`` block, so this is the same code path CI takes — only
    the credential is the wizard's in-memory token instead of an OIDC-minted
    or secret one.
    """
    output_file = output_dir / f"{slugify(job.component_name) or 'component'}-{job.sbom_format}.json"

    env = dict(os.environ)
    env.update(
        {
            # Set both names so we win regardless of resolution order, and
            # so a stale SBOMIFY_TOKEN already in the environment can't shadow
            # the token the user actually authenticated with.
            "TOKEN": token,
            "SBOMIFY_TOKEN": token,
            "COMPONENT_ID": job.component_id,
            "COMPONENT_NAME": job.component_name,
            "LOCK_FILE": job.lockfile_rel,
            "SBOM_FORMAT": job.sbom_format,
            "OUTPUT_FILE": str(output_file),
            "UPLOAD": "true",
            "AUGMENT": augment,
            "ENRICH": "true" if enrich else "false",
            "API_BASE_URL": api_base_url,
            # Force the child's Rich console into plain mode — it's writing to
            # a pipe, not a tty, so colour/cursor control codes would only
            # garble the lines we stream into the parent TUI's log.
            "NO_COLOR": "1",
            "TERM": "dumb",
        }
    )
    if version:
        env["COMPONENT_VERSION"] = version

    # ``python -m sbomify_action.cli.main`` runs the same entrypoint as the
    # installed ``sbomify-action`` console script but doesn't depend on it
    # being on PATH, and reuses the wizard's own interpreter/venv.
    cmd = [sys.executable, "-m", "sbomify_action.cli.main"]
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(repo_root),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        log("error", f"Could not launch the SBOM pipeline: {exc}")
        return False

    assert proc.stdout is not None  # PIPE always yields a readable stream
    for raw in proc.stdout:
        line = raw.rstrip("\n")
        if line:
            log("info", line)
    proc.wait()
    return proc.returncode == 0
