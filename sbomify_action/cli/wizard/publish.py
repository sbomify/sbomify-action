"""``run_publish`` — the wizard's local generate-and-upload step.

Runs after ``apply_plan`` has created the components and written the
workflow file: each (lockfile, format) matrix row the workflow would
run in CI is executed locally, once, so the user leaves the wizard with
their first SBOMs already on sbomify instead of waiting for the first
push to trigger CI.

Each row runs as a subprocess of this interpreter (see
``_PIPELINE_BOOTSTRAP``) rather than an in-process ``run_pipeline``
call. That's deliberate: the pipeline configures global logging, chdirs
via WORKING_DIR handling, mutates the process-wide audit trail, and
exits with ``sys.exit`` on failure — none of which can be allowed to
happen inside the Textual app's process. A subprocess also exercises
exactly the code path the emitted workflow will run in CI.

The subprocess env mirrors the workflow's ``env:`` block, with one
difference: CI authenticates via OIDC or the SBOMIFY_TOKEN secret,
while the local run reuses the session token the user already entered
on the Authenticate screen.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from sbomify_action.cli.wizard.ci_emitter import MatrixRow, augmentation_to_env, matrix_rows
from sbomify_action.cli.wizard.options import WizardOptions
from sbomify_action.cli.wizard.state import PublishOutcome, WizardState

LogKind = Literal["info", "success", "warning", "error", "output"]
LogFn = Callable[[LogKind, str], None]


def _noop(_kind: LogKind, _message: str) -> None:
    """Default log sink — used when no UI is attached (eg. tests)."""


# Pipeline configuration env vars scrubbed from the inherited environment
# before each run. Anything the user happens to have exported (a stray
# DOCKER_IMAGE, a leftover SBOM_FILE from manual testing) would otherwise
# silently redirect the run away from the lockfile the wizard planned.
_PIPELINE_ENV_VARS = (
    "TOKEN",
    "COMPONENT_ID",
    "COMPONENT_NAME",
    "COMPONENT_VERSION",
    "COMPONENT_PURL",
    "SBOM_VERSION",
    "OVERRIDE_NAME",
    "OVERRIDE_SBOM_METADATA",
    "SBOM_FILE",
    "LOCK_FILE",
    "DOCKER_IMAGE",
    "UPLOAD",
    "UPLOAD_DESTINATIONS",
    "AUGMENT",
    "ENRICH",
    "PRODUCT_RELEASE",
    "API_BASE_URL",
    "SBOM_FORMAT",
    "OUTPUT_FILE",
    "BOM_TYPE",
    "SPEC_VERSION",
    "OIDC_AUDIENCE",
    "WORKING_DIR",
)


# Bootstrap for the pipeline subprocess. ``-c`` rather than ``-m
# sbomify_action.cli.main``: the wizard process has already imported the
# module, and runpy re-executing an imported module prints a
# RuntimeWarning that would land as noise at the top of every publish
# log. It also avoids depending on the ``sbomify-action`` console script
# being on PATH. Configuration travels entirely via env vars (the same
# contract the GitHub Action uses), so no argv is needed.
_PIPELINE_BOOTSTRAP = "from sbomify_action.cli.main import main; main()"


@dataclass(frozen=True)
class PublishRun:
    """One planned local pipeline invocation."""

    row: MatrixRow
    output_path: Path
    """Absolute path the run writes its final SBOM to — ``row.output_file``
    inside the session's publish output dir, never the repo working tree."""


def component_version(repo_root: Path) -> str | None:
    """The version stamped on locally published SBOMs.

    Mirrors the emitted workflow's non-tag fallback (``git rev-parse
    --short HEAD``): trunk/manual strategies always use the short SHA,
    and tag-strategy dispatch runs fall back to it too, so the short SHA
    is the one version every strategy agrees on. ``None`` (version
    omitted) when git can't answer — eg. a repo with no commits yet.
    """
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    sha = proc.stdout.strip()
    return sha or None


def build_publish_runs(state: WizardState, output_dir: Path) -> list[PublishRun]:
    """Plan one run per (lockfile, format) — the same rows CI would run.

    Uses the real component IDs ``apply_plan`` recorded on
    ``state.component_ids``, so a row can never carry the
    ``REPLACE_WITH_COMPONENT_ID`` placeholder here (apply always runs
    first and populates every planned component's ID).
    """
    plan = state.plan
    component_ids = {str(rel): cid for rel, cid in state.component_ids.items()}
    rows = matrix_rows(plan.create_components, plan.sbom_formats or ["cyclonedx"], component_ids)
    return [PublishRun(row=row, output_path=output_dir / row.output_file) for row in rows]


def _build_env(run: PublishRun, state: WizardState, opts: WizardOptions, version: str | None) -> dict[str, str]:
    """Subprocess environment for one run — the workflow's ``env:`` block,
    with the session token standing in for OIDC / the repo secret.

    ``PRODUCT_RELEASE`` is intentionally NOT set even for tag-strategy
    plans: the local publish stamps a short-SHA version, and cutting a
    product release named after a random commit SHA as a side effect of
    onboarding would be surprising. Releases stay CI's job.
    """
    # The wizard's authenticate screen always constructs the client with
    # the token string the user entered, but the client's type allows
    # None (other flows construct it tokenless). Coerce for typing; an
    # empty TOKEN would fail the subprocess's own config validation with
    # a clear "token is required" error rather than anything silent.
    token = state.require_api().token or ""
    env = {k: v for k, v in os.environ.items() if k not in _PIPELINE_ENV_VARS}
    env.update(
        {
            "TOKEN": token,
            "COMPONENT_ID": run.row.component_id,
            "COMPONENT_NAME": run.row.component_name,
            "LOCK_FILE": run.row.lockfile,
            "UPLOAD": "true",
            "AUGMENT": augmentation_to_env(state.plan.augmentation),
            "ENRICH": "true" if state.plan.enrich else "false",
            "SBOM_FORMAT": run.row.sbom_format,
            "OUTPUT_FILE": str(run.output_path),
            "API_BASE_URL": opts.api_base_url,
        }
    )
    if version:
        env["COMPONENT_VERSION"] = version
    return env


def _stream_subprocess(
    cmd: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    on_line: Callable[[str], None],
) -> int:
    """Run ``cmd``, forwarding each output line to ``on_line``. Returns the exit code.

    stderr is merged into stdout so the log preserves the pipeline's own
    interleaving. Isolated as a module-level function so tests can stub
    the subprocess boundary without faking ``Popen``.
    """
    # nosemgrep: dangerous-subprocess-use-audit  # list-form, shell=False, fixed executable (sys.executable -c <constant>)
    proc = subprocess.Popen(  # noqa: S603 — argv is built from wizard state, not user shell input
        cmd,
        env=env,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None  # stdout=PIPE above
    for line in proc.stdout:
        on_line(line.rstrip("\n"))
    return proc.wait()


def run_publish(state: WizardState, opts: WizardOptions, *, log: LogFn = _noop) -> bool:
    """Execute every planned run sequentially. Returns True iff all succeeded.

    Best-effort by design: a failed run is logged and recorded on
    ``state.publish_outcomes`` but never aborts the remaining runs and
    never raises — the workflow file is already on disk, so CI will
    publish on the next push regardless of what happens here.

    Sequential rather than parallel: generators and enrichment already
    parallelise internally, the pipeline writes fixed-name step files
    (``step_1.json``…) into the working directory that concurrent runs
    would clobber, and an interleaved log would be unreadable anyway.
    """
    state.publish_outcomes = []
    output_dir = Path(tempfile.mkdtemp(prefix="sbomify-wizard-publish-"))
    state.publish_output_dir = output_dir
    runs = build_publish_runs(state, output_dir)

    if not runs:
        log("warning", "Nothing to publish — no components were applied.")
        return True

    if opts.dry_run:
        _run_publish_dry_run(state, runs, log)
        return True

    version = component_version(opts.repo_root)
    all_ok = True
    for i, run in enumerate(runs, start=1):
        row = run.row
        log("info", "")
        log(
            "info",
            f"[{i}/{len(runs)}] {row.component_name} — {row.lockfile} → {row.sbom_format}",
        )
        env = _build_env(run, state, opts, version)
        cmd = [sys.executable, "-c", _PIPELINE_BOOTSTRAP]
        try:
            # cwd must be the repo root: LOCK_FILE is repo-relative (same as
            # the CI matrix), and the augmentation providers resolve
            # sbomify.json / git VCS facts from the working directory.
            exit_code = _stream_subprocess(
                cmd,
                env=env,
                cwd=opts.repo_root,
                on_line=lambda line: log("output", line),
            )
        except OSError as exc:
            exit_code = -1
            log("error", f"Could not start the pipeline: {exc}")
            error: str | None = str(exc)
        else:
            error = None if exit_code == 0 else f"pipeline exited with code {exit_code}"

        ok = exit_code == 0
        state.publish_outcomes.append(
            PublishOutcome(
                rel_path=row.lockfile,
                sbom_format=row.sbom_format,
                output_file=run.output_path,
                ok=ok,
                error=error,
            )
        )
        if ok:
            log("success", f"Published {row.component_name} ({row.sbom_format}) to sbomify")
        else:
            all_ok = False
            log("error", f"Publish failed for {row.component_name} ({row.sbom_format}): {error}")

    log("info", "")
    if all_ok:
        log("success", f"All {len(runs)} SBOM(s) published. Files kept in {output_dir}")
    else:
        failed = sum(1 for o in state.publish_outcomes if not o.ok)
        log(
            "warning",
            f"{failed} of {len(runs)} run(s) failed — the CI workflow will retry on the next push. "
            "Scroll up for the pipeline output of the failed run(s).",
        )
    return all_ok


def _run_publish_dry_run(state: WizardState, runs: list[PublishRun], log: LogFn) -> None:
    """Preview the runs without spawning any pipeline subprocess.

    Populates ``state.publish_outcomes`` with ok=True markers so the
    Done screen can render a "would publish" preview panel;
    ``state.is_dry_run`` (set by the apply pass) drives the phrasing.
    """
    log("info", "Dry-run mode — no SBOMs are generated or uploaded.")
    for run in runs:
        row = run.row
        log(
            "info",
            f"[dry-run] Would generate {row.output_file} from {row.lockfile} "
            f"({row.sbom_format}) and upload it to component {row.component_id}",
        )
        state.publish_outcomes.append(
            PublishOutcome(
                rel_path=row.lockfile,
                sbom_format=row.sbom_format,
                output_file=run.output_path,
                ok=True,
            )
        )
    log("info", "")
    log("info", "Re-run without --dry-run to actually publish.")
