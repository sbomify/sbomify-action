"""The workflows under examples/ parse, and pass only settings the tool reads.

actionlint covers the GitHub files in CI, but it never sees `env:` names and
skips input checks for SHA-pinned actions; GitLab and Bitbucket files get no
linter at all. A misspelt setting is silently ignored at runtime, so the SBOM
comes out wrong with nothing to say so.
"""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).parent.parent
EXAMPLES = ROOT / "examples"
# A name is a setting if the package reads it: os.getenv("X"), envvar="X", ...
SOURCE = "".join(p.read_text() for p in (ROOT / "sbomify_action").rglob("*.py"))
INPUTS = yaml.safe_load((ROOT / "action.yml").read_text())["inputs"]


def _settings(path: Path) -> tuple[list[str], list[str]]:
    """(environment variables, action inputs) the example hands the tool."""
    doc = yaml.safe_load(path.read_text())
    assert isinstance(doc, dict), f"{path} did not parse to a mapping"
    env: list[str] = []
    inputs: list[str] = []
    match path.parent.name:
        case "github":
            for job in doc["jobs"].values():
                for step in job["steps"]:
                    if step.get("uses", "").startswith("sbomify/sbomify-action@"):
                        env += step.get("env", {})
                        inputs += step.get("with", {})
                    # Without it a missing SBOM only warns, and a misspelt key is ignored.
                    if step.get("uses", "").startswith("actions/upload-artifact@"):
                        assert step["with"].get("if-no-files-found") == "error", f"{path}: {step}"
        case "gitlab":
            for job in doc.values():
                if isinstance(job, dict) and "script" in job:
                    env += job.get("variables", {})
        case "bitbucket":
            for item in doc["pipelines"]["default"]:
                for line in item["step"]["script"]:
                    if line.startswith("export "):
                        env += [pair.partition("=")[0] for pair in line.split()[1:]]
    return env, inputs


EXAMPLE_FILES = sorted(EXAMPLES.glob("*/*.yml"))


def test_every_platform_has_examples():
    # Guards the parametrized test below against passing vacuously.
    assert {p.parent.name for p in EXAMPLE_FILES} == {"github", "gitlab", "bitbucket"}


@pytest.mark.parametrize("path", EXAMPLE_FILES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_example_uses_only_real_settings(path):
    env, inputs = _settings(path)
    assert env, f"{path} passes no settings to sbomify-action"
    assert [name for name in env if f'"{name}"' not in SOURCE] == []
    assert [name for name in inputs if name not in INPUTS] == []
