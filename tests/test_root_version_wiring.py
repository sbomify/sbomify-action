"""The root-version derivation as augmentation actually applies it.

test_root_version.py covers the resolver in isolation. This covers the branch
that decides whether to call it at all -- which is the behaviour change, and
the part that would silently stop working if the condition were wrong.
"""

import subprocess

import pytest
from cyclonedx.model.bom import Bom

from sbomify_action.augmentation import augment_cyclonedx_sbom

CI_VARS = (
    "GITHUB_REF_TYPE",
    "GITHUB_REF_NAME",
    "GITHUB_REF",
    "GITHUB_SHA",
    "CI_COMMIT_TAG",
    "CI_COMMIT_SHA",
    "BITBUCKET_TAG",
    "BITBUCKET_COMMIT",
)


@pytest.fixture(autouse=True)
def _no_ambient_ci(monkeypatch):
    for name in CI_VARS:
        monkeypatch.delenv(name, raising=False)


def _bom(version: str | None) -> Bom:
    component: dict = {"type": "application", "name": "thing", "bom-ref": "root"}
    if version is not None:
        component["version"] = version
    return Bom.from_json(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": component},
            "components": [],
        }
    )


def _tagged_repo(tmp_path, tag: str):
    tmp_path.mkdir(parents=True, exist_ok=True)
    run = lambda *a: subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("config", "user.email", "t@e.invalid")
    run("config", "user.name", "T")
    run("config", "commit.gpgsign", "false")
    run("config", "tag.gpgSign", "false")
    (tmp_path / "f").write_text("x")
    run("add", "f")
    run("commit", "-qm", "one")
    run("tag", tag)
    return tmp_path


@pytest.mark.parametrize("placeholder", ["latest", "unknown", "sha256:" + "a" * 64, None])
def test_a_placeholder_is_replaced_by_the_tag(tmp_path, placeholder):
    repo = _tagged_repo(tmp_path / "repo", "v4.5.6")

    out = augment_cyclonedx_sbom(_bom(placeholder), {}, source_dir=str(repo))

    assert out.metadata.component.version == "v4.5.6"


def test_a_real_version_is_left_alone(tmp_path):
    """The generator knew something; do not overwrite it."""
    repo = _tagged_repo(tmp_path / "repo", "v4.5.6")

    out = augment_cyclonedx_sbom(_bom("1.2.3"), {}, source_dir=str(repo))

    assert out.metadata.component.version == "1.2.3"


def test_an_explicit_version_wins_over_the_checkout(tmp_path):
    """COMPONENT_VERSION is the caller stating what this build is."""
    repo = _tagged_repo(tmp_path / "repo", "v4.5.6")

    out = augment_cyclonedx_sbom(_bom("latest"), {}, component_version="9.9.9", source_dir=str(repo))

    assert out.metadata.component.version == "9.9.9"


def test_nothing_knowable_leaves_the_placeholder_and_warns(tmp_path, caplog):
    """A tarball with no .git, outside CI. Inventing a version would be worse."""
    plain = tmp_path / "not-a-repo"
    plain.mkdir()

    with caplog.at_level("WARNING"):
        out = augment_cyclonedx_sbom(_bom("latest"), {}, source_dir=str(plain))

    assert out.metadata.component.version == "latest"
    assert any("COMPONENT_VERSION" in r.message for r in caplog.records), "the user was not told"


def test_no_source_dir_is_not_an_error(tmp_path):
    """A container image has no checkout to ask."""
    out = augment_cyclonedx_sbom(_bom("latest"), {}, source_dir=None)

    assert out.metadata.component.version == "latest"


def test_the_purl_is_updated_to_match(tmp_path):
    """A version and a purl that disagree is worse than either alone."""
    repo = _tagged_repo(tmp_path / "repo", "v4.5.6")
    bom = Bom.from_json(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": "thing",
                    "bom-ref": "root",
                    "version": "latest",
                    "purl": "pkg:pypi/thing@latest",
                }
            },
            "components": [],
        }
    )

    out = augment_cyclonedx_sbom(bom, {}, source_dir=str(repo))

    assert out.metadata.component.version == "v4.5.6"
    assert "latest" not in str(out.metadata.component.purl), str(out.metadata.component.purl)
