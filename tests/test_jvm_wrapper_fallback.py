"""A project's build wrapper that cannot run should not cost it its SBOM.

Both cases here were found by running the action over 500 open source
projects, and both ended the same way: the native generator failed, the chain
fell through to cdxgen, and the project got a materially worse document. This
module measures elsewhere that the gap is 288 components against 34.

  apache/kafka  gitignores gradle/wrapper/gradle-wrapper.jar, so gradlew tries
                to fetch it with curl, which the image does not carry:
                "/workspace/gradlew: 207: curl: not found", three times, then
                "Unable to access jarfile".

  apache/flink  ships its maven-wrapper.jar and mvnw rejects it at run time:
                "Failed to validate Maven wrapper SHA-256, your Maven wrapper
                might be compromised."

The first is predictable before running anything; the second is not, which is
why there are two mechanisms rather than one.
"""

from pathlib import Path

import pytest

from sbomify_action._generation.generators import cyclonedx_jvm as jvm
from sbomify_action.exceptions import SBOMGenerationError

#: As the jvm bundle declares them. Spelled out rather than read from
#: _WRAPPER_DEFAULTS so that a change to the defaults has to be made twice --
#: once in the code and once here, deliberately.
GRADLE = {"script": "gradlew", "tool": "gradle", "needs": "gradle/wrapper/gradle-wrapper.jar"}
MAVEN = {"script": "mvnw", "tool": "mvn"}


class TestWrapperSelection:
    def test_a_wrapper_with_its_jar_is_preferred(self, tmp_path):
        """The reason wrappers are preferred at all: projects pin a version."""
        (tmp_path / "gradlew").write_text("#!/bin/sh\n")
        jar = tmp_path / "gradle" / "wrapper" / "gradle-wrapper.jar"
        jar.parent.mkdir(parents=True)
        jar.write_bytes(b"jar")

        chosen = jvm._wrapper_or(tmp_path, GRADLE)

        assert chosen == str(tmp_path / "gradlew")

    def test_a_wrapper_without_its_jar_is_declined(self, tmp_path):
        """apache/kafka. The script is there; the thing it needs is not."""
        (tmp_path / "gradlew").write_text("#!/bin/sh\n")

        chosen = jvm._wrapper_or(tmp_path, GRADLE)

        assert chosen == "gradle"

    def test_no_wrapper_at_all_uses_the_pinned_tool(self, tmp_path):
        assert jvm._wrapper_or(tmp_path, GRADLE) == "gradle"

    def test_needs_is_optional(self, tmp_path):
        """Maven keeps the pre-flight check off, having no observed case for it."""
        (tmp_path / "mvnw").write_text("#!/bin/sh\n")

        assert jvm._wrapper_or(tmp_path, MAVEN) == str(tmp_path / "mvnw")


class TestTheBundleOwnsTheseFacts:
    """Which wrapper maps to which tool is the bundle's to state, not ours.

    The plugin pins made this case already: they lived in both repositories
    and disagreed within hours of the split, sbom-tools saying 2.9.3 while
    this one still said 2.9.1. Reading the wrapper map off the bundle keeps
    one source of truth in the repository that decides what the bundle holds.
    """

    def test_what_the_bundle_declares_is_used(self, monkeypatch):
        """A bundle that renames its tool is followed, not overruled."""
        monkeypatch.setattr(
            jvm,
            "bundle_wrappers",
            lambda _provider: {"gradle": {"script": "gradlew", "tool": "gradle-9", "needs": "somewhere/else.jar"}},
        )

        assert jvm._wrapper_spec("gradle", "gradle") == {
            "script": "gradlew",
            "tool": "gradle-9",
            "needs": "somewhere/else.jar",
        }

    def test_a_bundle_predating_the_block_falls_back_to_defaults(self, monkeypatch):
        """An older bundle should still build, so silence is not fatal."""
        monkeypatch.setattr(jvm, "bundle_wrappers", lambda _provider: {})

        assert jvm._wrapper_spec("gradle", "gradle") == GRADLE
        assert jvm._wrapper_spec("maven", "maven") == MAVEN

    def test_an_unreadable_bundle_falls_back_to_defaults(self, monkeypatch):
        """Not being able to ask must not cost more than being told nothing."""

        def _unavailable(_provider):
            raise SBOMGenerationError("no bundle here")

        monkeypatch.setattr(jvm, "bundle_wrappers", _unavailable)

        assert jvm._wrapper_spec("maven", "maven") == MAVEN

    def test_the_defaults_match_what_the_bundle_ships(self):
        """The floor and the bundle should not have drifted apart silently."""
        assert jvm._WRAPPER_DEFAULTS == {"gradle": GRADLE, "maven": MAVEN}


class TestRetryAfterAWrapperFails:
    @staticmethod
    def _record(monkeypatch, fail_on) -> list[list[str]]:
        """Capture each command, failing those whose argv[0] matches fail_on."""
        calls: list[list[str]] = []

        def fake_run(cmd, name, **kwargs):
            calls.append(list(cmd))
            if fail_on(cmd[0]):
                raise SBOMGenerationError(f"{name} failed")

        monkeypatch.setattr(jvm, "run_command", fake_run)
        return calls

    def test_a_failing_wrapper_is_retried_with_the_pinned_tool(self, tmp_path, monkeypatch):
        """apache/flink: the wrapper is present, and rejects itself."""
        wrapper = str(tmp_path / "mvnw")
        calls = self._record(monkeypatch, lambda argv0: argv0 == wrapper)

        jvm._run_build([wrapper, "-B", "goal"], "cyclonedx-maven", tmp_path, "mvn", 60)

        assert [c[0] for c in calls] == [wrapper, "mvn"]
        assert calls[1][1:] == ["-B", "goal"], "the retry must keep the same arguments"

    def test_the_pinned_tool_failing_is_a_real_failure(self, tmp_path, monkeypatch):
        """No wrapper involved, so there is nothing to fall back to."""
        calls = self._record(monkeypatch, lambda _argv0: True)

        with pytest.raises(SBOMGenerationError):
            jvm._run_build(["mvn", "-B", "goal"], "cyclonedx-maven", tmp_path, "mvn", 60)

        assert len(calls) == 1, "the pinned tool must not be retried against itself"

    def test_a_wrapper_that_works_is_not_retried(self, tmp_path, monkeypatch):
        wrapper = str(tmp_path / "gradlew")
        calls = self._record(monkeypatch, lambda _argv0: False)

        jvm._run_build([wrapper, "task"], "cyclonedx-gradle", tmp_path, "gradle", 60)

        assert [c[0] for c in calls] == [wrapper]

    def test_both_failing_still_raises(self, tmp_path, monkeypatch):
        """The retry is a second chance, not a guarantee."""
        wrapper = str(tmp_path / "gradlew")
        calls = self._record(monkeypatch, lambda _argv0: True)

        with pytest.raises(SBOMGenerationError):
            jvm._run_build([wrapper, "task"], "cyclonedx-gradle", tmp_path, "gradle", 60)

        assert [c[0] for c in calls] == [wrapper, "gradle"]


@pytest.fixture
def declared_wrappers(monkeypatch):
    """Answer for the bundle without going and fetching one.

    generate() calls ensure_runtime before _run, so in production the manifest
    read is free -- the bundle is already on disk and the result memoised.
    A test that calls _run directly skips that, and would otherwise download a
    190MB JDK to find out what "gradlew" maps to.
    """
    monkeypatch.setattr(jvm, "bundle_wrappers", lambda _provider: {"gradle": GRADLE, "maven": MAVEN})


def test_the_gradle_generator_declines_a_jarless_wrapper(tmp_path, monkeypatch, declared_wrappers):
    """End to end through the generator, not just the helper."""
    (tmp_path / "build.gradle").write_text("")
    (tmp_path / "gradlew").write_text("#!/bin/sh\n")

    calls: list[list[str]] = []
    monkeypatch.setattr(jvm, "run_command", lambda cmd, name, **kw: calls.append(list(cmd)))
    monkeypatch.setattr(jvm, "gradle_init_script", lambda: "// init")

    jvm.CycloneDXGradleGenerator()._run(tmp_path, tmp_path / "out.json")

    assert calls and calls[0][0] == "gradle", f"used {calls[0][0] if calls else 'nothing'} instead of the pinned tool"
    assert not (tmp_path / ".sbomify-cyclonedx.init.gradle").exists(), "scaffolding left behind"


def test_the_init_script_is_removed_even_when_both_attempts_fail(tmp_path, monkeypatch, declared_wrappers):
    """Both attempts, so the wrapper has to be usable enough to be chosen.

    Without a gradlew and its jar, `_wrapper_or` picks the pinned tool
    straight away and there is only ever one attempt -- the retry path this
    is named for never runs.
    """
    (tmp_path / "build.gradle").write_text("")
    (tmp_path / "gradlew").write_text("#!/bin/sh\n")
    jar = tmp_path / "gradle" / "wrapper" / "gradle-wrapper.jar"
    jar.parent.mkdir(parents=True)
    jar.write_bytes(b"jar")

    attempts: list[str] = []

    def always_fails(cmd, name, **kwargs):
        attempts.append(cmd[0])
        raise SBOMGenerationError("no")

    monkeypatch.setattr(jvm, "run_command", always_fails)
    monkeypatch.setattr(jvm, "gradle_init_script", lambda: "// init")

    with pytest.raises(SBOMGenerationError):
        jvm.CycloneDXGradleGenerator()._run(tmp_path, tmp_path / "out.json")

    assert attempts == [str(tmp_path / "gradlew"), "gradle"], f"expected both attempts, got {attempts}"
    assert not (tmp_path / ".sbomify-cyclonedx.init.gradle").exists()


def test_path_helpers_do_not_mind_a_missing_directory(tmp_path):
    """needs pointing into a directory that does not exist must not raise."""
    (tmp_path / "gradlew").write_text("#!/bin/sh\n")
    assert jvm._wrapper_or(tmp_path, {**GRADLE, "needs": "a/b/c.jar"}) == "gradle"


def test_wrapper_is_made_executable(tmp_path):
    """A checkout from an archive can arrive without the bit set."""
    wrapper = tmp_path / "gradlew"
    wrapper.write_text("#!/bin/sh\n")
    wrapper.chmod(0o644)

    jvm._wrapper_or(tmp_path, {"script": "gradlew", "tool": "gradle"})

    assert Path(wrapper).stat().st_mode & 0o111, "wrapper was not made executable"
