"""Regression test for the Maven aggregate BOM losing the reactor."""

from __future__ import annotations

from pathlib import Path

from sbomify_action._generation.generators.cyclonedx_jvm import CycloneDXMavenGenerator


class TestMavenAggregateBomKeepsTheReactor:
    """`-N` emptied the reactor that `makeAggregateBom` exists to aggregate.

    A multi-module Maven build -- the dominant shape of enterprise Java --
    produced a document containing its aggregator POM and nothing else, and
    exited 0. Measured against netty, jenkins, nacos and camel: 0 components
    every time. On a two-module fixture, the same command with and without
    `-N` gives 0 components and 10.
    """

    def _command(self, tmp_path: Path, monkeypatch) -> list[str]:
        captured: dict[str, list[str]] = {}

        def fake_run(cmd, _name, timeout=None, cwd=None):  # type: ignore[no-untyped-def]
            captured["cmd"] = list(cmd)

        monkeypatch.setattr(
            "sbomify_action._generation.generators.cyclonedx_jvm.run_command",
            fake_run,
        )
        monkeypatch.setattr(
            "sbomify_action._generation.generators.cyclonedx_jvm.maven_plugin_coordinate",
            lambda: "org.cyclonedx:cyclonedx-maven-plugin:9.9.9",
        )
        # generate() materialises the bundle before _run, so reading the
        # wrapper map costs nothing there. Calling _run directly skips that,
        # and an unanswered read would fetch a JDK to learn what mvnw means.
        monkeypatch.setattr(
            "sbomify_action._generation.generators.cyclonedx_jvm.bundle_wrappers",
            lambda _provider: {"maven": {"script": "mvnw", "tool": "mvn"}},
        )
        CycloneDXMavenGenerator()._run(tmp_path, tmp_path / "out.json")
        return captured["cmd"]

    def test_the_reactor_is_not_restricted_to_the_aggregator(self, tmp_path, monkeypatch):
        cmd = self._command(tmp_path, monkeypatch)
        assert "-N" not in cmd, "-N leaves makeAggregateBom a reactor of one module"
        assert "--non-recursive" not in cmd

    def test_the_aggregate_goal_is_what_runs(self, tmp_path, monkeypatch):
        """Aggregating is the whole point; makeBom alone would miss the modules."""
        cmd = self._command(tmp_path, monkeypatch)
        assert any(part.endswith(":makeAggregateBom") for part in cmd), cmd

    def test_no_lifecycle_phase_is_requested(self, tmp_path, monkeypatch):
        """Naming the goal directly is what keeps this from compiling the tree.

        The concern behind `-N` was real -- nobody wants an SBOM run to build
        every module -- it was just answered with the wrong flag.
        """
        cmd = self._command(tmp_path, monkeypatch)
        for phase in ("package", "install", "compile", "verify", "test"):
            assert phase not in cmd, f"{phase} would build the modules"
