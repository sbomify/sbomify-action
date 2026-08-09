"""PHP: the Composer toolchain, and when it is worth fetching.

sbom-tools has published a php bundle -- cdxgen with a PHP runtime and
Composer -- for some time, but nothing in this repository declared it. So
`bundle_for("composer")` returned None, `can_provide` said no, and a PHP
project with no committed composer.lock fell through to syft, which wrote a
document with zero components and exited 0.

That is the common case rather than a corner: PHP libraries gitignore
composer.lock, leaving the consuming application to resolve it.
"""

import pytest

from sbomify_action._generation.generators import cdxgen as cdxgen_module
from sbomify_action._generation.generators.cdxgen import CdxgenFsGenerator
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action.runtimes import can_provide
from sbomify_action.tool_manifest import bundle_for, load_bundles


class TestTheBundleIsDeclared:
    def test_composer_resolves_to_the_php_bundle(self):
        bundle = bundle_for("composer")
        assert bundle is not None, "nothing would ever fetch Composer"
        assert bundle.name == "php"

    def test_php_resolves_to_the_php_bundle(self):
        bundle = bundle_for("php")
        assert bundle is not None
        assert bundle.name == "php"

    def test_the_generator_can_say_it_is_able_to_provide_composer(self):
        """can_provide is what a generator asks before claiming an input."""
        assert can_provide("composer")

    def test_the_bundle_does_not_re_provide_cdxgen_or_syft(self):
        """It carries both, but [bundle.cdxgen] already claims cdxgen.

        load_bundles refuses two providers for one tool, so declaring them
        here would break every manifest load, not just PHP.
        """
        php = load_bundles()["php"]
        assert "cdxgen" not in php.provides
        assert "syft" not in php.provides


class TestWhenItIsFetched:
    @staticmethod
    def _run(tmp_path, monkeypatch, filename: str, body: str) -> list[str]:
        fetched: list[str] = []
        monkeypatch.setattr(cdxgen_module, "ensure_php_installed", lambda: fetched.append("php"))
        monkeypatch.setattr(cdxgen_module, "ensure_runtime", lambda _tool: None)
        monkeypatch.setattr(cdxgen_module, "run_command", lambda *a, **k: None)

        source = tmp_path / filename
        source.write_text(body)
        output = tmp_path / "o.json"
        output.write_text('{"components": []}')

        CdxgenFsGenerator().generate(
            GenerationInput(lock_file=str(source), output_file=str(output), output_format="cyclonedx")
        )
        return fetched

    def test_a_manifest_fetches_composer(self, tmp_path, monkeypatch):
        """Without it cdxgen stops at "No composer version found"."""
        assert self._run(tmp_path, monkeypatch, "composer.json", '{"require": {}}') == ["php"]

    def test_a_lock_file_does_not(self, tmp_path, monkeypatch):
        """cdxgen parses composer.lock as data and never shells out.

        The same distinction the .NET gate draws: pay for a toolchain only
        where it changes the answer.
        """
        assert self._run(tmp_path, monkeypatch, "composer.lock", '{"packages": []}') == []

    @pytest.mark.parametrize("name", ["package.json", "go.mod", "Cargo.toml"])
    def test_other_ecosystems_do_not(self, tmp_path, monkeypatch, name):
        assert self._run(tmp_path, monkeypatch, name, "{}") == []
