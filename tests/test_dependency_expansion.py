"""Tests for the dependency expansion subsystem."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from sbomify_action._dependency_expansion import (
    DiscoveredDependency,
    ExpansionResult,
    create_default_registry,
    expand_sbom_dependencies,
    normalize_python_package_name,
)
from sbomify_action._dependency_expansion.enricher import DependencyEnricher
from sbomify_action._dependency_expansion.expanders.pipdeptree import PipdeptreeExpander
from sbomify_action._dependency_expansion.registry import ExpanderRegistry


class TestNormalizePythonPackageName:
    """Tests for normalize_python_package_name function."""

    def test_lowercase(self):
        """Test that names are lowercased."""
        assert normalize_python_package_name("Django") == "django"
        assert normalize_python_package_name("REQUESTS") == "requests"

    def test_hyphen_to_underscore(self):
        """Test that hyphens become underscores."""
        assert normalize_python_package_name("my-package") == "my_package"
        assert normalize_python_package_name("some-long-name") == "some_long_name"

    def test_dot_to_underscore(self):
        """Test that dots become underscores."""
        assert normalize_python_package_name("zope.interface") == "zope_interface"

    def test_mixed_normalization(self):
        """Test mixed case with various separators."""
        assert normalize_python_package_name("My-Package.Name") == "my_package_name"


class TestDiscoveredDependency:
    """Tests for DiscoveredDependency dataclass."""

    def test_basic_creation(self):
        """Test basic dataclass creation."""
        dep = DiscoveredDependency(
            name="urllib3",
            version="2.0.4",
            purl="pkg:pypi/urllib3@2.0.4",
            parent="requests",
            depth=1,
        )
        assert dep.name == "urllib3"
        assert dep.version == "2.0.4"
        assert dep.purl == "pkg:pypi/urllib3@2.0.4"
        assert dep.parent == "requests"
        assert dep.depth == 1
        assert dep.ecosystem == "pypi"  # Default

    def test_defaults(self):
        """Test default values."""
        dep = DiscoveredDependency(
            name="certifi",
            version="2023.7.22",
            purl="pkg:pypi/certifi@2023.7.22",
        )
        assert dep.parent is None
        assert dep.depth == 1
        assert dep.ecosystem == "pypi"


class TestExpansionResult:
    """Tests for ExpansionResult dataclass."""

    def test_basic_creation(self):
        """Test basic dataclass creation."""
        result = ExpansionResult(
            original_count=5,
            discovered_count=10,
            added_count=8,
            dependencies=[],
            source="pipdeptree",
        )
        assert result.original_count == 5
        assert result.discovered_count == 10
        assert result.added_count == 8
        assert result.source == "pipdeptree"

    def test_source_required(self):
        """Test that source is a required field."""
        # source must be provided explicitly - no default value
        result = ExpansionResult(
            original_count=0,
            discovered_count=0,
            added_count=0,
            dependencies=[],
            source="test-expander",
        )
        assert result.source == "test-expander"


class TestPipdeptreeExpander:
    """Tests for PipdeptreeExpander class."""

    def test_name(self):
        """Test expander name."""
        expander = PipdeptreeExpander()
        assert expander.name == "pipdeptree"

    def test_priority(self):
        """Test expander priority."""
        expander = PipdeptreeExpander()
        assert expander.priority == 10

    def test_ecosystems(self):
        """Test supported ecosystems."""
        expander = PipdeptreeExpander()
        assert "pypi" in expander.ecosystems

    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree._PIPDEPTREE_AVAILABLE", True)
    def test_supports_requirements_txt(self):
        """Test that requirements.txt is supported."""
        expander = PipdeptreeExpander()
        assert expander.supports(Path("requirements.txt"))

    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree._PIPDEPTREE_AVAILABLE", True)
    def test_not_supports_other_lockfiles(self):
        """Test that other lockfiles are not supported."""
        expander = PipdeptreeExpander()
        assert not expander.supports(Path("poetry.lock"))
        assert not expander.supports(Path("Pipfile.lock"))
        assert not expander.supports(Path("uv.lock"))

    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree._PIPDEPTREE_AVAILABLE", False)
    def test_not_supports_when_tool_unavailable(self):
        """Test that nothing is supported when pipdeptree is unavailable."""
        expander = PipdeptreeExpander()
        assert not expander.supports(Path("requirements.txt"))

    def test_parse_requirements_basic(self, tmp_path):
        """Test parsing basic requirements.txt."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            """
requests==2.31.0
django>=4.0
flask
"""
        )

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert "requests" in deps
        assert deps["requests"] == "2.31.0"
        assert "django" in deps
        assert deps["django"] is None  # No exact version
        assert "flask" in deps
        assert deps["flask"] is None

    def test_parse_requirements_with_comments(self, tmp_path):
        """Test parsing requirements.txt with comments."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            """
# This is a comment
requests==2.31.0

# Another comment
django>=4.0  # inline comment
"""
        )

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert "requests" in deps
        assert "django" in deps
        assert len(deps) == 2

    def test_parse_requirements_with_extras(self, tmp_path):
        """Test parsing requirements with extras."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests[security]==2.31.0\n")

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert "requests" in deps
        assert deps["requests"] == "2.31.0"

    def test_parse_requirements_with_options(self, tmp_path):
        """Test that option lines are skipped."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            """
-r base.txt
--index-url https://pypi.org/simple
-e git+https://github.com/user/repo.git
requests==2.31.0
"""
        )

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        # Only requests should be parsed
        assert len(deps) == 1
        assert "requests" in deps

    def test_parse_requirements_with_markers(self, tmp_path):
        """Test parsing requirements with environment markers."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text('requests==2.31.0; python_version >= "3.6"\n')

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert "requests" in deps
        assert deps["requests"] == "2.31.0"

    def test_collect_transitives(self):
        """Test transitive dependency collection."""
        expander = PipdeptreeExpander()

        # Simulated pipdeptree JSON tree
        tree = [
            {
                "package_name": "requests",
                "installed_version": "2.31.0",
                "dependencies": [
                    {
                        "package_name": "urllib3",
                        "installed_version": "2.0.4",
                        "dependencies": [],
                    },
                    {
                        "package_name": "certifi",
                        "installed_version": "2023.7.22",
                        "dependencies": [],
                    },
                ],
            }
        ]

        direct_names = {"requests"}
        discovered: list[DiscoveredDependency] = []
        seen_package_versions: set[str] = set()

        for pkg in tree:
            expander._collect_transitives(pkg, direct_names, discovered, seen_package_versions, depth=0)

        # Should discover urllib3 and certifi as transitives
        assert len(discovered) == 2
        purl_names = {d.purl for d in discovered}
        assert "pkg:pypi/urllib3@2.0.4" in purl_names
        assert "pkg:pypi/certifi@2023.7.22" in purl_names

        # Both should have requests as parent
        for dep in discovered:
            assert dep.parent == "requests"
            assert dep.depth == 1


class TestEnvironmentVerification:
    """The guard that stops expansion reading an unrelated environment.

    pipdeptree reports whatever the running interpreter has installed.
    Under pipx/uvx (and in the Docker image) that interpreter holds
    sbomify-action's own dependencies rather than the scanned project's,
    and because this tool depends on requests, the lookups still resolve
    — so the expansion silently reports our versions as the project's.
    """

    #: A tree pipdeptree would return if it were allowed to run. Its
    #: presence in these tests proves the guard, not an empty tree, is
    #: what suppresses discovery.
    TREE = [
        {
            "package_name": "requests",
            "installed_version": "2.34.2",
            "dependencies": [
                {"package_name": "urllib3", "installed_version": "2.7.0", "dependencies": []},
            ],
        }
    ]

    def _requirements(self, tmp_path, body: str) -> Path:
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(body)
        return req_file

    def test_skips_when_pinned_versions_disagree(self, tmp_path):
        """The reported bug: right package names, wrong environment."""
        req_file = self._requirements(tmp_path, "click==8.1.7\nrequests==2.32.3\n")
        expander = PipdeptreeExpander()

        with (
            patch.object(expander, "_installed_versions", return_value={"click": "8.4.2", "requests": "2.34.2"}),
            patch.object(expander, "_run_pipdeptree", return_value=self.TREE) as run_tree,
        ):
            assert expander.expand(req_file) == []
            # The expensive query is never reached — the guard runs first.
            run_tree.assert_not_called()

    def test_skips_when_a_direct_dependency_is_not_installed(self, tmp_path):
        """A lockfile whose packages are largely absent is another project."""
        req_file = self._requirements(tmp_path, "click==8.1.7\nrequests==2.32.3\ndjango==5.0\n")
        expander = PipdeptreeExpander()

        with (
            patch.object(expander, "_installed_versions", return_value={"click": "8.1.7", "requests": "2.32.3"}),
            patch.object(expander, "_run_pipdeptree", return_value=self.TREE),
        ):
            assert expander.expand(req_file) == []

    def test_skips_when_nothing_is_pinned(self, tmp_path):
        """Without an == pin there is no evidence the environment matches."""
        req_file = self._requirements(tmp_path, "click\nrequests>=2.0\n")
        expander = PipdeptreeExpander()

        with (
            patch.object(expander, "_installed_versions", return_value={"click": "8.4.2", "requests": "2.34.2"}),
            patch.object(expander, "_run_pipdeptree", return_value=self.TREE),
        ):
            assert expander.expand(req_file) == []

    def test_expands_when_environment_matches(self, tmp_path):
        """A genuinely shared environment must still be expanded."""
        req_file = self._requirements(tmp_path, "requests==2.34.2\n")
        expander = PipdeptreeExpander()

        with (
            patch.object(expander, "_installed_versions", return_value={"requests": "2.34.2"}),
            patch.object(expander, "_run_pipdeptree", return_value=self.TREE),
        ):
            discovered = expander.expand(req_file)

        assert [d.purl for d in discovered] == ["pkg:pypi/urllib3@2.7.0"]

    def test_normalized_names_match_across_spellings(self, tmp_path):
        """A pin and its installed metadata may spell the name differently."""
        req_file = self._requirements(tmp_path, "charset-normalizer==3.4.9\n")
        expander = PipdeptreeExpander()

        with (
            patch.object(expander, "_installed_versions", return_value={"charset_normalizer": "3.4.9"}),
            patch.object(expander, "_run_pipdeptree", return_value=[]),
        ):
            # Verification passes (so we reach the tree query and its
            # empty result), rather than failing as a missing package.
            assert expander.expand(req_file) == []

    def test_skips_when_installed_versions_unavailable(self, tmp_path):
        """pipdeptree unreadable — expand rather than guess."""
        req_file = self._requirements(tmp_path, "requests==2.34.2\n")
        expander = PipdeptreeExpander()

        with (
            patch.object(expander, "_installed_versions", return_value=None),
            patch.object(expander, "_run_pipdeptree", return_value=self.TREE) as run_tree,
        ):
            assert expander.expand(req_file) == []
            run_tree.assert_not_called()

    def test_installed_versions_parses_flat_json(self):
        """The flat --json shape, which nests versions under 'package'."""
        payload = json.dumps(
            [
                {"package": {"key": "requests", "package_name": "requests", "installed_version": "2.34.2"}},
                {
                    "package": {
                        "key": "charset-normalizer",
                        "package_name": "charset-normalizer",
                        "installed_version": "3.4.9",
                    }
                },
            ]
        )
        expander = PipdeptreeExpander()

        with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=payload, stderr="")):
            versions = expander._installed_versions()

        assert versions == {"requests": "2.34.2", "charset_normalizer": "3.4.9"}

    def test_installed_versions_returns_none_on_bad_json(self):
        """Unparseable output is reported as unknown, not as 'nothing installed'."""
        expander = PipdeptreeExpander()

        with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout="", stderr="")):
            assert expander._installed_versions() is None

    def test_installed_versions_returns_none_on_failure(self):
        """A nonzero exit is reported as unknown too."""
        expander = PipdeptreeExpander()

        with patch("subprocess.run", return_value=MagicMock(returncode=1, stdout="", stderr="boom")):
            assert expander._installed_versions() is None


class TestExpanderRegistry:
    """Tests for ExpanderRegistry class."""

    def test_register_and_get(self):
        """Test registering and retrieving expanders."""
        registry = ExpanderRegistry()
        expander = PipdeptreeExpander()

        registry.register(expander)

        # Mock pipdeptree as available for this test
        with patch.object(expander, "supports", return_value=True):
            result = registry.get_expander_for(Path("requirements.txt"))
            assert result is not None
            assert result.name == "pipdeptree"

    def test_no_expander_found(self):
        """Test when no expander supports the lockfile."""
        registry = ExpanderRegistry()
        result = registry.get_expander_for(Path("unknown.lock"))
        assert result is None

    def test_priority_ordering(self):
        """Test that expanders are selected by priority."""
        registry = ExpanderRegistry()

        # Create mock expanders with different priorities
        low_priority = MagicMock()
        low_priority.name = "low"
        low_priority.priority = 100
        low_priority.supports.return_value = True

        high_priority = MagicMock()
        high_priority.name = "high"
        high_priority.priority = 10
        high_priority.supports.return_value = True

        registry.register(low_priority)
        registry.register(high_priority)

        result = registry.get_expander_for(Path("test.txt"))
        assert result.name == "high"


class TestDefaultRegistry:
    """Tests for default registry creation."""

    def test_create_default_registry(self):
        """Test that default registry is created with pipdeptree."""
        registry = create_default_registry()
        assert "pipdeptree" in registry.registered_expanders


class TestExpandSbomDependencies:
    """Integration tests for expand_sbom_dependencies function."""

    def test_returns_empty_result_for_unsupported_lockfile(self, tmp_path):
        """Test that unsupported lockfiles return empty result."""
        # Create a minimal SBOM
        sbom_file = tmp_path / "sbom.json"
        sbom_file.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [],
                }
            )
        )

        # Create an unsupported lockfile
        lock_file = tmp_path / "unknown.lock"
        lock_file.write_text("some content")

        result = expand_sbom_dependencies(str(sbom_file), str(lock_file))

        assert result.added_count == 0
        assert result.discovered_count == 0
        assert result.source == "none"

    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree._PIPDEPTREE_AVAILABLE", True)
    @patch("sbomify_action._dependency_expansion.expanders.pipdeptree.PipdeptreeExpander.can_expand")
    def test_skips_when_cannot_expand(self, mock_can_expand, tmp_path):
        """Test that expansion is skipped when prerequisites not met."""
        mock_can_expand.return_value = False

        # Create a minimal SBOM
        sbom_file = tmp_path / "sbom.json"
        original_content = json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "components": [],
            }
        )
        sbom_file.write_text(original_content)

        # Create requirements.txt
        lock_file = tmp_path / "requirements.txt"
        lock_file.write_text("requests==2.31.0")

        result = expand_sbom_dependencies(str(sbom_file), str(lock_file))

        assert result.added_count == 0
        assert result.discovered_count == 0
        assert result.source == "pipdeptree"

        # Verify SBOM file was not modified
        assert sbom_file.read_text() == original_content


class TestOriginalCountWhenNoDiscoveries:
    """Tests that original_count is accurate even when no deps are discovered."""

    def test_original_count_cyclonedx_no_discoveries(self, tmp_path):
        """Test original_count reflects SBOM components when no deps discovered."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
                {"type": "library", "name": "flask", "version": "3.0.0", "purl": "pkg:pypi/flask@3.0.0"},
            ],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = []  # No discoveries

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        assert result.original_count == 2
        assert result.added_count == 0
        assert result.discovered_count == 0

    def test_original_count_spdx_no_discoveries(self, tmp_path):
        """Test original_count reflects SBOM packages when no deps discovered."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "packages": [
                {"SPDXID": "SPDXRef-Package-requests", "name": "requests", "versionInfo": "2.31.0"},
                {"SPDXID": "SPDXRef-Package-flask", "name": "flask", "versionInfo": "3.0.0"},
                {"SPDXID": "SPDXRef-Package-django", "name": "django", "versionInfo": "5.0"},
            ],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = []  # No discoveries

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        assert result.original_count == 3
        assert result.added_count == 0
        assert result.discovered_count == 0


class TestEnrichCycloneDX:
    """Tests for CycloneDX SBOM enrichment."""

    def _make_discovered(self, name="urllib3", version="2.0.4", parent="requests"):
        return [
            DiscoveredDependency(
                name=name,
                version=version,
                purl=f"pkg:pypi/{name}@{version}",
                parent=parent,
                depth=1,
            )
        ]

    def test_adds_transitive_deps_to_cyclonedx(self, tmp_path):
        """Test that transitive dependencies are added to CycloneDX SBOM."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "requests",
                    "version": "2.31.0",
                    "purl": "pkg:pypi/requests@2.31.0",
                }
            ],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        # Mock the expander to return our discovered deps
        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = self._make_discovered()

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        assert result.added_count == 1
        assert result.discovered_count == 1
        assert result.original_count == 1
        assert result.source == "pipdeptree"

        # Verify the SBOM was updated
        updated = json.loads(sbom_file.read_text())
        component_names = [c["name"] for c in updated.get("components", [])]
        assert "urllib3" in component_names

    def test_deduplicates_existing_purls(self, tmp_path):
        """Test that existing PURLs are not duplicated."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "urllib3",
                    "version": "2.0.4",
                    "purl": "pkg:pypi/urllib3@2.0.4",
                }
            ],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = self._make_discovered()

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        assert result.added_count == 0
        assert result.discovered_count == 1

    def test_empty_components_cyclonedx(self, tmp_path):
        """Test enrichment when SBOM has no components."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = self._make_discovered()

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        assert result.added_count == 1
        assert result.original_count == 0


class TestEnrichSPDX:
    """Tests for SPDX SBOM enrichment."""

    def _make_discovered(self, name="urllib3", version="2.0.4", parent="requests"):
        return [
            DiscoveredDependency(
                name=name,
                version=version,
                purl=f"pkg:pypi/{name}@{version}",
                parent=parent,
                depth=1,
            )
        ]

    def test_adds_transitive_deps_to_spdx(self, tmp_path):
        """Test that transitive dependencies are added to SPDX SBOM."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-requests-2.31.0",
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "downloadLocation": "NOASSERTION",
                }
            ],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = self._make_discovered()

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        assert result.added_count == 1
        assert result.discovered_count == 1
        assert result.source == "pipdeptree"

        # Verify the SBOM was updated
        updated = json.loads(sbom_file.read_text())
        pkg_names = [p["name"] for p in updated["packages"]]
        assert "urllib3" in pkg_names

        # Verify SPDXID was generated
        new_pkg = [p for p in updated["packages"] if p["name"] == "urllib3"][0]
        assert new_pkg["SPDXID"].startswith("SPDXRef-")

        # Verify PURL in external refs
        assert any(ref["referenceLocator"] == "pkg:pypi/urllib3@2.0.4" for ref in new_pkg["externalRefs"])

    def test_deduplicates_existing_spdx_packages(self, tmp_path):
        """Test that existing packages are not duplicated in SPDX."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-urllib3-2.0.4",
                    "name": "urllib3",
                    "versionInfo": "2.0.4",
                    "downloadLocation": "NOASSERTION",
                }
            ],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = self._make_discovered()

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        assert result.added_count == 0
        assert result.discovered_count == 1

    def test_empty_packages_spdx(self, tmp_path):
        """Test enrichment when SPDX SBOM has no packages."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "packages": [],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = self._make_discovered()

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        assert result.added_count == 1
        assert result.original_count == 0


class TestParseRequirementsEdgeCases:
    """Tests for requirements.txt parsing edge cases."""

    def test_skips_url_requirements(self, tmp_path):
        """Test that URL/VCS requirements are skipped."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text(
            "git+https://github.com/user/repo.git\nhttps://example.com/package.tar.gz\nrequests==2.31.0\n"
        )

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert len(deps) == 1
        assert "requests" in deps

    def test_skips_pep508_direct_references(self, tmp_path):
        """Test that PEP 508 direct references are skipped."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("mypackage @ https://example.com/mypackage-1.0.tar.gz\nrequests==2.31.0\n")

        expander = PipdeptreeExpander()
        deps = expander._parse_requirements(req_file)

        assert len(deps) == 1
        assert "requests" in deps


class TestSpdxRelationships:
    """Tests that SPDX enrichment adds proper relationships."""

    def _make_discovered(self, name="urllib3", version="2.0.4", parent="requests"):
        return [
            DiscoveredDependency(
                name=name,
                version=version,
                purl=f"pkg:pypi/{name}@{version}",
                parent=parent,
                depth=1,
            )
        ]

    def test_describes_relationship_added(self, tmp_path):
        """Test that DESCRIBES relationships are added for new packages."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "packages": [{"SPDXID": "SPDXRef-Package-requests", "name": "requests", "versionInfo": "2.31.0"}],
            "relationships": [],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = self._make_discovered()

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        updated = json.loads(sbom_file.read_text())
        rels = updated.get("relationships", [])

        # Should have a DESCRIBES relationship
        describes = [r for r in rels if r["relationshipType"] == "DESCRIBES"]
        assert len(describes) == 1
        assert describes[0]["spdxElementId"] == "SPDXRef-DOCUMENT"

    def test_dependency_of_relationship_added(self, tmp_path):
        """Test that DEPENDENCY_OF relationships are added when parent is known."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "packages": [{"SPDXID": "SPDXRef-Package-requests", "name": "requests", "versionInfo": "2.31.0"}],
            "relationships": [],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = self._make_discovered()

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        updated = json.loads(sbom_file.read_text())
        rels = updated.get("relationships", [])

        # Should have a DEPENDENCY_OF relationship
        dep_of = [r for r in rels if r["relationshipType"] == "DEPENDENCY_OF"]
        assert len(dep_of) == 1
        assert dep_of[0]["relatedSpdxElement"] == "SPDXRef-Package-requests"


class TestSpdxIdSanitization:
    """Tests that SPDX IDs are properly sanitized."""

    def test_plus_in_version_is_sanitized(self, tmp_path):
        """PEP 440 local versions with + should be sanitized in SPDX IDs."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test",
            "packages": [],
            "relationships": [],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = [
            DiscoveredDependency(
                name="mypackage",
                version="1.0+ubuntu1",
                purl="pkg:pypi/mypackage@1.0+ubuntu1",
                depth=1,
            )
        ]

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))

        updated = json.loads(sbom_file.read_text())
        new_pkg = updated["packages"][0]

        # SPDX ID must only contain [a-zA-Z0-9.-]
        import re

        assert re.match(r"^SPDXRef-[a-zA-Z0-9.\-]+$", new_pkg["SPDXID"]), f"Invalid SPDX ID: {new_pkg['SPDXID']}"


class TestExpandSbomSpdx3AndUnknown:
    """Tests for SPDX 3 and unknown format paths in expand_sbom."""

    def test_spdx3_returns_zero_added(self, tmp_path):
        """SPDX 3 SBOMs should return added_count=0 (not yet supported)."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [{"type": "software_Package", "spdxId": "urn:spdx:pkg1", "name": "foo"}],
        }
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = [
            DiscoveredDependency(name="bar", version="1.0", purl="pkg:pypi/bar@1.0", depth=1)
        ]

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))
        assert result.added_count == 0
        assert result.discovered_count == 1
        assert result.original_count == 1

    def test_unknown_format_returns_zero_added(self, tmp_path):
        """Unknown SBOM formats should return added_count=0."""
        sbom_file = tmp_path / "sbom.json"
        sbom_data = {"unknownFormat": True, "data": []}
        sbom_file.write_text(json.dumps(sbom_data))

        mock_expander = MagicMock()
        mock_expander.name = "pipdeptree"
        mock_expander.priority = 10
        mock_expander.supports.return_value = True
        mock_expander.can_expand.return_value = True
        mock_expander.expand.return_value = [
            DiscoveredDependency(name="bar", version="1.0", purl="pkg:pypi/bar@1.0", depth=1)
        ]

        registry = ExpanderRegistry()
        registry.register(mock_expander)
        enricher = DependencyEnricher(registry=registry)

        result = enricher.expand_sbom(str(sbom_file), str(tmp_path / "requirements.txt"))
        assert result.added_count == 0
        assert result.discovered_count == 1
