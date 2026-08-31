"""Tests for CI provider VCS augmentation."""

import os
import tempfile
import unittest
from unittest.mock import patch

from sbomify_action._augmentation.metadata import AugmentationMetadata
from sbomify_action._augmentation.providers import (
    BitbucketPipelinesProvider,
    DockerImageProvider,
    GitHubActionsProvider,
    GitLabCIProvider,
    TeamCityProvider,
    is_vcs_augmentation_disabled,
)
from sbomify_action._augmentation.providers.teamcity import (
    _parse_java_properties,
    _read_properties_file,
)
from sbomify_action._augmentation.utils import (
    build_vcs_url_with_commit,
    normalize_repo_url,
    strip_ref_prefix,
    truncate_sha,
)


class TestIsVcsAugmentationDisabled(unittest.TestCase):
    """Tests for the VCS augmentation disable check."""

    @patch.dict(os.environ, {}, clear=True)
    def test_enabled_when_not_set(self):
        """VCS augmentation is enabled when env var is not set."""
        self.assertFalse(is_vcs_augmentation_disabled())

    @patch.dict(os.environ, {"DISABLE_VCS_AUGMENTATION": "true"}, clear=True)
    def test_disabled_when_true(self):
        """VCS augmentation is disabled when env var is 'true'."""
        self.assertTrue(is_vcs_augmentation_disabled())

    @patch.dict(os.environ, {"DISABLE_VCS_AUGMENTATION": "TRUE"}, clear=True)
    def test_disabled_when_true_uppercase(self):
        """VCS augmentation is disabled when env var is 'TRUE' (case-insensitive)."""
        self.assertTrue(is_vcs_augmentation_disabled())

    @patch.dict(os.environ, {"DISABLE_VCS_AUGMENTATION": "1"}, clear=True)
    def test_disabled_when_one(self):
        """VCS augmentation is disabled when env var is '1'."""
        self.assertTrue(is_vcs_augmentation_disabled())

    @patch.dict(os.environ, {"DISABLE_VCS_AUGMENTATION": "yes"}, clear=True)
    def test_disabled_when_yes(self):
        """VCS augmentation is disabled when env var is 'yes'."""
        self.assertTrue(is_vcs_augmentation_disabled())

    @patch.dict(os.environ, {"DISABLE_VCS_AUGMENTATION": "false"}, clear=True)
    def test_enabled_when_false(self):
        """VCS augmentation is enabled when env var is 'false'."""
        self.assertFalse(is_vcs_augmentation_disabled())

    @patch.dict(os.environ, {"DISABLE_VCS_AUGMENTATION": ""}, clear=True)
    def test_enabled_when_empty(self):
        """VCS augmentation is enabled when env var is empty."""
        self.assertFalse(is_vcs_augmentation_disabled())


class TestTruncateSha(unittest.TestCase):
    """Tests for the truncate_sha helper function."""

    def test_truncates_long_sha(self):
        """Long SHA is truncated to default 7 characters."""
        result = truncate_sha("abc123def456789")
        self.assertEqual(result, "abc123d")

    def test_truncates_to_custom_length(self):
        """SHA is truncated to custom length."""
        result = truncate_sha("abc123def456789", 12)
        self.assertEqual(result, "abc123def456")

    def test_short_sha_unchanged(self):
        """Short SHA is returned unchanged."""
        result = truncate_sha("abc", 7)
        self.assertEqual(result, "abc")

    def test_exact_length_sha(self):
        """SHA exactly matching length is returned unchanged."""
        result = truncate_sha("abc1234", 7)
        self.assertEqual(result, "abc1234")

    def test_none_returns_unknown(self):
        """None returns 'unknown'."""
        result = truncate_sha(None)
        self.assertEqual(result, "unknown")

    def test_empty_string_returns_unknown(self):
        """Empty string returns 'unknown'."""
        result = truncate_sha("")
        self.assertEqual(result, "unknown")


class TestGitHubActionsProvider(unittest.TestCase):
    """Tests for GitHubActionsProvider."""

    def setUp(self):
        self.provider = GitHubActionsProvider()

    def test_provider_attributes(self):
        """Test provider has correct name and priority."""
        self.assertEqual(self.provider.name, "github-actions")
        self.assertEqual(self.provider.priority, 20)

    @patch.dict(os.environ, {}, clear=True)
    def test_returns_none_when_not_in_github_actions(self):
        """Provider returns None when not in GitHub Actions."""
        result = self.provider.fetch()
        self.assertIsNone(result)

    @patch.dict(
        os.environ,
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "abc123def456",
            "GITHUB_REF_NAME": "main",
        },
        clear=True,
    )
    def test_extracts_vcs_info_from_github_actions(self):
        """Provider extracts VCS info from GitHub Actions env vars."""
        result = self.provider.fetch()

        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://github.com/owner/repo")
        self.assertEqual(result.vcs_commit_sha, "abc123def456")
        self.assertEqual(result.vcs_ref, "main")
        self.assertEqual(result.vcs_commit_url, "https://github.com/owner/repo/commit/abc123def456")
        self.assertEqual(result.source, "github-actions")
        # CycloneDX 1.7 meta:enum aligns a CI lockfile / manifest scan
        # with "pre-build" ("information obtained prior to a build
        # process … may contain source files, development artifacts and
        # manifests"). The DockerImageProvider overrides to "post-build"
        # when DOCKER_IMAGE is set; json_config can still force anything.
        self.assertEqual(result.lifecycle_phase, "pre-build")

    @patch.dict(
        os.environ,
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SERVER_URL": "https://github.mycompany.com",
            "GITHUB_REPOSITORY": "org/internal-repo",
            "GITHUB_SHA": "fedcba987654",
            "GITHUB_REF": "refs/heads/feature/test",
        },
        clear=True,
    )
    def test_supports_github_enterprise_server(self):
        """Provider supports GitHub Enterprise Server via GITHUB_SERVER_URL."""
        result = self.provider.fetch()

        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://github.mycompany.com/org/internal-repo")
        self.assertEqual(result.vcs_commit_url, "https://github.mycompany.com/org/internal-repo/commit/fedcba987654")
        # ref should be cleaned up from refs/heads/ prefix
        self.assertEqual(result.vcs_ref, "feature/test")

    @patch.dict(
        os.environ,
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "abc123",
            "GITHUB_REF": "refs/tags/v1.0.0",
        },
        clear=True,
    )
    def test_cleans_up_tag_ref(self):
        """Provider removes refs/tags/ prefix from ref."""
        result = self.provider.fetch()

        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_ref, "v1.0.0")

    @patch.dict(
        os.environ,
        {
            "GITHUB_ACTIONS": "true",
            "DISABLE_VCS_AUGMENTATION": "true",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_SHA": "abc123",
        },
        clear=True,
    )
    def test_respects_disable_vcs_augmentation(self):
        """Provider returns None when VCS augmentation is disabled."""
        result = self.provider.fetch()
        self.assertIsNone(result)

    @patch.dict(
        os.environ,
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_REPOSITORY": "owner/repo",
            # GITHUB_SHA and GITHUB_REF_NAME intentionally missing
        },
        clear=True,
    )
    def test_handles_missing_sha_and_ref(self):
        """Provider handles missing SHA and ref gracefully."""
        result = self.provider.fetch()

        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://github.com/owner/repo")
        self.assertIsNone(result.vcs_commit_sha)
        self.assertIsNone(result.vcs_ref)
        self.assertIsNone(result.vcs_commit_url)


class TestGitLabCIProvider(unittest.TestCase):
    """Tests for GitLabCIProvider."""

    def setUp(self):
        self.provider = GitLabCIProvider()

    def test_provider_attributes(self):
        """Test provider has correct name and priority."""
        self.assertEqual(self.provider.name, "gitlab-ci")
        self.assertEqual(self.provider.priority, 20)

    @patch.dict(os.environ, {}, clear=True)
    def test_returns_none_when_not_in_gitlab_ci(self):
        """Provider returns None when not in GitLab CI."""
        result = self.provider.fetch()
        self.assertIsNone(result)

    @patch.dict(
        os.environ,
        {
            "GITLAB_CI": "true",
            "CI_PROJECT_URL": "https://gitlab.com/owner/repo",
            "CI_COMMIT_SHA": "abc123def456",
            "CI_COMMIT_REF_NAME": "main",
        },
        clear=True,
    )
    def test_extracts_vcs_info_from_gitlab_ci(self):
        """Provider extracts VCS info from GitLab CI env vars."""
        result = self.provider.fetch()

        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://gitlab.com/owner/repo")
        self.assertEqual(result.vcs_commit_sha, "abc123def456")
        self.assertEqual(result.vcs_ref, "main")
        self.assertEqual(result.vcs_commit_url, "https://gitlab.com/owner/repo/-/commit/abc123def456")
        self.assertEqual(result.source, "gitlab-ci")
        self.assertEqual(result.lifecycle_phase, "pre-build")

    @patch.dict(
        os.environ,
        {
            "GITLAB_CI": "true",
            "CI_SERVER_URL": "https://gitlab.mycompany.com",
            "CI_PROJECT_PATH": "org/internal-repo",
            "CI_COMMIT_SHA": "fedcba987654",
            "CI_COMMIT_REF_NAME": "develop",
        },
        clear=True,
    )
    def test_supports_self_managed_gitlab(self):
        """Provider supports self-managed GitLab via CI_SERVER_URL fallback."""
        result = self.provider.fetch()

        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://gitlab.mycompany.com/org/internal-repo")
        self.assertEqual(result.vcs_commit_url, "https://gitlab.mycompany.com/org/internal-repo/-/commit/fedcba987654")

    @patch.dict(
        os.environ,
        {
            "GITLAB_CI": "true",
            "DISABLE_VCS_AUGMENTATION": "true",
            "CI_PROJECT_URL": "https://gitlab.com/owner/repo",
            "CI_COMMIT_SHA": "abc123",
        },
        clear=True,
    )
    def test_respects_disable_vcs_augmentation(self):
        """Provider returns None when VCS augmentation is disabled."""
        result = self.provider.fetch()
        self.assertIsNone(result)

    @patch.dict(
        os.environ,
        {
            "GITLAB_CI": "true",
            # CI_PROJECT_URL, CI_SERVER_URL, and CI_PROJECT_PATH all missing
        },
        clear=True,
    )
    def test_returns_none_when_url_cannot_be_determined(self):
        """Provider returns None when project URL cannot be determined."""
        result = self.provider.fetch()
        self.assertIsNone(result)


class TestBitbucketPipelinesProvider(unittest.TestCase):
    """Tests for BitbucketPipelinesProvider."""

    def setUp(self):
        self.provider = BitbucketPipelinesProvider()

    def test_provider_attributes(self):
        """Test provider has correct name and priority."""
        self.assertEqual(self.provider.name, "bitbucket-pipelines")
        self.assertEqual(self.provider.priority, 20)

    @patch.dict(os.environ, {}, clear=True)
    def test_returns_none_when_not_in_bitbucket_pipelines(self):
        """Provider returns None when not in Bitbucket Pipelines."""
        result = self.provider.fetch()
        self.assertIsNone(result)

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_PIPELINE_UUID": "{12345}",
            "BITBUCKET_GIT_HTTP_ORIGIN": "https://bitbucket.org/owner/repo",
            "BITBUCKET_COMMIT": "abc123def456",
            "BITBUCKET_BRANCH": "main",
        },
        clear=True,
    )
    def test_extracts_vcs_info_from_bitbucket_pipelines(self):
        """Provider extracts VCS info from Bitbucket Pipelines env vars."""
        result = self.provider.fetch()

        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://bitbucket.org/owner/repo")
        self.assertEqual(result.vcs_commit_sha, "abc123def456")
        self.assertEqual(result.vcs_ref, "main")
        self.assertEqual(result.vcs_commit_url, "https://bitbucket.org/owner/repo/commits/abc123def456")
        self.assertEqual(result.source, "bitbucket-pipelines")
        self.assertEqual(result.lifecycle_phase, "pre-build")

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_PIPELINE_UUID": "{12345}",
            "BITBUCKET_WORKSPACE": "myworkspace",
            "BITBUCKET_REPO_SLUG": "myrepo",
            "BITBUCKET_COMMIT": "fedcba987654",
            "BITBUCKET_BRANCH": "develop",
        },
        clear=True,
    )
    def test_constructs_url_from_workspace_and_slug(self):
        """Provider constructs URL from workspace and repo slug when origin not available."""
        result = self.provider.fetch()

        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://bitbucket.org/myworkspace/myrepo")

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_PIPELINE_UUID": "{12345}",
            "BITBUCKET_GIT_HTTP_ORIGIN": "https://bitbucket.org/owner/repo",
            "BITBUCKET_COMMIT": "abc123",
            "BITBUCKET_TAG": "v1.0.0",
        },
        clear=True,
    )
    def test_uses_tag_when_branch_not_set(self):
        """Provider uses BITBUCKET_TAG when BITBUCKET_BRANCH is not set."""
        result = self.provider.fetch()

        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_ref, "v1.0.0")

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_PIPELINE_UUID": "{12345}",
            "DISABLE_VCS_AUGMENTATION": "true",
            "BITBUCKET_GIT_HTTP_ORIGIN": "https://bitbucket.org/owner/repo",
            "BITBUCKET_COMMIT": "abc123",
        },
        clear=True,
    )
    def test_respects_disable_vcs_augmentation(self):
        """Provider returns None when VCS augmentation is disabled."""
        result = self.provider.fetch()
        self.assertIsNone(result)

    @patch.dict(
        os.environ,
        {
            "BITBUCKET_PIPELINE_UUID": "{12345}",
            # BITBUCKET_GIT_HTTP_ORIGIN, BITBUCKET_WORKSPACE, and BITBUCKET_REPO_SLUG all missing
            "BITBUCKET_COMMIT": "abc123",
        },
        clear=True,
    )
    def test_returns_none_when_url_cannot_be_determined(self):
        """Provider returns None when repository URL cannot be determined."""
        result = self.provider.fetch()
        self.assertIsNone(result)


class TestDockerImageProvider(unittest.TestCase):
    """Tests for the DockerImageProvider lifecycle-phase default."""

    def setUp(self):
        self.provider = DockerImageProvider()

    def test_name_and_priority(self):
        """Provider name is "docker-image", priority beats CI (20) and
        loses to json_config (10)."""
        self.assertEqual(self.provider.name, "docker-image")
        self.assertEqual(self.provider.priority, 15)

    @patch.dict(os.environ, {}, clear=True)
    def test_returns_none_when_docker_image_not_set(self):
        """No DOCKER_IMAGE env var → provider yields no metadata."""
        self.assertIsNone(self.provider.fetch())

    @patch.dict(os.environ, {"DOCKER_IMAGE": "ubuntu:24.04"}, clear=True)
    def test_emits_post_build_for_container_image(self):
        """Scanning a built image is ``post-build`` per CDX 1.7
        ``meta:enum`` for the lifecycle ``phase`` property."""
        result = self.provider.fetch()
        self.assertIsNotNone(result)
        assert result is not None  # mypy
        self.assertEqual(result.lifecycle_phase, "post-build")
        self.assertEqual(result.source, "docker-image")

    @patch.dict(os.environ, {"DOCKER_IMAGE": ""}, clear=True)
    def test_empty_docker_image_env_yields_none(self):
        """Empty string env var is treated as absent."""
        self.assertIsNone(self.provider.fetch())

    @patch.dict(os.environ, {"DOCKER_IMAGE": "ubuntu:24.04"}, clear=True)
    def test_emits_only_lifecycle_phase_no_other_fields(self):
        """Provider must not touch vcs_url / authors / supplier / etc.
        The CI providers own VCS metadata; json_config and sbomify-api
        own org metadata; DockerImageProvider owns the single signal
        that its input is a built artifact. Keeping it narrow prevents
        surprise collisions in the merge."""
        result = self.provider.fetch()
        assert result is not None  # mypy
        self.assertEqual(result.lifecycle_phase, "post-build")
        # Explicit null-checks on every field the other providers set —
        # so if someone broadens DockerImageProvider later, this test
        # forces them to justify each addition.
        self.assertIsNone(result.supplier)
        self.assertIsNone(result.manufacturer)
        self.assertIsNone(result.authors)
        self.assertIsNone(result.licenses)
        self.assertIsNone(result.vcs_url)
        self.assertIsNone(result.vcs_commit_sha)
        self.assertIsNone(result.vcs_ref)
        self.assertIsNone(result.vcs_commit_url)
        self.assertIsNone(result.security_contact)
        self.assertIsNone(result.support_period_end)
        self.assertIsNone(result.release_date)
        self.assertIsNone(result.end_of_life)

    @patch.dict(
        os.environ,
        {
            "DOCKER_IMAGE": "registry.example.com/team/app:v1.2.3-arm64",
        },
        clear=True,
    )
    def test_accepts_arbitrary_image_reference_forms(self):
        """The image string is not parsed — any non-empty value triggers
        post-build. This keeps the provider robust across docker/podman/
        OCI registry variants without baking in a reference parser."""
        result = self.provider.fetch()
        assert result is not None
        self.assertEqual(result.lifecycle_phase, "post-build")


class TestAugmentationMetadataVcsFields(unittest.TestCase):
    """Tests for VCS fields in AugmentationMetadata."""

    def test_has_data_with_vcs_url(self):
        """has_data returns True when vcs_url is set."""
        metadata = AugmentationMetadata(vcs_url="https://github.com/owner/repo")
        self.assertTrue(metadata.has_data())

    def test_has_data_with_vcs_commit_sha(self):
        """has_data returns True when vcs_commit_sha is set."""
        metadata = AugmentationMetadata(vcs_commit_sha="abc123")
        self.assertTrue(metadata.has_data())

    def test_merge_vcs_fields(self):
        """VCS fields are properly merged."""
        metadata1 = AugmentationMetadata(
            source="provider1",
            vcs_url="https://github.com/owner/repo",
            vcs_ref="main",
        )
        metadata2 = AugmentationMetadata(
            source="provider2",
            vcs_commit_sha="abc123",
            vcs_commit_url="https://github.com/owner/repo/commit/abc123",
        )

        merged = metadata1.merge(metadata2)

        self.assertEqual(merged.vcs_url, "https://github.com/owner/repo")  # from metadata1
        self.assertEqual(merged.vcs_ref, "main")  # from metadata1
        self.assertEqual(merged.vcs_commit_sha, "abc123")  # from metadata2
        self.assertEqual(merged.vcs_commit_url, "https://github.com/owner/repo/commit/abc123")  # from metadata2

    def test_to_dict_includes_vcs_fields(self):
        """to_dict includes VCS fields."""
        metadata = AugmentationMetadata(
            vcs_url="https://github.com/owner/repo",
            vcs_commit_sha="abc123",
            vcs_ref="main",
            vcs_commit_url="https://github.com/owner/repo/commit/abc123",
        )

        result = metadata.to_dict()

        self.assertEqual(result["vcs_url"], "https://github.com/owner/repo")
        self.assertEqual(result["vcs_commit_sha"], "abc123")
        self.assertEqual(result["vcs_ref"], "main")
        self.assertEqual(result["vcs_commit_url"], "https://github.com/owner/repo/commit/abc123")

    def test_from_dict_parses_vcs_fields(self):
        """from_dict parses VCS fields."""
        data = {
            "vcs_url": "https://github.com/owner/repo",
            "vcs_commit_sha": "abc123",
            "vcs_ref": "main",
            "vcs_commit_url": "https://github.com/owner/repo/commit/abc123",
        }

        metadata = AugmentationMetadata.from_dict(data, source="test")

        self.assertEqual(metadata.vcs_url, "https://github.com/owner/repo")
        self.assertEqual(metadata.vcs_commit_sha, "abc123")
        self.assertEqual(metadata.vcs_ref, "main")
        self.assertEqual(metadata.vcs_commit_url, "https://github.com/owner/repo/commit/abc123")


class TestBuildVcsUrlWithCommit(unittest.TestCase):
    """Tests for the build_vcs_url_with_commit helper function."""

    def test_https_url_with_commit(self):
        """HTTPS URL gets git+ prefix and commit appended."""
        result = build_vcs_url_with_commit("https://github.com/owner/repo", "abc123def456")
        self.assertEqual(result, "git+https://github.com/owner/repo@abc123def456")

    def test_git_plus_url_with_commit(self):
        """git+ URL just gets commit appended."""
        result = build_vcs_url_with_commit("git+https://github.com/owner/repo", "abc123def456")
        self.assertEqual(result, "git+https://github.com/owner/repo@abc123def456")

    def test_other_url_with_commit(self):
        """Other URLs get commit appended directly."""
        result = build_vcs_url_with_commit("ssh://git@github.com/owner/repo", "abc123def456")
        self.assertEqual(result, "ssh://git@github.com/owner/repo@abc123def456")

    def test_https_url_without_commit(self):
        """HTTPS URL without commit gets git+ prefix."""
        result = build_vcs_url_with_commit("https://github.com/owner/repo", None)
        self.assertEqual(result, "git+https://github.com/owner/repo")

    def test_git_plus_url_without_commit(self):
        """git+ URL without commit stays unchanged."""
        result = build_vcs_url_with_commit("git+https://github.com/owner/repo", None)
        self.assertEqual(result, "git+https://github.com/owner/repo")


class TestVcsAugmentationIntegration(unittest.TestCase):
    """Integration tests for VCS augmentation applied to SBOMs."""

    def test_cyclonedx_vcs_augmentation(self):
        """Test VCS info is added to CycloneDX SBOM."""
        from cyclonedx.model import ExternalReferenceType
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType

        from sbomify_action.augmentation import _add_vcs_info_to_cyclonedx

        # Create a minimal BOM with a root component
        bom = Bom()
        bom.metadata.component = Component(name="test-app", type=ComponentType.APPLICATION)

        # Add VCS info
        augmentation_data = {
            "vcs_url": "https://github.com/owner/repo",
            "vcs_commit_sha": "abc123def456789",
            "vcs_ref": "main",
        }
        _add_vcs_info_to_cyclonedx(bom, augmentation_data)

        # Verify VCS external reference was added
        vcs_refs = [ref for ref in bom.metadata.component.external_references if ref.type == ExternalReferenceType.VCS]
        self.assertEqual(len(vcs_refs), 1)
        self.assertIn("git+https://github.com/owner/repo@abc123def456789", str(vcs_refs[0].url))
        self.assertEqual(vcs_refs[0].comment, "Branch/ref: main")

    def test_cyclonedx_vcs_not_added_without_component(self):
        """Test VCS info is not added if no root component exists."""
        from cyclonedx.model.bom import Bom

        from sbomify_action.augmentation import _add_vcs_info_to_cyclonedx

        bom = Bom()
        # No root component set

        augmentation_data = {
            "vcs_url": "https://github.com/owner/repo",
            "vcs_commit_sha": "abc123",
        }
        _add_vcs_info_to_cyclonedx(bom, augmentation_data)

        # Should not raise, just skip silently
        self.assertIsNone(bom.metadata.component)

    def test_cyclonedx_vcs_not_duplicated(self):
        """Test VCS external reference is not duplicated if already exists."""
        from cyclonedx.model import ExternalReference, ExternalReferenceType, XsUri
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType

        from sbomify_action.augmentation import _add_vcs_info_to_cyclonedx

        bom = Bom()
        bom.metadata.component = Component(name="test-app", type=ComponentType.APPLICATION)

        # Add existing VCS reference
        existing_vcs = ExternalReference(type=ExternalReferenceType.VCS, url=XsUri("https://existing.com/repo"))
        bom.metadata.component.external_references.add(existing_vcs)

        augmentation_data = {
            "vcs_url": "https://github.com/owner/repo",
            "vcs_commit_sha": "abc123",
        }
        _add_vcs_info_to_cyclonedx(bom, augmentation_data)

        # Should still only have 1 VCS reference (the existing one)
        vcs_refs = [ref for ref in bom.metadata.component.external_references if ref.type == ExternalReferenceType.VCS]
        self.assertEqual(len(vcs_refs), 1)
        self.assertIn("existing.com", str(vcs_refs[0].url))

    def test_spdx_vcs_augmentation(self):
        """Test VCS info is added to SPDX document."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
            Package,
        )

        from sbomify_action.augmentation import _add_vcs_info_to_spdx

        # Create minimal SPDX document
        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc",
            document_namespace="https://example.com/test",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime.now(),
        )
        package = Package(spdx_id="SPDXRef-Package", name="test-pkg", download_location="NOASSERTION")
        document = Document(creation_info=creation_info, packages=[package])

        augmentation_data = {
            "vcs_url": "https://github.com/owner/repo",
            "vcs_commit_sha": "abc123def456789",
            "vcs_ref": "main",
        }
        _add_vcs_info_to_spdx(document, augmentation_data)

        # Verify downloadLocation was set
        self.assertEqual(document.packages[0].download_location, "git+https://github.com/owner/repo@abc123def456789")

        # Verify sourceInfo was added
        self.assertIn("Built from commit abc123def456", document.packages[0].source_info)
        self.assertIn("on main", document.packages[0].source_info)

        # Verify VCS external reference was added with normalized URL
        vcs_refs = [ref for ref in document.packages[0].external_references if ref.reference_type == "vcs"]
        self.assertEqual(len(vcs_refs), 1)
        self.assertEqual(vcs_refs[0].locator, "git+https://github.com/owner/repo@abc123def456789")

        # Verify document creation comment was updated
        self.assertIn("Source: https://github.com/owner/repo", document.creation_info.creator_comment)

    def test_spdx_vcs_preserves_existing_download_location(self):
        """Test VCS doesn't overwrite existing download_location."""
        from datetime import datetime

        from spdx_tools.spdx.model import (
            Actor,
            ActorType,
            CreationInfo,
            Document,
            Package,
        )

        from sbomify_action.augmentation import _add_vcs_info_to_spdx

        creation_info = CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name="test-doc",
            document_namespace="https://example.com/test",
            creators=[Actor(ActorType.TOOL, "test-tool")],
            created=datetime.now(),
        )
        package = Package(
            spdx_id="SPDXRef-Package", name="test-pkg", download_location="https://existing.com/download.tar.gz"
        )
        document = Document(creation_info=creation_info, packages=[package])

        augmentation_data = {
            "vcs_url": "https://github.com/owner/repo",
            "vcs_commit_sha": "abc123",
        }
        _add_vcs_info_to_spdx(document, augmentation_data)

        # download_location should NOT be overwritten
        self.assertEqual(document.packages[0].download_location, "https://existing.com/download.tar.gz")


# Full-length hex used throughout the TeamCity tests (40 chars, SHA-1 shaped).
_TC_SHA = "abc123def4567890abc123def4567890abc123de"


def _write_teamcity_properties(tmpdir, build_lines=(), config_lines=None):
    """Write a build properties file, optionally chained to a config file.

    Returns the path to the build properties file, which is what
    TEAMCITY_BUILD_PROPERTIES_FILE points at.
    """
    build_lines = list(build_lines)
    if config_lines is not None:
        config_path = os.path.join(tmpdir, "teamcity.config.parameters")
        with open(config_path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(config_lines))
        build_lines.append(f"teamcity.configuration.properties.file={config_path}")

    build_path = os.path.join(tmpdir, "teamcity.build.properties")
    with open(build_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(build_lines))
    return build_path


class TestStripRefPrefix(unittest.TestCase):
    """Tests for the strip_ref_prefix helper."""

    def test_strips_heads(self):
        self.assertEqual(strip_ref_prefix("refs/heads/main"), "main")

    def test_strips_tags(self):
        self.assertEqual(strip_ref_prefix("refs/tags/v1.0"), "v1.0")

    def test_leaves_other_refs_untouched(self):
        """Pull/merge-request refs are left alone rather than guessed at."""
        self.assertEqual(strip_ref_prefix("refs/pull/42/head"), "refs/pull/42/head")

    def test_plain_branch_unchanged(self):
        self.assertEqual(strip_ref_prefix("main"), "main")

    def test_none_and_empty(self):
        self.assertIsNone(strip_ref_prefix(None))
        self.assertIsNone(strip_ref_prefix(""))


class TestBuildVcsUrlWithHttp(unittest.TestCase):
    """http:// URLs must still get the git+ prefix.

    TeamCity is the first provider that can emit a plain-http root URL (an
    internal server). Without the prefix the locator is
    "http://host/org/app@<sha>", which a consumer reads as part of the path
    rather than as a pinned VCS reference.
    """

    def test_http_url_is_prefixed(self):
        self.assertEqual(
            build_vcs_url_with_commit("http://git.corp.local:8080/org/app", "abc123"),
            "git+http://git.corp.local:8080/org/app@abc123",
        )

    def test_http_url_without_commit_is_prefixed(self):
        self.assertEqual(
            build_vcs_url_with_commit("http://git.corp.local/org/app", None),
            "git+http://git.corp.local/org/app",
        )

    def test_https_behaviour_unchanged(self):
        self.assertEqual(
            build_vcs_url_with_commit("https://github.com/acme/app", "abc123"),
            "git+https://github.com/acme/app@abc123",
        )


class TestNormalizeRepoUrl(unittest.TestCase):
    """Tests for normalize_repo_url."""

    CASES = [
        ("git@github.com:acme/app.git", "https://github.com/acme/app"),
        ("ssh://git@bitbucket.example.com:7999/proj/app.git", "https://bitbucket.example.com/proj/app"),
        ("https://user:token@gitlab.example.com/grp/sub/app.git", "https://gitlab.example.com/grp/sub/app"),
        ("git://git.example.com/org/repo", "https://git.example.com/org/repo"),
        ("https://host/org/repo/", "https://host/org/repo"),
        ("https://host:8443/org/repo.git", "https://host:8443/org/repo"),
        ("http://internal.git/org/repo.git", "http://internal.git/org/repo"),
        ("git+ssh://git@host/org/repo.git", "https://host/org/repo"),
        ("ssh://git@[2001:db8::1]:7999/org/repo.git", "https://[2001:db8::1]/org/repo"),
        ("GIT@GitHub.com:Acme/App.git", "https://github.com/Acme/App"),
        ("https://host/org/repo?token=abc#frag", "https://host/org/repo"),
        # scp syntax has no port: the digits are a path segment, not a port.
        ("git@host:7999/org/repo.git", "https://host/7999/org/repo"),
        (None, None),
        ("", None),
        ("   ", None),
        ("not a url", None),
        ("/srv/git/repo.git", None),
        ("file:///srv/git/repo.git", None),
        ("svn://host/repo", None),
        ("C:\\repos\\app", None),
        ("perforce:1666", None),
        ("https://host/", None),
        ("https://host:notaport/x/y", None),
    ]

    def test_normalization_table(self):
        for raw, expected in self.CASES:
            with self.subTest(raw=raw):
                self.assertEqual(normalize_repo_url(raw), expected)

    def test_over_long_url_rejected(self):
        self.assertIsNone(normalize_repo_url("https://host/" + "a" * 4000))

    def test_scp_form_with_absolute_path(self):
        """git@host:/srv/git/app.git is a legal scp-style remote."""
        self.assertEqual(
            normalize_repo_url("git@host:/srv/git/app.git"),
            "https://host/srv/git/app",
        )

    def test_perforce_port_is_not_a_git_remote(self):
        """user@host:1666 is a P4PORT, not scp shorthand.

        Its "path" is a port number with no separator and no .git suffix;
        accepting it would fabricate https://perforce.example.com/1666.
        """
        self.assertIsNone(normalize_repo_url("user@perforce.example.com:1666"))

    def test_credentials_never_survive(self):
        """An access token in a VCS root URL must never reach the SBOM."""
        result = normalize_repo_url("https://ci-user:ghp_supersecret@git.corp.example.com/org/repo.git")
        self.assertEqual(result, "https://git.corp.example.com/org/repo")
        self.assertNotIn("ghp_supersecret", result)
        self.assertNotIn("ci-user", result)


class TestJavaPropertiesParser(unittest.TestCase):
    """Tests for the Java .properties parser used for TeamCity build properties."""

    def test_three_separators(self):
        props = _parse_java_properties("a=1\nb:2\nc    3")
        self.assertEqual(props["a"], "1")
        self.assertEqual(props["b"], "2")
        self.assertEqual(props["c"], "3")

    def test_escaped_colon_in_url(self):
        """TeamCity writes URLs with backslash-escaped colons."""
        props = _parse_java_properties(r"vcsroot.url=https\://github.com/acme/app.git")
        self.assertEqual(props["vcsroot.url"], "https://github.com/acme/app.git")

    def test_comments_skipped(self):
        props = _parse_java_properties("# hash\n! bang\na=1")
        self.assertEqual(props, {"a": "1"})

    def test_comment_ending_in_backslash_does_not_continue(self):
        props = _parse_java_properties("# comment \\\na=1")
        self.assertEqual(props["a"], "1")

    def test_line_continuation(self):
        props = _parse_java_properties("k=one\\\n   two")
        self.assertEqual(props["k"], "onetwo")

    def test_even_trailing_backslashes_are_not_a_continuation(self):
        props = _parse_java_properties("k=b\\\\\nnext=2")
        self.assertEqual(props["k"], "b\\")
        self.assertEqual(props["next"], "2")

    def test_control_and_unicode_escapes(self):
        props = _parse_java_properties(r"a=x\ty" + "\n" + r"b=caf\u00e9")
        self.assertEqual(props["a"], "x\ty")
        self.assertEqual(props["b"], "caf\u00e9")

    def test_windows_path_escapes(self):
        props = _parse_java_properties(r"dir=C\:\\BuildAgent\\work")
        self.assertEqual(props["dir"], "C:\\BuildAgent\\work")

    def test_key_with_escaped_separator(self):
        props = _parse_java_properties(r"key.with\:colon=val")
        self.assertEqual(props["key.with:colon"], "val")

    def test_key_with_no_separator(self):
        self.assertEqual(_parse_java_properties("novalue")["novalue"], "")

    def test_hash_inside_value_is_not_a_comment(self):
        self.assertEqual(_parse_java_properties("u=http://x/#frag")["u"], "http://x/#frag")

    def test_crlf_and_bare_cr_line_endings(self):
        self.assertEqual(_parse_java_properties("a=1\r\nb=2")["b"], "2")
        self.assertEqual(_parse_java_properties("a=1\rb=2")["b"], "2")

    def test_formfeed_is_not_a_line_break(self):
        """str.splitlines() would split on \\f; java.util.Properties does not."""
        props = _parse_java_properties("a=x\fy\nb=2")
        self.assertEqual(props["a"], "x\fy")
        self.assertEqual(props["b"], "2")

    def test_duplicate_key_last_wins(self):
        self.assertEqual(_parse_java_properties("d=first\nd=second")["d"], "second")

    def test_trailing_continuation_is_flushed(self):
        self.assertEqual(_parse_java_properties("a=1\\")["a"], "1")

    def test_surrogate_pair_merged_and_encodable(self):
        value = _parse_java_properties(r"e=\uD83D\uDE00")["e"]
        self.assertEqual(value, "\U0001f600")
        value.encode("utf-8")  # must not raise

    def test_lone_surrogate_dropped_and_encodable(self):
        """A lone surrogate is a legal str element but cannot encode to UTF-8."""
        value = _parse_java_properties(r"e=\uD800x")["e"]
        self.assertEqual(value, "x")
        value.encode("utf-8")  # must not raise

    def test_malformed_unicode_escape_degrades(self):
        self.assertEqual(_parse_java_properties(r"m=\uZZ")["m"], "uZZ")

    def test_max_keys_cap(self):
        text = "\n".join(f"k{i}=v" for i in range(50))
        self.assertEqual(len(_parse_java_properties(text, max_keys=10)), 10)


class TestReadPropertiesFile(unittest.TestCase):
    """Tests for the guarded properties-file reader."""

    def test_nonexistent_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_read_properties_file(os.path.join(tmp, "missing")), {})

    def test_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_read_properties_file(tmp), {})

    def test_oversized_file_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "big.properties")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("a=" + "x" * 200)
            with patch(
                "sbomify_action._augmentation.providers.teamcity._MAX_PROPERTIES_BYTES",
                32,
            ):
                self.assertEqual(_read_properties_file(path), {})

    def test_utf8_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "u.properties")
            with open(path, "wb") as handle:
                handle.write("a=café\n".encode("utf-8"))
            self.assertEqual(_read_properties_file(path)["a"], "café")

    def test_latin1_fallback_never_raises(self):
        """A non-UTF-8 byte in an unrelated parameter must not cost us the file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "l.properties")
            with open(path, "wb") as handle:
                handle.write(b"a=caf\xe9\n")
            self.assertEqual(_read_properties_file(path)["a"], "caf\u00e9")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires os.mkfifo")
    def test_fifo_returns_promptly(self):
        """open() on a FIFO with no writer blocks forever without O_NONBLOCK.

        If this test hangs, the O_NONBLOCK/S_ISREG guard has regressed.
        """
        with tempfile.TemporaryDirectory() as tmp:
            fifo = os.path.join(tmp, "fifo")
            os.mkfifo(fifo)
            self.assertEqual(_read_properties_file(fifo), {})

    @unittest.skipIf(
        hasattr(os, "geteuid") and os.geteuid() == 0,
        "root bypasses file permissions",
    )
    def test_unreadable_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "locked.properties")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("a=1")
            os.chmod(path, 0o000)
            try:
                self.assertEqual(_read_properties_file(path), {})
            finally:
                os.chmod(path, 0o600)


class TestTeamCityProvider(unittest.TestCase):
    """Tests for TeamCityProvider."""

    def setUp(self):
        self.provider = TeamCityProvider()

    def _fetch(self, env, build_lines=(), config_lines=None, with_props=True):
        with tempfile.TemporaryDirectory() as tmp:
            full_env = dict(env)
            if with_props:
                full_env["TEAMCITY_BUILD_PROPERTIES_FILE"] = _write_teamcity_properties(tmp, build_lines, config_lines)
            with patch.dict(os.environ, full_env, clear=True):
                return self.provider.fetch()

    def test_provider_attributes(self):
        self.assertEqual(self.provider.name, "teamcity")
        self.assertEqual(self.provider.priority, 20)

    @patch.dict(os.environ, {"BUILD_VCS_NUMBER": _TC_SHA}, clear=True)
    def test_returns_none_when_not_in_teamcity(self):
        """TEAMCITY_VERSION is the detection signal; without it we do nothing."""
        self.assertIsNone(self.provider.fetch())

    def test_respects_disable_vcs_augmentation(self):
        result = self._fetch(
            {
                "TEAMCITY_VERSION": "2024.12",
                "BUILD_VCS_NUMBER": _TC_SHA,
                "DISABLE_VCS_AUGMENTATION": "true",
            },
            config_lines=["vcsroot.Main.url=https://github.com/acme/app.git"],
        )
        self.assertIsNone(result)

    def test_extracts_vcs_info_through_two_hop_properties(self):
        """The happy path: build properties -> config parameters -> VCS fields."""
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            build_lines=[f"build.vcs.number={_TC_SHA}"],
            config_lines=[
                r"vcsroot.Main.url=git@github.com\:acme/app.git",
                "teamcity.build.branch=refs/heads/main",
            ],
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://github.com/acme/app")
        self.assertEqual(result.vcs_commit_sha, _TC_SHA)
        self.assertEqual(result.vcs_ref, "main")
        self.assertEqual(result.source, "teamcity")
        self.assertEqual(result.lifecycle_phase, "pre-build")

    def test_commit_url_is_always_none(self):
        """TeamCity is host-agnostic, so the commit path shape is unknowable."""
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            config_lines=["vcsroot.Main.url=https://github.com/acme/app.git"],
        )
        self.assertIsNone(result.vcs_commit_url)

    def test_credentials_stripped_from_vcs_root_url(self):
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            config_lines=["vcsroot.Main.url=https://user:ghp_tok@git.corp.example.com/org/app.git"],
        )
        self.assertEqual(result.vcs_url, "https://git.corp.example.com/org/app")
        self.assertNotIn("ghp_tok", str(result.to_dict()))

    def test_default_branch_placeholder_falls_through(self):
        """teamcity.build.branch is the literal <default> on the default branch."""
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            config_lines=[
                "vcsroot.Main.url=https://github.com/acme/app.git",
                "teamcity.build.branch=<default>",
                "teamcity.build.vcs.branch.Main=refs/heads/master",
            ],
        )
        self.assertEqual(result.vcs_ref, "master")

    def test_default_branch_placeholder_without_fallback(self):
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            config_lines=[
                "vcsroot.Main.url=https://github.com/acme/app.git",
                "teamcity.build.branch=<default>",
            ],
        )
        self.assertIsNone(result.vcs_ref)

    def test_tag_ref_is_stripped(self):
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            config_lines=[
                "vcsroot.Main.url=https://github.com/acme/app.git",
                "teamcity.build.branch=refs/tags/v1.0.0",
            ],
        )
        self.assertEqual(result.vcs_ref, "v1.0.0")

    def test_multiple_vcs_roots_pick_deterministically(self):
        """Root choice must not depend on dict insertion order."""
        forward = [
            "vcsroot.Zeta.url=https://github.com/acme/zeta.git",
            "vcsroot.Alpha.url=https://github.com/acme/alpha.git",
        ]
        first = self._fetch({"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA}, config_lines=forward)
        second = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            config_lines=list(reversed(forward)),
        )
        self.assertEqual(first.vcs_url, "https://github.com/acme/alpha")
        self.assertEqual(second.vcs_url, first.vcs_url)

    def test_env_fallback_when_properties_unavailable(self):
        """The container case: no readable properties file, explicit mapping instead."""
        result = self._fetch(
            {
                "TEAMCITY_VERSION": "2024.12",
                "BUILD_VCS_NUMBER": _TC_SHA,
                "SBOMIFY_VCS_URL": "git@git.corp.example.com:org/app.git",
                "SBOMIFY_VCS_REF": "refs/heads/release",
            },
            with_props=False,
        )
        self.assertEqual(result.vcs_url, "https://git.corp.example.com/org/app")
        self.assertEqual(result.vcs_ref, "release")

    def test_operator_supplied_url_bypasses_git_gate(self):
        """An explicit URL is an operator assertion, like sbomify.json."""
        result = self._fetch(
            {
                "TEAMCITY_VERSION": "2024.12",
                "BUILD_VCS_NUMBER": _TC_SHA,
                "SBOMIFY_VCS_URL": "https://git.corp.example.com/org/app",
            },
            with_props=False,
        )
        self.assertEqual(result.vcs_url, "https://git.corp.example.com/org/app")

    def test_missing_chained_config_file_degrades(self):
        result = self._fetch(
            {
                "TEAMCITY_VERSION": "2024.12",
                "BUILD_VCS_NUMBER": _TC_SHA,
                "SBOMIFY_VCS_URL": "https://github.com/acme/app.git",
            },
            build_lines=["teamcity.configuration.properties.file=/nonexistent/config.properties"],
        )
        self.assertEqual(result.vcs_url, "https://github.com/acme/app")

    def test_relative_chained_config_path_ignored(self):
        result = self._fetch(
            {
                "TEAMCITY_VERSION": "2024.12",
                "BUILD_VCS_NUMBER": _TC_SHA,
                "SBOMIFY_VCS_URL": "https://github.com/acme/app.git",
            },
            build_lines=["teamcity.configuration.properties.file=relative/config.properties"],
        )
        self.assertEqual(result.vcs_url, "https://github.com/acme/app")

    def test_returns_none_when_url_cannot_be_determined(self):
        """Without a URL the root cannot be confirmed as Git, so nothing is emitted.

        TeamCity exposes no VCS-type parameter at all (verified on 2024.12.3
        through 2026.1.3), so the URL is the only automatic Git signal. Default-
        deny therefore means a build whose repository URL cannot be resolved
        contributes nothing, even though BUILD_VCS_NUMBER is present.
        """
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            config_lines=["teamcity.build.branch=refs/heads/main"],
        )
        self.assertIsNone(result)

    def test_returns_none_when_nothing_resolvable(self):
        result = self._fetch({"TEAMCITY_VERSION": "2024.12"})
        self.assertIsNone(result)

    def test_does_not_emit_lifecycle_only_metadata(self):
        """has_data() is True for lifecycle_phase alone, which would make every
        TeamCity build claim source="teamcity" while contributing nothing."""
        self.assertIsNone(self._fetch({"TEAMCITY_VERSION": "2024.12"}))

    def test_scoped_build_vcs_number_uses_verbatim_root_id(self):
        """TeamCity exports BUILD_VCS_NUMBER_<verbatim root id>.

        Measured on 2024.12.3 - 2026.1.3: the suffix is the root id exactly as
        written (BUILD_VCS_NUMBER_ProbeRoot), not an upper/underscored form.
        In a multi-root build the bare BUILD_VCS_NUMBER is absent entirely, so
        this lookup is the only way to get the revision.
        """
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER_ProbeRoot": _TC_SHA},
            config_lines=["vcsroot.ProbeRoot.url=https://github.com/acme/app.git"],
        )
        self.assertEqual(result.vcs_commit_sha, _TC_SHA)

    def test_scoped_build_vcs_number_normalized_fallback(self):
        """The upper/underscored form is still accepted as a fallback."""
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER_MY_ROOT": _TC_SHA},
            config_lines=["vcsroot.My-Root.url=https://github.com/acme/app.git"],
        )
        self.assertEqual(result.vcs_commit_sha, _TC_SHA)

    def test_multi_root_build_has_no_bare_revision(self):
        """Reproduces the real multi-root shape: no bare BUILD_VCS_NUMBER."""
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER_ProbeRoot": _TC_SHA},
            config_lines=[
                "vcsroot.MinimalRoot.url=https://github.com/acme/minimal.git",
                "vcsroot.ProbeRoot.url=https://github.com/acme/probe.git",
                f"build.vcs.number.ProbeRoot={_TC_SHA}",
            ],
        )
        # Roots sort deterministically: MinimalRoot wins.
        self.assertEqual(result.vcs_url, "https://github.com/acme/minimal")

    def test_sole_scoped_build_vcs_number_used(self):
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER_ANYTHING": _TC_SHA},
            config_lines=["vcsroot.Main.url=https://github.com/acme/app.git"],
        )
        self.assertEqual(result.vcs_commit_sha, _TC_SHA)

    def test_ambiguous_scoped_build_vcs_numbers_omit_sha(self):
        """Pinning the wrong repository's revision is worse than pinning none."""
        other = "fedcba9876543210fedcba9876543210fedcba98"
        result = self._fetch(
            {
                "TEAMCITY_VERSION": "2024.12",
                "BUILD_VCS_NUMBER_ONE": _TC_SHA,
                "BUILD_VCS_NUMBER_TWO": other,
            },
            config_lines=["vcsroot.Main.url=https://github.com/acme/app.git"],
        )
        self.assertIsNone(result.vcs_commit_sha)
        self.assertEqual(result.vcs_url, "https://github.com/acme/app")

    def test_secrets_in_properties_never_leak(self):
        """These files hold plaintext passwords for unrelated build parameters."""
        with self.assertLogs("sbomify_action", level="DEBUG") as captured:
            result = self._fetch(
                {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
                build_lines=["env.DEPLOY_TOKEN=hunter2", "system.password=s3cr3t"],
                config_lines=["vcsroot.Main.url=https://github.com/acme/app.git"],
            )
        logged = "\n".join(captured.output)
        self.assertNotIn("hunter2", logged)
        self.assertNotIn("s3cr3t", logged)
        self.assertNotIn("hunter2", str(result.to_dict()))
        self.assertNotIn("s3cr3t", str(result.to_dict()))


class TestTeamCityReviewRegressions(unittest.TestCase):
    """Regressions for the issues found reviewing PR #395."""

    def setUp(self):
        self.provider = TeamCityProvider()

    def _fetch(self, env, config_lines):
        with tempfile.TemporaryDirectory() as tmp:
            full = dict(env)
            full["TEAMCITY_BUILD_PROPERTIES_FILE"] = _write_teamcity_properties(tmp, config_lines=config_lines)
            with patch.dict(os.environ, full, clear=True):
                return self.provider.fetch()

    def test_operator_url_rescues_unrecognised_self_hosted_root(self):
        """The documented escape hatch must work for the documented case.

        A self-hosted root such as https://git.example.com/team/app normalizes
        fine but cannot be recognised as Git, so the fallback has to key off
        "Git not confirmed", not "no URL found" -- otherwise SBOMIFY_VCS_URL is
        unreachable in exactly the situation the README prescribes it for.
        """
        result = self._fetch(
            {
                "TEAMCITY_VERSION": "2024.12",
                "BUILD_VCS_NUMBER": _TC_SHA,
                "SBOMIFY_VCS_URL": "https://git.example.com/team/app",
            },
            ["vcsroot.url=https://git.example.com/team/app"],
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://git.example.com/team/app")
        self.assertEqual(result.vcs_commit_sha, _TC_SHA)

    def test_multi_root_ignores_bare_revision(self):
        """The bare BUILD_VCS_NUMBER belongs to the *primary* root.

        With several roots it need not be the root whose URL we chose, and
        pinning it would attest one repository's URL to another's commit.
        """
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            [
                "vcsroot.MinimalRoot.url=https://github.com/acme/minimal.git",
                "vcsroot.ProbeRoot.url=https://github.com/acme/probe.git",
            ],
        )
        self.assertEqual(result.vcs_url, "https://github.com/acme/minimal")
        self.assertIsNone(result.vcs_commit_sha)

    def test_multi_root_ignores_other_roots_revision(self):
        other = "fedcba9876543210fedcba9876543210fedcba98"
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER_ProbeRoot": other},
            [
                "vcsroot.MinimalRoot.url=https://github.com/acme/minimal.git",
                "vcsroot.ProbeRoot.url=https://github.com/acme/probe.git",
            ],
        )
        self.assertEqual(result.vcs_url, "https://github.com/acme/minimal")
        self.assertIsNone(result.vcs_commit_sha)

    def test_multi_root_uses_revision_scoped_to_chosen_root(self):
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER_MinimalRoot": _TC_SHA},
            [
                "vcsroot.MinimalRoot.url=https://github.com/acme/minimal.git",
                "vcsroot.ProbeRoot.url=https://github.com/acme/probe.git",
            ],
        )
        self.assertEqual(result.vcs_url, "https://github.com/acme/minimal")
        self.assertEqual(result.vcs_commit_sha, _TC_SHA)

    def test_multi_root_ignores_other_roots_branch(self):
        """A lone branch parameter belonging to a different root is not ours."""
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER_MinimalRoot": _TC_SHA},
            [
                "vcsroot.MinimalRoot.url=https://github.com/acme/minimal.git",
                "vcsroot.ProbeRoot.url=https://github.com/acme/probe.git",
                "teamcity.build.vcs.branch.ProbeRoot=refs/heads/other",
            ],
        )
        self.assertIsNone(result.vcs_ref)

    def test_single_root_still_uses_sole_branch_parameter(self):
        """The unambiguous case must keep working -- this is the common path."""
        result = self._fetch(
            {"TEAMCITY_VERSION": "2024.12", "BUILD_VCS_NUMBER": _TC_SHA},
            [
                "vcsroot.url=https://github.com/acme/app.git",
                "teamcity.build.vcs.branch.Main=refs/heads/main",
            ],
        )
        self.assertEqual(result.vcs_ref, "main")
        self.assertEqual(result.vcs_commit_sha, _TC_SHA)


class TestTeamCityGitPlusSchemes(unittest.TestCase):
    """`git+` alone is not a Git signal.

    git+svn:// and git+file:// are not Git, and normalize_repo_url rejects
    them -- so treating the bare prefix as confirmation left the provider
    "confirmed Git" with no URL, emitting a commit SHA attached to nothing.
    """

    def setUp(self):
        self.provider = TeamCityProvider()

    def _fetch(self, url):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_teamcity_properties(tmp, config_lines=[f"vcsroot.url={url}"])
            env = {
                "TEAMCITY_VERSION": "2024.12",
                "BUILD_VCS_NUMBER": _TC_SHA,
                "TEAMCITY_BUILD_PROPERTIES_FILE": path,
            }
            with patch.dict(os.environ, env, clear=True):
                return self.provider.fetch()

    def test_git_plus_svn_is_refused(self):
        self.assertIsNone(self._fetch("git+svn://svn.example.com/repo"))

    def test_git_plus_file_is_refused(self):
        self.assertIsNone(self._fetch("git+file:///srv/git/app"))

    def test_git_plus_ssh_is_accepted(self):
        result = self._fetch("git+ssh://git@selfhosted.corp/org/app")
        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://selfhosted.corp/org/app")

    def test_confirmed_root_always_has_a_url(self):
        """No path may emit a revision with no repository to attach it to."""
        result = self._fetch("https://github.com/acme/app")
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.vcs_url)


class TestTeamCityNonGitRoots(unittest.TestCase):
    """The default-deny gate: only a positively-identified Git root may emit.

    TeamCity's VCS support is plugin-extensible, so the set of non-Git types is
    open-ended and cannot be enumerated for rejection.
    """

    def setUp(self):
        self.provider = TeamCityProvider()

    def _fetch(self, revision, config_lines):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write_teamcity_properties(tmp, config_lines=config_lines)
            env = {
                "TEAMCITY_VERSION": "2024.12",
                "BUILD_VCS_NUMBER": revision,
                "TEAMCITY_BUILD_PROPERTIES_FILE": path,
            }
            with patch.dict(os.environ, env, clear=True):
                return self.provider.fetch()

    def test_non_git_roots_are_refused(self):
        cases = [
            ("subversion", "https://svn.example.com/repo/trunk", "1234567"),
            ("perforce", "https://p4.example.com/depot/main", "9876543"),
            ("tfvc", "https://tfs.example.com/coll/proj", "12345"),
            ("clearcase", "https://cc.example.com/vobs/proj", "/main/3"),
            ("bazaar", "https://bzr.example.com/repo", "user@host-20090101120000-abcdef"),
        ]
        for label, url, revision in cases:
            with self.subTest(vcs=label):
                self.assertIsNone(self._fetch(revision, [f"vcsroot.Main.url={url}"]))

    def test_hash_shaped_revision_alone_does_not_authorise(self):
        """Fossil and Monotone also emit 40-hex content hashes.

        Hex length narrows the field but never proves Git, so it must not be
        sufficient on its own.
        """
        self.assertIsNone(self._fetch(_TC_SHA, ["vcsroot.Main.url=https://fossil.example.com/repo"]))

    def test_no_vcs_type_parameter_exists(self):
        """TeamCity exposes no VCS-type parameter, so it cannot veto or confirm.

        Verified against real servers 2024.12.3 - 2026.1.3: there is no
        `vcsroot.<id>.type`, and a root created with only url+branch exposes
        only `vcsroot.<id>.url` and `vcsroot.<id>.branch`. A planted `.type`
        key must therefore have no effect either way -- it is not a signal the
        provider is entitled to trust.
        """
        # Planted type is ignored; the URL decides. Non-git-shaped URL -> None.
        self.assertIsNone(
            self._fetch(_TC_SHA, ["vcsroot.Main.type=jetbrains.git", "vcsroot.Main.url=https://svn.corp/org/app"])
        )
        # ...and a git-shaped URL is accepted regardless of a planted type.
        result = self._fetch(_TC_SHA, ["vcsroot.Main.type=svn", "vcsroot.Main.url=https://github.com/acme/app"])
        self.assertIsNotNone(result)

    def test_svn_revision_rejected_as_sha_on_a_git_root(self):
        """A 7-digit SVN revision is valid hex and would pass a {7,64} rule."""
        result = self._fetch("1234567", ["vcsroot.Main.url=https://github.com/acme/app.git"])
        self.assertIsNotNone(result)
        self.assertEqual(result.vcs_url, "https://github.com/acme/app")
        self.assertIsNone(result.vcs_commit_sha)

    def test_each_positive_signal_is_sufficient_alone(self):
        cases = [
            ("known git host", ["vcsroot.Main.url=https://github.com/acme/app"]),
            ("dot-git suffix", ["vcsroot.Main.url=https://selfhosted.corp/org/app.git"]),
            ("scp shorthand", [r"vcsroot.Main.url=git@selfhosted.corp\:org/app"]),
            ("ssh scheme", ["vcsroot.Main.url=ssh://git@selfhosted.corp/org/app"]),
        ]
        for label, config_lines in cases:
            with self.subTest(signal=label):
                result = self._fetch(_TC_SHA, config_lines)
                self.assertIsNotNone(result)
                self.assertIsNotNone(result.vcs_url)


if __name__ == "__main__":
    unittest.main()
