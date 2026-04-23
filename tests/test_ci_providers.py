"""Tests for CI provider VCS augmentation."""

import os
import unittest
from unittest.mock import patch

from sbomify_action._augmentation.metadata import AugmentationMetadata
from sbomify_action._augmentation.providers import (
    BitbucketPipelinesProvider,
    DockerImageProvider,
    GitHubActionsProvider,
    GitLabCIProvider,
    is_vcs_augmentation_disabled,
)
from sbomify_action._augmentation.utils import build_vcs_url_with_commit, truncate_sha


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


if __name__ == "__main__":
    unittest.main()
