import contextlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

import jsonschema
import pytest
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    CreationInfo,
    Document,
    Package,
    Relationship,
    RelationshipType,
    SpdxNoAssertion,
)
from spdx_tools.spdx.writer.write_anything import write_file as spdx_write_file

from sbomify_action.augmentation import augment_sbom_from_file
from sbomify_action.enrichment import clear_cache, enrich_sbom
from sbomify_action.serialization import serialize_cyclonedx_bom

# Environment keys that any augmentation provider might react to.
# The schema-compliance tests mock sbomify-api and drive the whole
# pipeline to verify that an operator-supplied lifecycle_phase makes
# it all the way to the emitted BOM. If the suite runs IN GitHub
# Actions / GitLab CI / Bitbucket Pipelines, the real CI providers
# fire and win over the sbomify-api mock (priority 20 < 50), which
# would falsely fail these assertions. Scrub the relevant env vars
# for the duration of each test so only the mocked providers speak.
_AUGMENTATION_ENV_KEYS_TO_CLEAR = (
    "GITHUB_ACTIONS",
    "GITHUB_REPOSITORY",
    "GITHUB_SHA",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_SERVER_URL",
    "GITLAB_CI",
    "CI_PROJECT_URL",
    "CI_PROJECT_PATH",
    "CI_SERVER_URL",
    "CI_COMMIT_SHA",
    "CI_COMMIT_REF_NAME",
    "CI_COMMIT_TAG",
    "BITBUCKET_PIPELINE_UUID",
    "BITBUCKET_GIT_HTTP_ORIGIN",
    "BITBUCKET_WORKSPACE",
    "BITBUCKET_REPO_SLUG",
    "BITBUCKET_COMMIT",
    "BITBUCKET_BRANCH",
    "BITBUCKET_TAG",
    "DOCKER_IMAGE",
)


@contextlib.contextmanager
def _scrub_ci_env():
    """Remove all CI / docker-image environment variables for the
    duration of the block and restore them afterwards. Use this when
    a test wants only the mocked providers (sbomify-api / json-config)
    to contribute augmentation metadata."""
    saved = {k: os.environ.pop(k, None) for k in _AUGMENTATION_ENV_KEYS_TO_CLEAR}
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


# Path to schemas
REPO_ROOT = Path(__file__).parent.parent
CDX_SCHEMA_DIR = REPO_ROOT / "sbomify_action" / "schemas" / "cyclonedx"
SPDX_SCHEMA_DIR = REPO_ROOT / "sbomify_action" / "schemas" / "spdx"

CDX_SCHEMAS = {
    "1.3": CDX_SCHEMA_DIR / "cdx-1.3.schema.json",
    "1.4": CDX_SCHEMA_DIR / "cdx-1.4.schema.json",
    "1.5": CDX_SCHEMA_DIR / "cdx-1.5.schema.json",
    "1.6": CDX_SCHEMA_DIR / "cdx-1.6.schema.json",
    "1.7": CDX_SCHEMA_DIR / "cdx-1.7.schema.json",
}

SPDX_SCHEMAS = {
    "2.2": SPDX_SCHEMA_DIR / "spdx-2.2.schema.json",
    "2.3": SPDX_SCHEMA_DIR / "spdx-2.3.schema.json",
}


def load_schema(schema_path: Path):
    if not schema_path.exists():
        pytest.skip(f"Schema file not found: {schema_path}")
    with open(schema_path) as f:
        return json.load(f)


@pytest.mark.parametrize("version", ["1.3", "1.4", "1.5", "1.6", "1.7"])
def test_cyclonedx_full_flow_compliance(version, tmp_path):
    """Test CycloneDX compliance using full augmentation and enrichment public APIs."""
    schema = load_schema(CDX_SCHEMAS[version])

    # 1. Create and write minimal valid BOM
    bom = Bom()
    c = Component(name="test-lib", version="1.0.0", type=ComponentType.LIBRARY)
    # Add PURL for enrichment
    from packageurl import PackageURL

    c.purl = PackageURL.from_string("pkg:pypi/test-lib@1.0.0")
    bom.components.add(c)

    # Set proper spec version in BOM so serializer uses it and file has it
    bom.spec_version = version

    input_file = tmp_path / f"input_{version}.json"
    augmented_file = tmp_path / f"augmented_{version}.json"
    final_file = tmp_path / f"final_{version}.json"

    # Serialize initial BOM to file
    with open(input_file, "w") as f:
        f.write(serialize_cyclonedx_bom(bom, version))

    # 2. Augment (Augmentation Flow)
    augmentation_data = {
        "supplier": {"name": "Augmented Supplier", "url": "https://supplier.com"},
        "authors": [{"name": "Augmented Author", "email": "author@example.com"}],
        "licenses": ["MIT"],
        "lifecycle_phase": "build",  # CISA 2025 Generation Context
    }

    # Mock the sbomify API provider and disable json-config provider
    mock_api_response = Mock()
    mock_api_response.ok = True
    mock_api_response.json.return_value = augmentation_data

    with (
        _scrub_ci_env(),
        patch(
            "sbomify_action._augmentation.providers.json_config.JsonConfigProvider._find_config_file",
            return_value=None,
        ),
        patch(
            "sbomify_action._augmentation.providers.sbomify_api.requests.get",
            return_value=mock_api_response,
        ),
    ):
        augment_sbom_from_file(
            input_file=str(input_file),
            output_file=str(augmented_file),
            api_base_url="https://api.test",
            token="dummy",
            component_id="123",
        )

    # 3. Enrich (Enrichment Flow)
    enrichment_metadata = {
        "description": "Enriched description",
        "homepage": "https://enriched.com",
        "normalized_licenses": ["Apache-2.0"],
    }

    # Clear cache to ensure fresh fetch
    clear_cache()

    # Mock the package metadata fetcher via requests.Session.get
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "info": {
            "summary": enrichment_metadata.get("description"),
            "home_page": enrichment_metadata.get("homepage"),
            "license": enrichment_metadata.get("normalized_licenses", [""])[0]
            if enrichment_metadata.get("normalized_licenses")
            else None,
            "author": "Test Author",
        }
    }
    with patch("requests.Session.get", return_value=mock_response):
        enrich_sbom(input_file=str(augmented_file), output_file=str(final_file))

    # 4. Validate Final Output
    with open(final_file) as f:
        bom_data = json.load(f)

    try:
        jsonschema.validate(instance=bom_data, schema=schema)
    except jsonschema.ValidationError as e:
        pytest.fail(f"CycloneDX {version} schema validation failed: {e}")

    # 5. Verify version-specific lifecycle handling
    metadata = bom_data.get("metadata", {})
    if version in ["1.5", "1.6", "1.7"]:
        # Lifecycle should be present in CycloneDX 1.5+
        assert "lifecycles" in metadata, f"CycloneDX {version} should have lifecycles field"
        lifecycles = metadata.get("lifecycles", [])
        assert len(lifecycles) > 0, f"CycloneDX {version} should have at least one lifecycle entry"
        assert lifecycles[0].get("phase") == "build", "Lifecycle phase should be 'build'"
    else:
        # Lifecycle should NOT be present in CycloneDX 1.3/1.4
        assert "lifecycles" not in metadata or len(metadata.get("lifecycles", [])) == 0, (
            f"CycloneDX {version} should NOT have lifecycles (not supported in schema)"
        )


@pytest.mark.parametrize("version", ["2.2", "2.3"])
def test_spdx_full_flow_compliance(version, tmp_path):
    """Test SPDX compliance using full augmentation and enrichment public APIs."""
    schema = load_schema(SPDX_SCHEMAS[version])

    # 1. Create and write minimal valid SPDX Document
    creation_info = CreationInfo(
        spdx_version=f"SPDX-{version}",
        spdx_id="SPDXRef-DOCUMENT",
        name="test-document",
        document_namespace="http://example.com/namespace",
        creators=[Actor(ActorType.TOOL, "original-tool")],
        created=datetime(2023, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
    )
    document = Document(creation_info=creation_info)

    # Add a package with PURL for enrichment
    package = Package(
        name="test-package",
        spdx_id="SPDXRef-Package",
        download_location=SpdxNoAssertion(),
        license_concluded=SpdxNoAssertion(),
        license_declared=SpdxNoAssertion(),
        copyright_text=SpdxNoAssertion(),
        files_analyzed=False,
    )
    # Add External Ref for PURL
    from spdx_tools.spdx.model import ExternalPackageRef, ExternalPackageRefCategory

    package.external_references.append(
        ExternalPackageRef(
            category=ExternalPackageRefCategory.PACKAGE_MANAGER,
            reference_type="purl",
            locator="pkg:pypi/test-package@1.0.0",
        )
    )
    document.packages.append(package)

    # Add relationship
    relationship = Relationship(
        spdx_element_id="SPDXRef-DOCUMENT",
        relationship_type=RelationshipType.DESCRIBES,
        related_spdx_element_id="SPDXRef-Package",
    )
    document.relationships.append(relationship)

    input_file = tmp_path / f"input_spdx_{version}.json"
    augmented_file = tmp_path / f"augmented_spdx_{version}.json"
    final_file = tmp_path / f"final_spdx_{version}.json"

    # Write initial SPDX to file
    spdx_write_file(document, str(input_file))

    # 2. Augment (Augmentation Flow)
    augmentation_data = {
        "supplier": {"name": "Augmented Supplier", "url": "https://supplier.com"},
        "authors": [{"name": "Augmented Author", "email": "author@example.com"}],
        "licenses": ["MIT"],
        "lifecycle_phase": "build",  # CISA 2025 Generation Context
    }

    # Mock the sbomify API provider and disable json-config provider
    mock_api_response = Mock()
    mock_api_response.ok = True
    mock_api_response.json.return_value = augmentation_data

    with (
        _scrub_ci_env(),
        patch(
            "sbomify_action._augmentation.providers.json_config.JsonConfigProvider._find_config_file",
            return_value=None,
        ),
        patch(
            "sbomify_action._augmentation.providers.sbomify_api.requests.get",
            return_value=mock_api_response,
        ),
    ):
        augment_sbom_from_file(
            input_file=str(input_file),
            output_file=str(augmented_file),
            api_base_url="https://api.test",
            token="dummy",
            component_id="123",
        )

    # 3. Enrich (Enrichment Flow)
    enrichment_metadata = {
        "description": "Enriched description",
        "homepage": "https://enriched.com",
        "normalized_licenses": ["Apache-2.0"],
    }

    clear_cache()

    # Mock the package metadata fetcher via requests.Session.get
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "info": {
            "summary": enrichment_metadata.get("description"),
            "home_page": enrichment_metadata.get("homepage"),
            "license": enrichment_metadata.get("normalized_licenses", [""])[0]
            if enrichment_metadata.get("normalized_licenses")
            else None,
            "author": "Test Author",
        }
    }
    with patch("requests.Session.get", return_value=mock_response):
        enrich_sbom(input_file=str(augmented_file), output_file=str(final_file))

    # 4. Validate Final Output
    with open(final_file) as f:
        spdx_data = json.load(f)

    try:
        jsonschema.validate(instance=spdx_data, schema=schema)
    except jsonschema.ValidationError as e:
        pytest.fail(f"SPDX {version} schema validation failed: {e}")

    # 5. Verify lifecycle phase in SPDX creator comment
    creation_info = spdx_data.get("creationInfo", {})
    creator_comment = creation_info.get("comment", "")
    assert "Lifecycle phase: build" in creator_comment, (
        f"SPDX {version} should have lifecycle phase in creator comment. Got: {creator_comment}"
    )
