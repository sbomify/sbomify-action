"""Data models for Yocto SPDX processing."""

from dataclasses import dataclass
from dataclasses import field as dataclass_field


@dataclass
class YoctoPackage:
    """A package discovered from Yocto SPDX output."""

    name: str
    version: str
    spdx_file: str
    document_namespace: str
    sha256: str


@dataclass
class YoctoConfig:
    """Configuration for the Yocto pipeline."""

    input_path: str
    token: str = dataclass_field(repr=False)
    product_id: str
    release_version: str
    api_base_url: str = "https://app.sbomify.com"
    api_allow_insecure_http: bool = False
    augment: bool = False
    enrich: bool = False
    dry_run: bool = False
    component_id: str | None = None
    visibility: str | None = None
    max_packages: int | None = None


@dataclass
class YoctoPipelineResult:
    """Summary of a Yocto pipeline run."""

    packages_found: int = 0
    components_created: int = 0
    sboms_uploaded: int = 0
    sboms_skipped: int = 0
    errors: int = 0
    release_id: str | None = None
    error_messages: list[str] = dataclass_field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return self.errors > 0
