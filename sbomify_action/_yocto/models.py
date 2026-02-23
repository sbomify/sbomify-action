"""Data models for Yocto SPDX processing."""

from dataclasses import dataclass, field


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
    token: str
    product_id: str
    release_version: str
    api_base_url: str = "https://app.sbomify.com"
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
    error_messages: list[str] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return self.errors > 0
