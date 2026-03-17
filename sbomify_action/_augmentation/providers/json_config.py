"""JSON config file provider for augmentation metadata.

This provider reads augmentation metadata from a JSON config file,
typically named 'sbomify.json' in the project root.

Example config file:
{
    "lifecycle_phase": "build",
    "supplier": {
        "name": "My Company",
        "url": ["https://example.com"],
        "contacts": [{"name": "Support", "email": "support@example.com"}]
    },
    "manufacturer": {
        "name": "Acme Manufacturing",
        "url": ["https://acme-mfg.com"],
        "contacts": [{"name": "Mfg Contact", "email": "contact@acme-mfg.com"}]
    },
    "authors": [
        {"name": "John Doe", "email": "john@example.com"}
    ],
    "licenses": ["MIT"],
    "vcs_url": "https://github.mycompany.com/org/repo",
    "vcs_ref": "main",
    "security_contact": "https://example.com/.well-known/security.txt",
    "release_date": "2024-06-15",
    "support_period_end": "2026-12-31",
    "end_of_life": "2028-12-31"
}

VCS fields can be used to override auto-detected CI values or configure
VCS info for self-hosted instances. Set DISABLE_VCS_AUGMENTATION=true
to disable all VCS enrichment.

Security and lifecycle fields (CRA compliance):
- security_contact: URL/email for security vulnerability reporting
  Accepts: https://, mailto:, tel: URIs (e.g., security.txt URL recommended)
- release_date: ISO-8601 date when component was released (YYYY-MM-DD)
- support_period_end: ISO-8601 date when security support ends (YYYY-MM-DD)
- end_of_life: ISO-8601 date when all support ends (YYYY-MM-DD)
"""

import json
from pathlib import Path
from typing import Any, Optional

from sbomify_action.logging_config import logger

from ..metadata import AugmentationMetadata
from ..utils import is_vcs_augmentation_disabled

# Default config file name
DEFAULT_CONFIG_FILE = "sbomify.json"


class JsonConfigProvider:
    """
    Provider that reads augmentation metadata from a JSON config file.

    This provider has high priority (10) so local config takes precedence
    over remote API data.
    """

    name: str = "json-config"
    priority: int = 10

    def fetch(
        self,
        component_id: Optional[str] = None,
        api_base_url: Optional[str] = None,
        token: Optional[str] = None,
        config_path: Optional[str] = None,
        **kwargs: Any,
    ) -> Optional[AugmentationMetadata]:
        """
        Fetch augmentation metadata from a JSON config file.

        Args:
            config_path: Path to the config file. If not provided,
                        searches for default config files in current directory.
            component_id: Ignored (not needed for file-based provider)
            api_base_url: Ignored (not needed for file-based provider)
            token: Ignored (not needed for file-based provider)
            **kwargs: Additional arguments (ignored)

        Returns:
            AugmentationMetadata if config file found and valid, None otherwise
        """
        # Find config file
        config_file = self._find_config_file(config_path)
        if not config_file:
            logger.debug("No JSON config file found for augmentation")
            return None

        # Read and parse config file
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, dict):
                logger.warning(f"Invalid JSON config format in {config_file}: expected object")
                return None

            # Strip VCS fields if VCS augmentation is disabled
            if is_vcs_augmentation_disabled():
                vcs_keys = {"vcs_url", "vcs_commit_sha", "vcs_ref", "vcs_commit_url"}
                data = {k: v for k, v in data.items() if k not in vcs_keys}
                logger.debug("VCS augmentation disabled, ignoring VCS fields from config")

            # Create metadata from config
            metadata = AugmentationMetadata.from_dict(data, source=self.name)

            if metadata.has_data():
                logger.info(f"Loaded augmentation metadata from {config_file}")
                return metadata
            else:
                logger.debug(f"No augmentation metadata found in {config_file}")
                return None

        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in config file {config_file}: {e}")
            return None
        except OSError as e:
            logger.warning(f"Error reading config file {config_file}: {e}")
            return None

    def _find_config_file(self, config_path: Optional[str] = None) -> Optional[Path]:
        """
        Find the config file to use.

        Args:
            config_path: Explicit path to config file, or None to search

        Returns:
            Path to config file if found, None otherwise
        """
        if config_path:
            path = Path(config_path)
            if path.is_file():
                return path
            logger.debug(f"Specified config file not found: {config_path}")
            return None

        # Search for default config file in current directory
        cwd = Path.cwd()
        path = cwd / DEFAULT_CONFIG_FILE
        if path.is_file():
            return path

        # Also check /github/workspace for GitHub Actions
        github_workspace = Path("/github/workspace")
        if github_workspace.is_dir():
            path = github_workspace / DEFAULT_CONFIG_FILE
            if path.is_file():
                return path

        return None
