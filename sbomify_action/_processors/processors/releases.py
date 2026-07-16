"""sbomify releases processor for tagging SBOMs with product releases.

This processor handles the creation or retrieval of product releases
in the sbomify platform and associates (tags) uploaded SBOMs with those releases.
"""

from typing import List, Optional

from sbomify_action.exceptions import APIError
from sbomify_action.logging_config import logger

from ..protocol import ProcessorInput
from ..releases_api import (
    check_release_exists,
    create_release,
    get_release_details,
    get_release_friendly_name,
    get_release_id,
    tag_sbom_with_release,
)
from ..result import ProcessorResult


class SbomifyReleasesProcessor:
    """
    Processor that tags SBOMs with sbomify product releases.

    This processor:
    1. Checks if each specified release exists in sbomify
    2. Creates the release if it doesn't exist (with get-or-create pattern)
    3. Tags the uploaded SBOM with each release in sbomify

    Triggered by: PRODUCT_RELEASE environment variable being set.
    """

    def __init__(self, api_base_url: Optional[str] = None, token: Optional[str] = None) -> None:
        """
        Initialize the SbomifyReleasesProcessor.

        Args:
            api_base_url: Base URL for the sbomify API
            token: API authentication token
        """
        self._api_base_url = api_base_url
        self._token = token

    @property
    def name(self) -> str:
        """Return the processor name."""
        return "sbomify_releases"

    def is_enabled(self, input: ProcessorInput) -> bool:
        """
        Check if this processor should run.

        Returns True if product_releases is set in the input.
        """
        return bool(input.product_releases)

    def process(self, input: ProcessorInput) -> ProcessorResult:
        """
        Process product releases by tagging the SBOM with each release.

        Args:
            input: ProcessorInput with SBOM ID and product releases

        Returns:
            ProcessorResult with success/failure info
        """
        if not input.product_releases:
            return ProcessorResult.skipped_result(
                processor_name=self.name,
                reason="No product releases specified",
            )

        # Use input values or fall back to constructor values
        api_base_url = input.api_base_url or self._api_base_url
        token = input.token or self._token

        if not api_base_url or not token:
            return ProcessorResult.failure_result(
                processor_name=self.name,
                error_message="API base URL and token are required for release processing",
            )

        processed = 0
        failed = 0
        release_ids: List[str] = []
        errors: List[str] = []

        for release_spec in input.product_releases:
            try:
                product_id, version = release_spec.split(":", 1)
                logger.info(f"Processing release {version} for product {product_id}")

                release_id = self._process_single_release(
                    api_base_url=api_base_url,
                    token=token,
                    sbom_id=input.sbom_id,
                    product_id=product_id,
                    version=version,
                )

                if release_id:
                    release_ids.append(release_id)
                    processed += 1
                else:
                    failed += 1
                    errors.append(f"Could not get release ID for {product_id}:{version}")

            except Exception as e:
                failed += 1
                errors.append(f"Error processing {release_spec}: {str(e)}")
                logger.error(f"Error processing release {release_spec}: {e}")

        # Any failed release is fatal, including partial success (some
        # succeeded, some failed) — a silently missing release must fail the run.
        if failed > 0:
            if processed > 0:
                logger.warning(f"Partial failure: {processed} release(s) processed, {failed} failed")
            return ProcessorResult.failure_result(
                processor_name=self.name,
                error_message="; ".join(errors),
                processed_items=processed,
                failed_items=failed,
                metadata={"release_ids": release_ids},
            )

        return ProcessorResult.success_result(
            processor_name=self.name,
            processed_items=processed,
            metadata={"release_ids": release_ids},
        )

    def _process_single_release(
        self,
        api_base_url: str,
        token: str,
        sbom_id: str,
        product_id: str,
        version: str,
    ) -> Optional[str]:
        """
        Process a single release: check/create and tag.

        Returns the release ID if successful, None otherwise.
        """
        release_id = None
        release_details = None

        # Check if release exists
        release_exists = check_release_exists(api_base_url, token, product_id, version)

        if release_exists:
            # Get release details for user-friendly logging
            try:
                release_details = get_release_details(api_base_url, token, product_id, version)
                friendly_name = get_release_friendly_name(release_details, version)
                logger.info(f"{friendly_name} already exists for product {product_id}")
                release_id = release_details.get("id") if release_details else None
            except APIError as e:
                logger.warning(f"Could not get release details for logging: {e}")
                logger.info(f"Release {version} already exists for product {product_id}")
        else:
            logger.info(f"Creating release {version} for product {product_id}")
            created_release_id = create_release(api_base_url, token, product_id, version)
            if created_release_id:
                release_id = created_release_id
            # Get details after creation for consistent logging
            try:
                release_details = get_release_details(api_base_url, token, product_id, version)
                if not release_id and release_details:
                    release_id = release_details.get("id")
            except APIError as e:
                logger.warning(f"Could not get release details after creation: {e}")

        # Fall back to explicit lookup if we still don't know the release ID
        if not release_id:
            release_id = get_release_id(api_base_url, token, product_id, version)

        if release_id:
            # Use friendly name if we have release details
            if release_details:
                friendly_name = get_release_friendly_name(release_details, version)
                logger.info(f"Tagging SBOM {sbom_id} with {friendly_name} (ID: {release_id})")
            else:
                logger.info(f"Tagging SBOM {sbom_id} with release {version} (ID: {release_id})")
            tag_sbom_with_release(api_base_url, token, sbom_id, release_id)
        else:
            logger.error(f"Could not get release ID for {product_id}:{version}")

        return release_id
