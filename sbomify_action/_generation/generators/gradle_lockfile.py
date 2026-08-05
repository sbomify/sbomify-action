"""Read a Gradle dependency lock file directly.

Priority: 10 (native, authoritative)

Every other Gradle path runs the build: the CycloneDX Gradle plugin and cdxgen
both invoke the project's own wrapper, which needs a JDK the project accepts,
a Gradle the JDK accepts, and a build that actually configures. Measured
against three real projects, none of that held -- apache/kafka failed inside
the plugin, ReactiveX/RxJava could not find a Java installation it wanted, and
embulk/embulk could not open a Gradle class cache. Three projects, three
different failures, no SBOM from any of them.

A gradle.lockfile needs none of it. Gradle wrote it precisely so the resolved
graph could be read without resolving again, and the format is one line per
dependency:

    ch.qos.logback:logback-classic:1.3.14=compileClasspath,runtimeClasspath
    empty=annotationProcessor

That is the answer the build would have computed, already computed. Reading it
is both more reliable and more honest than re-deriving it, which is why this
sits at native priority rather than being a fallback.
"""

from __future__ import annotations

import json
from pathlib import Path

from sbomify_action.logging_config import logger

from ..protocol import (
    CYCLONEDX_VERSIONS,
    SPDX_VERSIONS,
    FormatVersion,
    GenerationInput,
)
from ..result import GenerationResult
from ..utils import convert_to_spdx

#: What the document says when the caller did not ask for a version. Matches
#: the defaults the other native generators emit, so a mixed pipeline does not
#: produce documents at two spec versions for no reason.
CYCLONEDX_DEFAULT_VERSION = "1.6"
SPDX_DEFAULT_VERSION = "2.3"

#: Configurations that contribute nothing to what ships. Gradle records the
#: build's own tooling in the same file as the application's dependencies, and
#: a compiler plugin is not part of the delivered artifact.
BUILD_ONLY = frozenset({"annotationProcessor", "checkstyle", "spotbugs", "pmd", "jacocoAgent", "jacocoAnt"})


def parse_lockfile(path: Path) -> list[tuple[str, str, str]]:
    """(group, artifact, version) for every dependency the lock file pins."""
    found: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in path.read_text().splitlines():
        line = raw.strip()
        # "empty=<configuration>" is how Gradle records a configuration that
        # resolved to nothing. It is not a dependency.
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coordinate, _, configurations = line.partition("=")
        parts = coordinate.split(":")
        if len(parts) != 3:
            logger.debug(f"gradle.lockfile: skipping unparseable line {line[:60]!r}")
            continue
        if configurations and all(c in BUILD_ONLY for c in configurations.split(",") if c):
            continue
        group, artifact, version = (p.strip() for p in parts)
        if not (group and artifact and version) or (group, artifact, version) in seen:
            continue
        seen.add((group, artifact, version))
        found.append((group, artifact, version))
    return found


class GradleLockfileGenerator:
    """Native reader for gradle.lockfile."""

    @property
    def name(self) -> str:
        return "gradle-lockfile"

    @property
    def command(self) -> str:
        return ""  # nothing to run: the file is the answer

    @property
    def priority(self) -> int:
        return 10

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(format="cyclonedx", versions=CYCLONEDX_VERSIONS, default_version=CYCLONEDX_DEFAULT_VERSION),
            FormatVersion(format="spdx", versions=SPDX_VERSIONS, default_version=SPDX_DEFAULT_VERSION),
        ]

    def supports(self, input: GenerationInput) -> bool:
        if not input.is_lock_file or input.lock_file_name != "gradle.lockfile":
            return False
        if input.output_format not in ("cyclonedx", "spdx"):
            return False
        allowed = SPDX_VERSIONS if input.output_format == "spdx" else CYCLONEDX_VERSIONS
        return not (input.spec_version and input.spec_version not in allowed)

    def generate(self, input: GenerationInput) -> GenerationResult:
        assert input.lock_file is not None  # guaranteed by supports()
        source = Path(input.lock_file)
        dependencies = parse_lockfile(source)
        if not dependencies:
            return GenerationResult.failure_result(
                error_message=f"{source.name} pins no dependencies",
                sbom_format=input.output_format,
                spec_version=input.spec_version or "",
                generator_name=self.name,
            )

        version = input.spec_version or (
            SPDX_DEFAULT_VERSION if input.output_format == "spdx" else CYCLONEDX_DEFAULT_VERSION
        )
        cyclonedx_version = CYCLONEDX_DEFAULT_VERSION if input.output_format == "spdx" else version
        document = {
            "bomFormat": "CycloneDX",
            "specVersion": cyclonedx_version,
            "version": 1,
            "metadata": {
                "component": {
                    "type": "application",
                    "name": source.parent.name or "gradle-project",
                    "bom-ref": f"root-{source.parent.name or 'gradle-project'}",
                }
            },
            "components": [
                {
                    "type": "library",
                    "group": group,
                    "name": artifact,
                    "version": dependency_version,
                    "purl": f"pkg:maven/{group}/{artifact}@{dependency_version}",
                    "bom-ref": f"pkg:maven/{group}/{artifact}@{dependency_version}",
                }
                for group, artifact, dependency_version in dependencies
            ],
        }

        output = Path(input.output_file)
        output.parent.mkdir(parents=True, exist_ok=True)
        logger.info(f"Read {len(dependencies)} pinned dependencies from {source.name}")

        if input.output_format == "spdx":
            # Written beside the output rather than in the project, which may
            # be read-only and is not ours to litter.
            staging = output.parent / f".{output.name}.cdx.json"
            staging.write_text(json.dumps(document, indent=2))
            try:
                convert_to_spdx(staging, output, source.parent)
            finally:
                staging.unlink(missing_ok=True)
        else:
            output.write_text(json.dumps(document, indent=2))

        return GenerationResult.success_result(
            output_file=str(output),
            sbom_format=input.output_format,
            spec_version=version,
            generator_name=self.name,
        )
