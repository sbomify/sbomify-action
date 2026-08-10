"""Native CycloneDX generators for the JVM: Maven, Gradle and sbt.

The ecosystem's own resolvers, alongside cyclonedx-py for Python,
cyclonedx-gomod for Go and cyclonedx-cargo for Rust. Priority 10.

They exist because cdxgen drives these build systems badly. Measured on whole
real projects, with cdxgen failing outright on all three:

    spring-petclinic   native 106   syft  42
    keycloak 26.4.7    native 340   syft  92
    okhttp             native 288   syft  34

syft is not a substitute here for a structural reason: it catalogs artifacts
on disk, and an unbuilt JVM source tree has no jars to catalog. trivy is not
either -- `trivy fs` matches lock files, and these projects have none, so it
returns zero components for Gradle and sbt and errors on Maven.

None of these tools is a binary we install. They are build plugins, fetched by
the build system itself from Maven Central or the Gradle Plugin Portal, so
supporting them costs no bundle space -- only the JDK and build tool, which
the jvm bundle already carries.

Each generator uses the project's own wrapper (mvnw, gradlew) when it has one.
That is not a nicety: RxJava pins Gradle 7.6.4 and scopt pins sbt 1.5.2, and
both predate Java 21 and die against the JDK we ship. A project pins its build
tool for a reason, and the wrapper is how it does so.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from sbomify_action.exceptions import SBOMGenerationError
from sbomify_action.logging_config import logger
from sbomify_action.runtimes import bundle_plugin_version, bundle_wrappers, ensure_runtime, fetching_is_enabled

from ..protocol import FormatVersion, GenerationInput
from ..result import GenerationResult
from ..utils import convert_to_spdx, run_command

#: All three plugins emit these; 1.6 is what the plugins default to.
JVM_CYCLONEDX_VERSIONS = ("1.4", "1.5", "1.6")
JVM_CYCLONEDX_DEFAULT = "1.6"

#: The plugins emit CycloneDX only, so SPDX is converted from it rather than
#: scanned for. That is not a shortcut, it is the better document: syft finds
#: 38 packages in spring-petclinic where the Maven plugin resolves 106, and 92
#: in Keycloak against 340, because an unbuilt source tree has no jars to
#: catalog. Conversion keeps every component and every purl -- measured, 106
#: in and 106 out at 100% purl coverage.
JVM_SPDX_VERSIONS = ("SPDX-2.3",)
JVM_SPDX_DEFAULT = "SPDX-2.3"


#: Read from the JVM bundle, which is where these are pinned.
#:
#: They were pinned here too, in tools/pom.xml and tools/build.gradle, until
#: sbom-tools took ownership of the JVM toolchain. Keeping a copy meant two
#: repositories describing the same plugin, both watched by Dependabot and
#: free to disagree -- and they did, within hours: sbom-tools said 2.9.3 while
#: this repository still said 2.9.1, so the generator applied one version and
#: the bundle advertised another.
#:
#: Nothing installs these; Maven, Gradle and sbt fetch them themselves. We
#: only have to name a version, and the bundle we already fetched states it.
#: Resolved when a generator runs rather than at import, because that is when
#: the bundle exists.
def maven_plugin_coordinate() -> str:
    return f"org.cyclonedx:cyclonedx-maven-plugin:{bundle_plugin_version('maven', 'cyclonedx-maven')}"


def gradle_plugin_coordinate() -> str:
    return f"org.cyclonedx:cyclonedx-gradle-plugin:{bundle_plugin_version('gradle', 'cyclonedx-gradle')}"


def sbt_plugin_version() -> str:
    return bundle_plugin_version("sbt", "sbt-sbom")


#: Applied through --init-script so the project's build files are never edited.
#:
#: Two details that cost real time. The class is CyclonedxPlugin with a
#: lowercase d -- the natural spelling fails with "unknown property 'org'",
#: which reads like a classpath fault and is not one. And the plugin is
#: published to the Gradle Plugin Portal, not Maven Central: Central's search
#: index still answers 1.4.0 and does not carry 3.3.0 at all.
def gradle_init_script() -> str:
    """Applied through --init-script so the project's build files are never edited.

    Two details that cost real time. The class is CyclonedxPlugin with a
    lowercase d -- the natural spelling fails with "unknown property 'org'",
    which reads like a classpath fault and is not one. And the plugin is
    published to the Gradle Plugin Portal, not Maven Central: Central's search
    index still answers 1.4.0 and does not carry 3.3.0 at all.
    """
    return f"""initscript {{
  repositories {{
    maven {{ url "https://plugins.gradle.org/m2/" }}
    mavenCentral()
  }}
  dependencies {{ classpath "{gradle_plugin_coordinate()}" }}
}}
allprojects {{ apply plugin: org.cyclonedx.gradle.CyclonedxPlugin }}
"""


#: Used only when the bundle predates the ``[wrappers]`` block.
#:
#: The bundle is the source of truth for these -- which wrapper stands in for
#: which tool, and what the wrapper cannot bootstrap without, are facts about
#: the JVM toolchain, and sbom-tools owns that. Keeping a second copy here is
#: exactly what went wrong with the plugin pins, which drifted to 2.9.1 against
#: the bundle's 2.9.3 within hours of the split.
#:
#: These remain as a floor rather than a second opinion: an older bundle should
#: still build, and being wrong about a fallback costs a retry, where refusing
#: to run costs the whole SBOM.
_WRAPPER_DEFAULTS: dict[str, dict[str, str]] = {
    "gradle": {"script": "gradlew", "tool": "gradle", "needs": "gradle/wrapper/gradle-wrapper.jar"},
    "maven": {"script": "mvnw", "tool": "mvn"},
}


def _wrapper_spec(name: str, provider: str) -> dict[str, str]:
    """What the bundle says about one wrapper, falling back to our defaults.

    ``provider`` is the tool whose bundle is asked -- the name this repository
    knows it by, which is not always the executable: the jvm bundle provides
    "maven" and the thing you run is "mvn".
    """
    try:
        declared = bundle_wrappers(provider).get(name)
    except SBOMGenerationError as unavailable:
        logger.debug(f"Could not read the {provider} bundle's wrappers ({unavailable}); using defaults")
        return _WRAPPER_DEFAULTS[name]
    if not declared:
        logger.debug(f"The {provider} bundle declares no {name} wrapper; using defaults")
        return _WRAPPER_DEFAULTS[name]
    return declared


def _wrapper_or(project_dir: Path, spec: dict[str, str]) -> str:
    """Prefer the project's own build-tool wrapper -- if it can actually run.

    ``spec`` comes from the bundle: the ``script`` a project commits, the
    ``tool`` here that stands in for it, and optionally ``needs``, a file the
    wrapper cannot bootstrap without.

    That last one exists because a wrapper script is small while the jar that
    does the work is a binary, and projects that refuse to commit binaries
    gitignore it and let the script fetch it on first run. That fetch shells
    out to curl, which this image does not carry and deliberately does not
    want to: apache/kafka fails with ``/workspace/gradlew: 207: curl: not
    found`` three times over, then ``Unable to access jarfile
    gradle/wrapper/gradle-wrapper.jar``.

    Falling back to the pinned tool is strictly better than what happened
    before, which was to fail the native generator and hand the project to
    cdxgen -- measured elsewhere in this module as 288 components against 34.
    A pinned Gradle that runs beats a project-pinned Gradle that cannot.
    """
    wrapper, fallback, needs = spec["script"], spec["tool"], spec.get("needs")
    candidate = project_dir / wrapper
    if not candidate.is_file():
        return fallback
    if needs and not (project_dir / needs).is_file():
        logger.info(f"{wrapper} cannot bootstrap without {needs}; using the pinned {fallback}")
        return fallback
    candidate.chmod(0o755)
    return str(candidate)


def _run_build(cmd: list[str], tool_name: str, project_dir: Path, fallback: str, timeout: int) -> None:
    """Run the build, retrying with the pinned tool if the wrapper fails.

    Not every broken wrapper can be spotted in advance. apache/flink ships its
    maven-wrapper.jar and the wrapper rejects it at run time -- "Failed to
    validate Maven wrapper SHA-256, your Maven wrapper might be compromised"
    -- which no pre-flight check here could have predicted.

    The old behaviour in both cases was to give up on the native generator and
    fall through to cdxgen, so the cost of a project's wrapper being unusable
    was paid in SBOM quality. Retrying with the tool we ship is cheap by
    comparison: it only happens after a failure, on a path that was about to
    run a whole other generator anyway.

    The retry deliberately does not happen when the wrapper was never used --
    then cmd[0] is already the pinned tool and the failure is the build's own.
    """
    try:
        run_command(cmd, tool_name, timeout=timeout, cwd=str(project_dir))
        return
    except SBOMGenerationError as first_failure:
        if cmd[0] == fallback:
            raise
        logger.warning(f"The project's wrapper failed ({first_failure}); retrying with the pinned {fallback}")
        run_command([fallback, *cmd[1:]], tool_name, timeout=timeout, cwd=str(project_dir))


def _largest_bom(candidates: list[Path]) -> Path | None:
    """The document with the most components.

    A multi-module build writes one per module, and the root project's own is
    usually near-empty; picking the first would report a handful of components
    for a project with hundreds.
    """
    import json

    best: tuple[int, Path] | None = None
    for path in candidates:
        try:
            count = len(json.loads(path.read_text()).get("components") or [])
        except (OSError, json.JSONDecodeError):
            continue
        if best is None or count > best[0]:
            best = (count, path)
    return best[1] if best else None


class _JvmGenerator:
    """Shared behaviour: claim a JVM build file, run a plugin, collect the BOM."""

    build_files: tuple[str, ...] = ()
    tool_name: str = ""
    #: The build tool actually invoked. None of these generators is a binary
    #: of its own -- the plugin is fetched by the build system -- so the
    #: command to look for on PATH is the build tool.
    runtime: str = ""

    @property
    def name(self) -> str:
        return self.tool_name

    @property
    def command(self) -> str:
        return self.runtime

    @property
    def priority(self) -> int:
        # Native/authoritative, like cyclonedx-py and cyclonedx-gomod.
        return 10

    @property
    def supported_formats(self) -> list[FormatVersion]:
        return [
            FormatVersion(
                format="cyclonedx",
                versions=JVM_CYCLONEDX_VERSIONS,
                default_version=JVM_CYCLONEDX_DEFAULT,
            ),
            FormatVersion(
                format="spdx",
                versions=JVM_SPDX_VERSIONS,
                default_version=JVM_SPDX_DEFAULT,
            ),
        ]

    def supports(self, input: GenerationInput) -> bool:
        if not fetching_is_enabled():
            # Outside our image the user's toolchain decides. Fetching a JDK
            # they did not install would change which generator wins, and so
            # change the SBOM they get, without them asking.
            return False
        if not input.is_lock_file or input.output_format not in ("cyclonedx", "spdx"):
            return False
        if input.lock_file_name not in self.build_files:
            return False
        allowed = JVM_SPDX_VERSIONS if input.output_format == "spdx" else JVM_CYCLONEDX_VERSIONS
        return not (input.spec_version and input.spec_version not in allowed)

    def _run(self, project_dir: Path, output: Path) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def generate(self, input: GenerationInput) -> GenerationResult:
        wants_spdx = input.output_format == "spdx"
        default = JVM_SPDX_DEFAULT if wants_spdx else JVM_CYCLONEDX_DEFAULT
        spec_version = input.spec_version or default
        assert input.lock_file is not None  # guaranteed by supports()
        project_dir = Path(input.lock_file).parent.resolve()
        output = Path(input.output_file).resolve()
        # The plugin always writes CycloneDX; SPDX is converted from it.
        produced = output.with_suffix(".cyclonedx.json") if wants_spdx else output

        try:
            # The JDK, and the build tool that drives the plugin.
            ensure_runtime("java")
            ensure_runtime(self.runtime)
            self._run(project_dir, produced)
            if wants_spdx:
                if not produced.exists():
                    raise SBOMGenerationError(f"{self.name} produced no CycloneDX document to convert")
                convert_to_spdx(produced, output, project_dir)
                produced.unlink(missing_ok=True)
        except SBOMGenerationError as exc:
            return GenerationResult.failure_result(
                error_message=str(exc),
                sbom_format=input.output_format,
                spec_version=spec_version,
                generator_name=self.name,
            )

        if not output.exists():
            return GenerationResult.failure_result(
                error_message=f"{self.name} completed but wrote no output file",
                sbom_format=input.output_format,
                spec_version=spec_version,
                generator_name=self.name,
            )
        return GenerationResult.success_result(
            output_file=str(output),
            sbom_format=input.output_format,
            spec_version=spec_version,
            generator_name=self.name,
        )


class CycloneDXMavenGenerator(_JvmGenerator):
    """Maven, via the CycloneDX Maven plugin.

    106 components for spring-petclinic and 340 for Keycloak, against syft's
    42 and 92, with cdxgen failing on both.
    """

    build_files = ("pom.xml",)
    tool_name = "cyclonedx-maven"
    runtime = "maven"

    def _run(self, project_dir: Path, output: Path) -> None:
        wrapper = _wrapper_spec("maven", self.runtime)
        mvn = _wrapper_or(project_dir, wrapper)
        cmd = [
            mvn,
            "-B",
            "-q",
            # No -N. It used to be passed here on the reasoning that
            # "makeAggregateBom already walks the reactor", which has it
            # backwards: the goal aggregates the BOMs of the reactor projects
            # Maven *built*, and -N (--non-recursive) restricts the reactor to
            # the aggregator POM alone. The goal then walks a reactor of one,
            # finds no modules, and writes a BOM with zero components -- while
            # exiting 0, so nothing downstream noticed.
            #
            # Measured on netty, jenkins, nacos and camel: every one produced
            # 0 components, each with a `?type=pom` aggregator as its root.
            # On a two-module fixture, the same command with and without -N
            # gives 0 components and 10.
            #
            # Naming the goal directly (rather than a lifecycle phase) still
            # avoids compiling anything: Maven runs that goal across the
            # reactor and nothing else.
            f"{maven_plugin_coordinate()}:makeAggregateBom",
            "-DoutputFormat=json",
            "-DoutputName=bom",
        ]
        logger.info(f"Running the CycloneDX Maven plugin in {project_dir.name}")
        _run_build(cmd, "cyclonedx-maven", project_dir, wrapper["tool"], 2400)
        produced = project_dir / "target" / "bom.json"
        if produced.exists():
            shutil.copy(produced, output)


class CycloneDXGradleGenerator(_JvmGenerator):
    """Gradle, via the CycloneDX Gradle plugin.

    288 components for okhttp against syft's 34, with cdxgen failing.
    """

    build_files = (
        "build.gradle",
        "build.gradle.kts",
        # gradle.lockfile is deliberately absent. This generator runs the
        # project's build; the lock file exists so that is unnecessary, and
        # GradleLockfileGenerator reads it directly. Claiming it here meant
        # winning the tie at equal priority and then failing the build, which
        # in strict mode aborts instead of falling through to the reader.
    )
    tool_name = "cyclonedx-gradle"
    runtime = "gradle"

    def _run(self, project_dir: Path, output: Path) -> None:
        init_script = project_dir / ".sbomify-cyclonedx.init.gradle"
        init_script.write_text(gradle_init_script())
        wrapper = _wrapper_spec("gradle", self.runtime)
        gradle = _wrapper_or(project_dir, wrapper)
        try:
            cmd = [gradle, "--no-daemon", "-I", str(init_script), "cyclonedxBom"]
            logger.info(f"Running the CycloneDX Gradle plugin in {project_dir.name}")
            _run_build(cmd, "cyclonedx-gradle", project_dir, wrapper["tool"], 2400)
            found = _largest_bom(sorted(project_dir.rglob("*bom.json")))
            if found:
                shutil.copy(found, output)
        finally:
            # Never leave our scaffolding in someone's checkout.
            init_script.unlink(missing_ok=True)


class CycloneDXSbtGenerator(_JvmGenerator):
    """sbt, via the sbt-sbom plugin.

    cdxgen cannot serve this at all: it drives sbt through
    net.virtual-void:sbt-dependency-graph, which is published for sbt 1.x only
    and fails to resolve for anything newer.
    """

    build_files = ("build.sbt",)
    tool_name = "cyclonedx-sbt"
    runtime = "sbt"

    def _run(self, project_dir: Path, output: Path) -> None:
        # sbt has no per-invocation plugin flag, so the plugin is dropped into
        # project/ and removed afterwards.
        plugin_dir = project_dir / "project"
        plugin_dir.mkdir(exist_ok=True)
        injected = plugin_dir / "sbomify-sbom.sbt"
        injected.write_text(f'addSbtPlugin("com.github.sbt" % "sbt-sbom" % "{sbt_plugin_version()}")\n')
        try:
            logger.info(f"Running the sbt-sbom plugin in {project_dir.name}")
            run_command(["sbt", "-batch", "makeBom"], "cyclonedx-sbt", timeout=2400, cwd=str(project_dir))
            found = _largest_bom([p for p in sorted(project_dir.rglob("*.bom.json"))])
            if found:
                shutil.copy(found, output)
        finally:
            injected.unlink(missing_ok=True)
