"""Jenkins platform.

Jenkins publishes the repository details its Git plugin checked out --
``GIT_URL``, ``GIT_COMMIT``, ``GIT_BRANCH`` -- so they are read from the
environment like every other vendor rather than by shelling out to ``git``.
That matters beyond tidiness: the environment names the branch the *job* was
triggered for, while the checkout is routinely a detached HEAD that can only
report a tag, and on a multibranch pull-request build it names the source
branch, which the checkout cannot know at all.

The git checkout stays as the fallback, inherited from
:class:`GitCheckoutPlatform`. Jenkins is VCS-agnostic and a job may use
Subversion, Perforce or no SCM at all, in which case none of the ``GIT_*``
variables exist; the same is true of a scripted pipeline whose ``checkout``
step does not export them. Detection then behaves exactly as it did before
this platform existed.

Environment variables used:
- JENKINS_URL / JENKINS_HOME / HUDSON_HOME / JENKINS_NODE_COOKIE /
  JENKINS_SERVER_COOKIE: detection (see :data:`DETECTION_VARS`)
- WORKSPACE: checkout root
- GIT_URL (GIT_URL_1 with multiple SCMs): repository URL
- GIT_COMMIT: full commit SHA
- GIT_LOCAL_BRANCH / TAG_NAME / CHANGE_BRANCH / BRANCH_NAME / GIT_BRANCH: ref
"""

import logging
from pathlib import Path

from ..git import commit_url_for
from ..protocol import VcsInfo
from ..vcs_url import normalize_repo_url, strip_ref_prefix
from .base import GitCheckoutPlatform, env_checkout_dir, env_first, env_present

logger = logging.getLogger("sbomify_action")

#: Markers that say "this is a Jenkins build", in descending obviousness.
#:
#: ``JENKINS_URL`` alone is not enough, and this is not a theoretical worry: the
#: documented way to run the action on Jenkins is the container image as a
#: pipeline agent, and the Docker Pipeline plugin forwards the *build*
#: environment into the container, not the controller's. Against a real
#: controller (Jenkins 2.568.2, Docker Pipeline agent) the container gets
#: ``GIT_URL``, ``GIT_COMMIT``, ``GIT_BRANCH``, ``BUILD_NUMBER``, ``JOB_NAME``,
#: ``HUDSON_HOME`` and both cookies -- but no ``JENKINS_URL``, which Jenkins
#: only exports once someone has filled in the instance's own URL in the system
#: settings, and no ``JENKINS_HOME``.
#:
#: The cookies are the reliable pair: Jenkins sets ``JENKINS_NODE_COOKIE`` on
#: every build for its process-tree killer, and ``JENKINS_SERVER_COOKIE`` on
#: every durable task. ``HUDSON_HOME`` is the legacy alias of ``JENKINS_HOME``
#: and is exported in the build environment where the newer name is not.
DETECTION_VARS: tuple[str, ...] = (
    "JENKINS_URL",
    "JENKINS_HOME",
    "HUDSON_HOME",
    "JENKINS_NODE_COOKIE",
    "JENKINS_SERVER_COOKIE",
)

#: Prefix on the remote-tracking form of ``GIT_BRANCH``.
_REMOTES_PREFIX = "refs/remotes/"

#: The only remote name we are willing to strip from a bare ``origin/main``.
_DEFAULT_REMOTE_PREFIX = "origin/"


def _strip_remote_prefix(ref: str | None) -> str | None:
    """Reduce a remote-tracking branch name to the branch itself.

    ``GIT_BRANCH`` is remote-tracking: the Git plugin sets ``origin/main``, or
    ``refs/remotes/origin/main`` on older versions. An SBOM records the branch,
    so the remote has to come off.

    ``refs/remotes/<remote>/<branch>`` has a fixed layout, so any remote name
    can be dropped from it. The bare form does not -- ``upstream/main`` is
    indistinguishable from a branch literally named ``upstream/main`` -- so
    only ``origin/`` is stripped there, which is what Jenkins configures unless
    someone changed it.
    """
    ref = strip_ref_prefix(ref)
    if not ref:
        return None
    if ref.startswith(_REMOTES_PREFIX):
        _, _, branch = ref[len(_REMOTES_PREFIX) :].partition("/")
        return branch or None
    if ref.startswith(_DEFAULT_REMOTE_PREFIX):
        return ref[len(_DEFAULT_REMOTE_PREFIX) :] or None
    return ref


class JenkinsPlatform(GitCheckoutPlatform):
    """Jenkins agent."""

    name: str = "jenkins"
    priority: int = 50
    is_ci: bool = True

    def detects(self) -> bool:
        """True when running under a Jenkins job.

        Every marker carries a value rather than a boolean, so presence is the
        signal. See :data:`DETECTION_VARS` for why the list is not just
        ``JENKINS_URL``.
        """
        return env_present(*DETECTION_VARS)

    def workspace(self) -> Path | None:
        """Return ``WORKSPACE``, or the process working directory."""
        return env_checkout_dir(self.name, "WORKSPACE") or Path.cwd()

    def vcs(self) -> VcsInfo | None:
        """Read repository coordinates from the job's environment.

        Falls back to the git checkout when the job has no Git SCM attached, or
        has one that did not export its variables.
        """
        # GIT_URL is whatever the job was configured with, so it may be SSH or
        # carry an embedded credential; normalize it to a browse URL.
        vcs_url = normalize_repo_url(env_first("GIT_URL", "GIT_URL_1"))
        if not vcs_url:
            logger.debug("Jenkins exported no usable GIT_URL; reading VCS metadata from the checkout")
            return super().vcs()

        commit_sha = env_first("GIT_COMMIT")
        return VcsInfo(
            url=vcs_url,
            commit_sha=commit_sha,
            ref=self._ref(),
            commit_url=commit_url_for(vcs_url, commit_sha),
        )

    def _ref(self) -> str | None:
        """Return the branch or tag this build is for.

        In order of how directly each variable answers that question:

        - ``GIT_LOCAL_BRANCH`` is the branch name with no remote attached, set
          when the job checks out to a local branch.
        - ``TAG_NAME`` is a multibranch tag build.
        - ``CHANGE_BRANCH`` is the *source* branch of a multibranch pull
          request. It beats ``BRANCH_NAME``, which on that build is Jenkins'
          own ``PR-42`` -- a job name, not a ref anyone can check out.
        - ``BRANCH_NAME`` is the multibranch branch build.
        - ``GIT_BRANCH`` is the freestyle remote-tracking name, ``origin/main``.
        """
        if ref := env_first("GIT_LOCAL_BRANCH", "TAG_NAME", "CHANGE_BRANCH", "BRANCH_NAME"):
            return strip_ref_prefix(ref)
        return _strip_remote_prefix(env_first("GIT_BRANCH"))

    def telemetry_tags(self) -> dict[str, str]:
        """Platform tags.

        ``ci.platform`` names Jenkins now that it is a platform of its own,
        where the generic fallback used to report ``unknown`` with the vendor
        alongside it in ``ci.vendor``.

        Jenkins exposes no repository visibility -- there is no vendor to ask,
        and the repository may be on any host -- so it is treated as private,
        as on Bitbucket, and nothing identifying is reported.
        """
        return {"ci.platform": self.name, "repo.public": "False"}

    def telemetry_context(self) -> dict[str, str]:
        """No context -- visibility is unknown, so nothing is safe to report."""
        return {}
