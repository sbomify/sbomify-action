"""Tests for the CI runtime platform subsystem (sbomify_action._runtime)."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sbomify_action._runtime import (
    VcsInfo,
    create_default_registry,
    get_platform,
    reset_platform,
    set_platform,
    use_platform,
)
from sbomify_action._runtime.formatters import GitHubActionsFormatter, PlainFormatter
from sbomify_action._runtime.git import (
    commit_url_for,
    detect_vcs,
    git_safe_directory_env,
)
from sbomify_action._runtime.platforms import (
    BitbucketPlatform,
    CircleCIPlatform,
    GenericCIPlatform,
    GitHubPlatform,
    GitLabPlatform,
    JenkinsPlatform,
    LocalPlatform,
    TeamCityPlatform,
    TravisPlatform,
)
from sbomify_action._runtime.vcs_url import _is_known_git_host

GHA_ENV = {"GITHUB_ACTIONS": "true"}
GITLAB_ENV = {"GITLAB_CI": "true"}
BITBUCKET_ENV = {"BITBUCKET_PIPELINE_UUID": "{1234}"}
JENKINS_ENV = {"JENKINS_URL": "https://ci.example.com"}
CIRCLECI_ENV = {"CIRCLECI": "true"}
TRAVIS_ENV = {"TRAVIS": "true"}

#: The remote a Jenkins, Travis or TeamCity build actually has. These run next
#: to someone's own git server far more often than against github.com, so the
#: cases below are written around a self-hosted host that no commit-URL layout
#: is known for.
#:
#: The two forms are not interchangeable: CLONE is what a job is configured
#: with and what the vendor exports, BROWSE is what normalisation turns it into
#: and what reaches the SBOM.
SELF_HOSTED_CLONE_URL = "ssh://git@git.corp.example.com:7999/team/app.git"
SELF_HOSTED_BROWSE_URL = "https://git.corp.example.com/team/app"

#: Every platform except the one under test, for the "nothing else does this" checks.
NON_GITHUB_PLATFORMS = (
    GitLabPlatform(),
    BitbucketPlatform(),
    TeamCityPlatform(),
    JenkinsPlatform(),
    CircleCIPlatform(),
    TravisPlatform(),
    GenericCIPlatform(),
    LocalPlatform(),
)


class TestPlatformResolution(unittest.TestCase):
    """Which platform claims a given environment."""

    @patch.dict(os.environ, GHA_ENV, clear=True)
    def test_resolves_github_actions(self):
        """GITHUB_ACTIONS selects the GitHub platform."""
        self.assertEqual(get_platform().name, "github-actions")

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "1"}, clear=True)
    def test_accepts_alternative_truthy_values(self):
        """Detection accepts any conventional truthy value, not just 'true'."""
        self.assertEqual(get_platform().name, "github-actions")

    @patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=True)
    def test_falsy_value_does_not_detect(self):
        """An explicitly false flag does not select the platform."""
        self.assertEqual(get_platform().name, "local")

    @patch.dict(os.environ, GITLAB_ENV, clear=True)
    def test_resolves_gitlab_ci(self):
        """GITLAB_CI selects the GitLab platform."""
        self.assertEqual(get_platform().name, "gitlab-ci")

    @patch.dict(os.environ, BITBUCKET_ENV, clear=True)
    def test_resolves_bitbucket_pipelines(self):
        """BITBUCKET_PIPELINE_UUID selects the Bitbucket platform."""
        self.assertEqual(get_platform().name, "bitbucket-pipelines")

    @patch.dict(os.environ, {"TEAMCITY_VERSION": "2024.03"}, clear=True)
    def test_resolves_teamcity_as_its_own_platform(self):
        """TeamCity has a platform of its own, ahead of the generic fallback.

        It needs one: its repository details live in a build-properties file
        rather than the environment, and the git checkout alone cannot tell a
        Git VCS root from a Perforce one.
        """
        platform = get_platform()
        self.assertEqual(platform.name, "teamcity")
        self.assertTrue(platform.is_ci)
        self.assertIsInstance(platform, TeamCityPlatform)

    @patch.dict(os.environ, JENKINS_ENV, clear=True)
    def test_resolves_jenkins_as_its_own_platform(self):
        """JENKINS_URL selects the Jenkins platform, ahead of the generic one."""
        platform = get_platform()
        self.assertEqual(platform.name, "jenkins")
        self.assertTrue(platform.is_ci)
        self.assertIsInstance(platform, JenkinsPlatform)

    def test_jenkins_detects_on_every_marker_a_build_may_carry(self):
        """JENKINS_URL is not always there, and a container agent has neither name.

        Measured on a real controller running the documented Docker Pipeline
        agent: the container gets HUDSON_HOME and both cookies, but no
        JENKINS_URL (unset until the instance URL is configured) and no
        JENKINS_HOME.
        """
        for marker, value in (
            ("JENKINS_URL", "https://ci.example.com"),
            ("JENKINS_HOME", "/var/jenkins_home"),
            ("HUDSON_HOME", "/var/jenkins_home"),
            ("JENKINS_NODE_COOKIE", "c6c7e015-de8f-4a23-bd47-3eea9a20e126"),
            ("JENKINS_SERVER_COOKIE", "durable-30ec40576d0dceda"),
        ):
            with self.subTest(marker=marker), patch.dict(os.environ, {marker: value}, clear=True):
                self.assertEqual(get_platform().name, "jenkins")

    @patch.dict(os.environ, CIRCLECI_ENV, clear=True)
    def test_resolves_circleci_as_its_own_platform(self):
        """CIRCLECI selects the CircleCI platform."""
        platform = get_platform()
        self.assertEqual(platform.name, "circleci")
        self.assertTrue(platform.is_ci)
        self.assertIsInstance(platform, CircleCIPlatform)

    @patch.dict(os.environ, TRAVIS_ENV, clear=True)
    def test_resolves_travis_as_its_own_platform(self):
        """TRAVIS selects the Travis CI platform."""
        platform = get_platform()
        self.assertEqual(platform.name, "travis-ci")
        self.assertTrue(platform.is_ci)
        self.assertIsInstance(platform, TravisPlatform)

    @patch.dict(os.environ, {"CI": "true"}, clear=True)
    def test_unrecognised_ci_falls_back_to_generic(self):
        """A build that only sets CI still counts as CI."""
        platform = get_platform()
        self.assertEqual(platform.name, "generic-ci")
        self.assertTrue(platform.is_ci)

    @patch.dict(os.environ, {"CI": "false"}, clear=True)
    def test_ci_false_is_not_a_ci_run(self):
        """CI is a boolean and must be read as one.

        Some toolchains export CI=false locally; treating a set-but-false flag
        as CI would refuse the interactive wizard on a developer's machine.
        """
        platform = get_platform()
        self.assertEqual(platform.name, "local")
        self.assertFalse(platform.is_ci)

    @patch.dict(os.environ, {"CI": "0"}, clear=True)
    def test_ci_zero_is_not_a_ci_run(self):
        """'0' is falsy for the same reason."""
        self.assertEqual(get_platform().name, "local")

    @patch.dict(os.environ, {}, clear=True)
    def test_resolves_local_when_nothing_matches(self):
        """An empty environment resolves to the local platform."""
        platform = get_platform()
        self.assertEqual(platform.name, "local")
        self.assertFalse(platform.is_ci)

    @patch.dict(os.environ, {**GHA_ENV, **GITLAB_ENV, "CI": "true"}, clear=True)
    def test_vendor_platforms_beat_generic_and_local(self):
        """Priority order decides when several platforms would detect."""
        self.assertEqual(get_platform().name, "github-actions")

    def test_registry_always_resolves(self):
        """The default registry has a catch-all, so resolve() never returns None."""
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNotNone(create_default_registry().resolve())

    def test_registry_is_sorted_by_priority(self):
        """get_platforms() returns platforms in detection order."""
        priorities = [p.priority for p in create_default_registry().get_platforms()]
        self.assertEqual(priorities, sorted(priorities))

    def test_every_platform_is_reached_before_the_fallbacks(self):
        """Vendor platforms are tried first, then generic CI, then local.

        Supporting another CI system is one module and one register() call, so
        this ordering is the whole contract: a new vendor slots in ahead of the
        two fallbacks and nothing else in the codebase has to learn about it.
        """
        names = [p.name for p in create_default_registry().get_platforms()]
        self.assertEqual(
            names,
            [
                "github-actions",
                "gitlab-ci",
                "bitbucket-pipelines",
                "teamcity",
                "jenkins",
                "circleci",
                "travis-ci",
                "generic-ci",
                "local",
            ],
        )

    def test_every_registered_platform_satisfies_the_protocol(self):
        """Each platform answers the full interface the codebase relies on.

        Catches a new platform that forgot a method before it reaches the one
        caller that happens to need it.
        """
        for platform in create_default_registry().get_platforms():
            with self.subTest(platform=platform.name):
                self.assertIsInstance(platform.name, str)
                self.assertIsInstance(platform.priority, int)
                self.assertIsInstance(platform.is_ci, bool)
                self.assertIsInstance(platform.confines_working_dir, bool)
                self.assertIsInstance(platform.detects(), bool)
                self.assertIsNotNone(platform.log_formatter())
                self.assertIsInstance(platform.telemetry_tags(), dict)
                self.assertIsInstance(platform.telemetry_context(), dict)


class TestPlatformOverride(unittest.TestCase):
    """Explicitly pinning a platform."""

    def tearDown(self):
        reset_platform()

    @patch.dict(os.environ, {}, clear=True)
    def test_use_platform_pins_and_restores(self):
        """use_platform pins for the block and restores afterwards."""
        self.assertEqual(get_platform().name, "local")
        with use_platform(GitHubPlatform()):
            self.assertEqual(get_platform().name, "github-actions")
        self.assertEqual(get_platform().name, "local")

    @patch.dict(os.environ, {}, clear=True)
    def test_use_platform_nests(self):
        """Nested pins restore the outer platform, not auto-detection."""
        with use_platform(GitHubPlatform()):
            with use_platform(GitLabPlatform()):
                self.assertEqual(get_platform().name, "gitlab-ci")
            self.assertEqual(get_platform().name, "github-actions")

    @patch.dict(os.environ, {}, clear=True)
    def test_reset_platform_resumes_detection(self):
        """reset_platform clears the pin."""
        set_platform(GitHubPlatform())
        self.assertEqual(get_platform().name, "github-actions")
        reset_platform()
        self.assertEqual(get_platform().name, "local")


class TestWorkspace(unittest.TestCase):
    """Where each platform says the checkout lives."""

    @patch.dict(os.environ, {**GHA_ENV, "GITHUB_WORKSPACE": "/runner/work/repo/repo"}, clear=True)
    def test_github_uses_workspace_variable(self):
        """GITHUB_WORKSPACE wins when the runner sets it."""
        self.assertEqual(get_platform().workspace(), Path("/runner/work/repo/repo"))

    @patch.dict(os.environ, GHA_ENV, clear=True)
    def test_github_falls_back_to_container_mount(self):
        """A container action without GITHUB_WORKSPACE uses the mount point."""
        self.assertEqual(get_platform().workspace(), Path("/github/workspace"))

    @patch.dict(os.environ, {**GITLAB_ENV, "CI_PROJECT_DIR": "/builds/group/project"}, clear=True)
    def test_gitlab_uses_project_dir(self):
        """GitLab reports CI_PROJECT_DIR."""
        self.assertEqual(get_platform().workspace(), Path("/builds/group/project"))

    @patch.dict(os.environ, {**BITBUCKET_ENV, "BITBUCKET_CLONE_DIR": "/opt/atlassian/repo"}, clear=True)
    def test_bitbucket_uses_clone_dir(self):
        """Bitbucket reports BITBUCKET_CLONE_DIR."""
        self.assertEqual(get_platform().workspace(), Path("/opt/atlassian/repo"))

    def test_jenkins_uses_its_workspace_variable(self):
        """A vendor's checkout variable is used when it has one."""
        with tempfile.TemporaryDirectory() as checkout:
            with patch.dict(os.environ, {**JENKINS_ENV, "WORKSPACE": checkout}, clear=True):
                self.assertEqual(get_platform().workspace(), Path(checkout))

    def test_travis_uses_its_build_dir(self):
        """Travis reports TRAVIS_BUILD_DIR."""
        with tempfile.TemporaryDirectory() as checkout:
            with patch.dict(os.environ, {**TRAVIS_ENV, "TRAVIS_BUILD_DIR": checkout}, clear=True):
                self.assertEqual(get_platform().workspace(), Path(checkout))

    def test_generic_ci_uses_vendor_checkout_path(self):
        """A recognised generic vendor's checkout variable is used too."""
        with tempfile.TemporaryDirectory() as checkout:
            with patch.dict(os.environ, {"BUILDKITE": "true", "BUILDKITE_BUILD_CHECKOUT_PATH": checkout}, clear=True):
                self.assertEqual(get_platform().workspace(), Path(checkout))

    def test_a_tilde_checkout_path_is_expanded(self):
        """CircleCI's default working_directory is the literal string ~/project.

        Taken at face value that is a *relative* path with a literal ~, so git
        would run against a directory that does not exist and silently report
        nothing -- the exact case this platform exists to make work.
        """
        with tempfile.TemporaryDirectory() as home:
            checkout = Path(home) / "project"
            checkout.mkdir()
            env = {**CIRCLECI_ENV, "CIRCLE_WORKING_DIRECTORY": "~/project", "HOME": home}
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(get_platform().workspace(), checkout)

    def test_a_second_checkout_variable_is_tried_when_the_first_is_not_here(self):
        """Azure Pipelines publishes two, and a container job sees the first as a host path.

        BUILD_REPOSITORY_LOCALPATH is where the agent put the checkout on the
        host; inside a container that path is routinely absent while
        SYSTEM_DEFAULTWORKINGDIRECTORY is mounted. Stopping at the first
        variable that happened to be set would fall back to the cwd with the
        real answer sitting in the next one.
        """
        with tempfile.TemporaryDirectory() as checkout:
            env = {
                "TF_BUILD": "True",
                "BUILD_REPOSITORY_LOCALPATH": "/agent/_work/1/s",
                "SYSTEM_DEFAULTWORKINGDIRECTORY": checkout,
            }
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(get_platform().workspace(), Path(checkout))

    def test_a_checkout_path_that_is_not_here_falls_back_to_cwd(self):
        """A vendor variable holding a host-side path is not trusted blindly.

        Inside a container that path routinely does not exist; using it would
        point every lookup at nothing.
        """
        env = {**JENKINS_ENV, "WORKSPACE": "/does/not/exist/here"}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(get_platform().workspace(), Path.cwd())

    @patch.dict(os.environ, {"TEAMCITY_VERSION": "2024.03"}, clear=True)
    def test_generic_ci_falls_back_to_cwd(self):
        """TeamCity publishes no checkout variable, so the cwd is the answer.

        This is what makes `docker run -v "$PWD:/src" -w /src` correct on
        TeamCity without any GitHub-specific mount path.
        """
        self.assertEqual(get_platform().workspace(), Path.cwd())

    @patch.dict(os.environ, {}, clear=True)
    def test_local_uses_cwd(self):
        """The local platform reports the process working directory."""
        self.assertEqual(get_platform().workspace(), Path.cwd())


class TestLocalVcsIsOptIn(unittest.TestCase):
    """A non-CI run does not start emitting VCS metadata on its own."""

    @patch.dict(os.environ, {}, clear=True)
    @patch("sbomify_action._runtime.platforms.base.detect_vcs")
    def test_local_does_not_read_the_checkout_by_default(self, mock_detect):
        """The same lock file must not produce a different SBOM off CI.

        Before platforms existed a local run emitted no VCS fields at all.
        Reading the checkout automatically would change the document for
        identical input, and write an internal remote into something often
        shared outside the company.
        """
        self.assertIsNone(LocalPlatform().vcs())
        mock_detect.assert_not_called()

    @patch.dict(os.environ, {"SBOMIFY_LOCAL_VCS": "true"}, clear=True)
    @patch("sbomify_action._runtime.platforms.base.detect_vcs")
    def test_local_reads_the_checkout_when_asked(self, mock_detect):
        """SBOMIFY_LOCAL_VCS opts in."""
        mock_detect.return_value = VcsInfo(url="https://github.com/owner/repo")
        self.assertEqual(LocalPlatform().vcs().url, "https://github.com/owner/repo")

    @patch.dict(os.environ, {"CI": "true"}, clear=True)
    @patch("sbomify_action._runtime.platforms.base.detect_vcs")
    def test_ci_still_reads_the_checkout_automatically(self, mock_detect):
        """The opt-in is for local runs only; on CI this is the whole feature."""
        mock_detect.return_value = VcsInfo(url="https://github.com/owner/repo")
        self.assertIsNotNone(get_platform().vcs())
        mock_detect.assert_called()


class TestWorkingDirConfinement(unittest.TestCase):
    """Only a platform that mounts a fixed checkout confines --working-dir."""

    def test_only_github_confines(self):
        """GitHub Actions confines; nothing else does."""
        self.assertTrue(GitHubPlatform().confines_working_dir)
        others = NON_GITHUB_PLATFORMS
        for platform in others:
            self.assertFalse(platform.confines_working_dir, platform.name)


class TestLogFormatters(unittest.TestCase):
    """Which dialect each platform speaks."""

    def test_github_uses_workflow_commands(self):
        """GitHub Actions gets the workflow-command formatter."""
        formatter = GitHubPlatform().log_formatter()
        self.assertIsInstance(formatter, GitHubActionsFormatter)
        self.assertTrue(formatter.force_terminal)
        self.assertFalse(formatter.show_log_time)

    def test_other_platforms_use_plain_output(self):
        """Everything else gets Rich styling and its own timestamps."""
        others = NON_GITHUB_PLATFORMS
        for platform in others:
            formatter = platform.log_formatter()
            self.assertIsInstance(formatter, PlainFormatter, platform.name)
            self.assertIsNone(formatter.force_terminal, platform.name)
            self.assertTrue(formatter.show_log_time, platform.name)

    def test_github_formatter_emits_annotations(self):
        """Workflow commands are written to stdout verbatim."""
        formatter = GitHubActionsFormatter()
        with patch("builtins.print") as mock_print:
            formatter.warning("careful")
            mock_print.assert_called_with("::warning::careful")
            formatter.error("broke", "Title")
            mock_print.assert_called_with("::error title=Title::broke")
            formatter.notice("fyi")
            mock_print.assert_called_with("::notice::fyi")
            formatter.group_start("Details")
            mock_print.assert_called_with("::group::Details")
            formatter.group_end()
            mock_print.assert_called_with("::endgroup::")

    def test_plain_formatter_emits_no_annotations(self):
        """Grouping is a no-op where the platform cannot collapse output."""
        formatter = PlainFormatter()
        with patch("builtins.print") as mock_print:
            formatter.group_start("Details")
            formatter.group_end()
            mock_print.assert_not_called()


class TestOidc(unittest.TestCase):
    """Which platforms can mint an OIDC token."""

    @patch.dict(
        os.environ,
        {
            **GHA_ENV,
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://runner/token",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "bearer",
        },
        clear=True,
    )
    def test_github_offers_oidc_when_id_token_granted(self):
        """A workflow with id-token: write gets a provider."""
        provider = get_platform().oidc()
        self.assertIsNotNone(provider)
        self.assertEqual(provider.exchange_slug, "github")

    @patch.dict(os.environ, GHA_ENV, clear=True)
    def test_github_offers_no_oidc_without_id_token(self):
        """Detected GitHub Actions is not enough — the runner must expose the endpoint."""
        self.assertIsNone(get_platform().oidc())

    def test_other_platforms_offer_no_oidc(self):
        """No other platform has an accepted issuer yet."""
        others = NON_GITHUB_PLATFORMS
        for platform in others:
            self.assertIsNone(platform.oidc(), platform.name)


class TestTelemetry(unittest.TestCase):
    """What each platform is willing to report."""

    @patch.dict(
        os.environ,
        {
            **GHA_ENV,
            "GITHUB_REPOSITORY_VISIBILITY": "public",
            "GITHUB_REPOSITORY": "owner/repo",
            "GITHUB_WORKFLOW": "build",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": "abcdef1234567890",
            "GITHUB_RUN_ID": "42",
        },
        clear=True,
    )
    def test_public_github_repo_reports_identifiers(self):
        """A public repository may be named in tags and context."""
        platform = get_platform()
        tags = platform.telemetry_tags()
        self.assertEqual(tags["ci.platform"], "github-actions")
        self.assertEqual(tags["repo.public"], "True")
        self.assertEqual(tags["ci.repository"], "owner/repo")
        # The tag carries a short SHA; the context keeps the full one.
        self.assertEqual(tags["ci.sha"], "abcdef1")

        context = platform.telemetry_context()
        self.assertEqual(context["sha"], "abcdef1234567890")
        self.assertEqual(context["run_id"], "42")

    @patch.dict(
        os.environ,
        {**GHA_ENV, "GITHUB_REPOSITORY_VISIBILITY": "private", "GITHUB_REPOSITORY": "owner/secret"},
        clear=True,
    )
    def test_private_github_repo_reports_nothing_identifying(self):
        """A private repository contributes no identifiers at all."""
        platform = get_platform()
        tags = platform.telemetry_tags()
        self.assertEqual(tags, {"ci.platform": "github-actions", "repo.public": "False"})
        self.assertEqual(platform.telemetry_context(), {})

    @patch.dict(os.environ, {**GHA_ENV, "GITHUB_REPOSITORY": "owner/repo"}, clear=True)
    def test_unset_visibility_is_treated_as_private(self):
        """Absent visibility is read conservatively."""
        self.assertEqual(get_platform().telemetry_tags()["repo.public"], "False")

    @patch.dict(os.environ, BITBUCKET_ENV, clear=True)
    def test_bitbucket_is_always_treated_as_private(self):
        """Bitbucket exposes no visibility, so nothing is reported."""
        platform = get_platform()
        self.assertEqual(platform.telemetry_tags()["repo.public"], "False")
        self.assertEqual(platform.telemetry_context(), {})

    @patch.dict(os.environ, {}, clear=True)
    def test_local_keeps_reporting_the_original_platform_value(self):
        """ci.platform stays "unknown" for platforms that never had a name.

        Saved Sentry searches and alert rules are keyed on that value, so the
        newly available detail is additive in ci.vendor rather than a
        replacement.
        """
        self.assertEqual(get_platform().telemetry_tags(), {"ci.platform": "unknown", "ci.vendor": "local"})

    @patch.dict(os.environ, {"BUILDKITE": "true"}, clear=True)
    def test_a_named_generic_vendor_is_reported_additively(self):
        """A vendor still on the generic platform is named without moving ci.platform."""
        tags = get_platform().telemetry_tags()
        self.assertEqual(tags["ci.platform"], "unknown")
        self.assertEqual(tags["ci.vendor"], "buildkite")

    def test_graduated_vendors_name_themselves_in_ci_platform(self):
        """A vendor with a platform of its own reports it like GitHub or GitLab.

        These three used to come through the generic fallback as
        ci.platform=unknown with the name in ci.vendor. Now that each is a
        platform, ci.platform is the name -- the tag means "the platform we
        resolved", and we resolved one.
        """
        for env, expected in ((JENKINS_ENV, "jenkins"), (CIRCLECI_ENV, "circleci"), (TRAVIS_ENV, "travis-ci")):
            with self.subTest(platform=expected), patch.dict(os.environ, env, clear=True):
                tags = get_platform().telemetry_tags()
                self.assertEqual(tags, {"ci.platform": expected, "repo.public": "False"})
                self.assertEqual(get_platform().telemetry_context(), {})


class TestJenkinsVcs(unittest.TestCase):
    """What Jenkins publishes, and what happens when it publishes nothing.

    Jenkins is nearly always someone's own server sitting next to their own git
    server, so a self-hosted remote -- Bitbucket Data Center on an SSH port, a
    corporate GitLab, a bare gitolite host -- is the normal case here and
    github.com is the exception. The cases below are written that way round.
    """

    def _vcs(self, **env):
        with patch.dict(os.environ, {**JENKINS_ENV, **env}, clear=True):
            return JenkinsPlatform().vcs()

    def test_reads_the_git_plugin_variables(self):
        """GIT_URL, GIT_COMMIT and GIT_BRANCH are the whole answer."""
        vcs = self._vcs(
            GIT_URL="https://git.corp.example.com/team/app.git",
            GIT_COMMIT="abc123",
            GIT_BRANCH="origin/main",
        )
        self.assertEqual(vcs.url, "https://git.corp.example.com/team/app")
        self.assertEqual(vcs.commit_sha, "abc123")
        self.assertEqual(vcs.ref, "main")

    def test_an_unrecognised_forge_gets_no_commit_url(self):
        """A self-hosted git server's commit path is unknowable from the URL.

        Guessing one produces a link that 404s in an attestation document,
        which is worse than the repository URL and SHA on their own.
        """
        vcs = self._vcs(GIT_URL="https://git.corp.example.com/team/app.git", GIT_COMMIT="abc123")
        self.assertIsNone(vcs.commit_url)

    def test_a_self_hosted_gitlab_keeps_its_commit_layout(self):
        """Self-hosted GitLab lays commits out exactly like gitlab.com."""
        vcs = self._vcs(GIT_URL="https://gitlab.corp.example.com/group/app.git", GIT_COMMIT="abc123")
        self.assertEqual(vcs.commit_url, "https://gitlab.corp.example.com/group/app/-/commit/abc123")

    def test_ssh_remotes_are_normalised_to_browse_urls(self):
        """GIT_URL is whatever the job was configured with, and that is usually SSH."""
        cases = (
            # Bitbucket Data Center's SSH port. An SSH port is not an HTTPS
            # port, so it is dropped rather than carried into a dead URL.
            ("ssh://git@git.corp.example.com:7999/team/app.git", "https://git.corp.example.com/team/app"),
            ("git@gitea.corp.example.com:team/app.git", "https://gitea.corp.example.com/team/app"),
            # A credential embedded in the remote must never reach the document.
            ("https://svc-build:s3cret@git.corp.example.com/team/app.git", "https://git.corp.example.com/team/app"),
            # An internal server on plain http, or a non-standard https port,
            # keeps both -- rewriting either produces a 404.
            ("http://git.internal:8080/team/app.git", "http://git.internal:8080/team/app"),
        )
        for raw, expected in cases:
            with self.subTest(url=raw):
                self.assertEqual(self._vcs(GIT_URL=raw).url, expected)

    def test_falls_back_to_the_numbered_url_of_a_multi_scm_job(self):
        """A job with several SCMs numbers the variables from 1."""
        self.assertEqual(
            self._vcs(GIT_URL_1="https://git.corp.example.com/team/app").url,
            "https://git.corp.example.com/team/app",
        )

    def test_remote_tracking_ref_forms_are_reduced_to_the_branch(self):
        """GIT_BRANCH is remote-tracking; an SBOM records the branch."""
        for branch, expected in (
            ("origin/main", "main"),
            ("refs/remotes/origin/feature/x", "feature/x"),
            ("refs/remotes/upstream/main", "main"),
            ("refs/heads/main", "main"),
            ("main", "main"),
        ):
            with self.subTest(branch=branch):
                self.assertEqual(self._vcs(GIT_URL=SELF_HOSTED_CLONE_URL, GIT_BRANCH=branch).ref, expected)

    def test_a_local_branch_checkout_wins_over_the_remote_tracking_name(self):
        """GIT_LOCAL_BRANCH already is the branch, with nothing to strip."""
        vcs = self._vcs(GIT_URL=SELF_HOSTED_CLONE_URL, GIT_LOCAL_BRANCH="main", GIT_BRANCH="origin/main")
        self.assertEqual(vcs.ref, "main")

    def test_a_multibranch_tag_build_reports_the_tag(self):
        """TAG_NAME is the ref of a tag build."""
        self.assertEqual(self._vcs(GIT_URL=SELF_HOSTED_CLONE_URL, TAG_NAME="v1.2.3").ref, "v1.2.3")

    def test_a_pull_request_build_reports_the_source_branch(self):
        """BRANCH_NAME on a PR build is Jenkins' own PR-42, not a ref.

        CHANGE_BRANCH is the branch the request came from, which is the thing
        someone reading the SBOM can actually check out.
        """
        vcs = self._vcs(GIT_URL=SELF_HOSTED_CLONE_URL, BRANCH_NAME="PR-42", CHANGE_BRANCH="feature/x")
        self.assertEqual(vcs.ref, "feature/x")

    @patch("sbomify_action._runtime.platforms.base.detect_vcs")
    def test_falls_back_to_the_checkout_without_git_variables(self, mock_detect):
        """A job on Subversion, Perforce or no SCM exports no GIT_URL.

        Behaviour there is exactly what it was before Jenkins had a platform.
        """
        mock_detect.return_value = VcsInfo(url="https://git.corp.example.com/team/app", commit_sha="abc123")
        with patch.dict(os.environ, JENKINS_ENV, clear=True):
            self.assertEqual(JenkinsPlatform().vcs().url, "https://git.corp.example.com/team/app")
        mock_detect.assert_called_once()

    @patch("sbomify_action._runtime.platforms.base.detect_vcs")
    def test_a_non_repository_git_url_falls_back_too(self, mock_detect):
        """A GIT_URL that does not normalise is no better than none at all.

        A local path is the case that matters: a Jenkins job pointed at a
        filesystem repository has a GIT_URL that is no use in a document.
        """
        mock_detect.return_value = None
        self.assertIsNone(self._vcs(GIT_URL="/srv/git/app.git"))
        mock_detect.assert_called_once()


class TestCircleCIVcs(unittest.TestCase):
    """What CircleCI publishes.

    CircleCI is hosted and only builds projects it has an integration with, so
    unlike Jenkins its remotes really are the three public forges.
    """

    def _vcs(self, **env):
        with patch.dict(os.environ, {**CIRCLECI_ENV, **env}, clear=True):
            return CircleCIPlatform().vcs()

    def test_reads_the_job_environment(self):
        """The clone URL is SSH for most projects and is normalised."""
        vcs = self._vcs(
            CIRCLE_REPOSITORY_URL="git@github.com:owner/repo.git",
            CIRCLE_SHA1="abc123",
            CIRCLE_BRANCH="main",
        )
        self.assertEqual(vcs.url, "https://github.com/owner/repo")
        self.assertEqual(vcs.commit_sha, "abc123")
        self.assertEqual(vcs.ref, "main")
        self.assertEqual(vcs.commit_url, "https://github.com/owner/repo/commit/abc123")

    def test_a_bitbucket_project_gets_bitbucket_commit_urls(self):
        """CircleCI builds Bitbucket and GitLab projects too, not only GitHub."""
        vcs = self._vcs(CIRCLE_REPOSITORY_URL="git@bitbucket.org:team/repo.git", CIRCLE_SHA1="abc123")
        self.assertEqual(vcs.url, "https://bitbucket.org/team/repo")
        self.assertEqual(vcs.commit_url, "https://bitbucket.org/team/repo/commits/abc123")

    def test_a_tag_build_reports_the_tag(self):
        """CIRCLE_BRANCH is empty on a tag build, and empty is not a value."""
        vcs = self._vcs(CIRCLE_REPOSITORY_URL="https://github.com/o/r", CIRCLE_BRANCH="", CIRCLE_TAG="v1.2.3")
        self.assertEqual(vcs.ref, "v1.2.3")

    @patch("sbomify_action._runtime.platforms.base.detect_vcs")
    def test_falls_back_to_the_checkout_without_a_repository_url(self, mock_detect):
        """A job that did not use the checkout step publishes no URL."""
        mock_detect.return_value = VcsInfo(url="https://github.com/owner/repo")
        with patch.dict(os.environ, CIRCLECI_ENV, clear=True):
            self.assertEqual(CircleCIPlatform().vcs().url, "https://github.com/owner/repo")
        mock_detect.assert_called_once()


class TestTravisVcs(unittest.TestCase):
    """Travis publishes no repository URL, so the checkout supplies it.

    Travis served GitHub, Bitbucket, GitLab and Assembla, and Travis Enterprise
    sat in front of self-hosted servers, so the remote is written here as one
    of those rather than assumed to be github.com.
    """

    def _vcs(self, checkout, **env):
        with patch("sbomify_action._runtime.platforms.base.detect_vcs", return_value=checkout):
            with patch.dict(os.environ, {**TRAVIS_ENV, **env}, clear=True):
                return TravisPlatform().vcs()

    def test_url_comes_from_the_checkout_and_the_ref_from_the_job(self):
        """Travis leaves a detached HEAD, so the checkout cannot name the branch."""
        checkout = VcsInfo(url=SELF_HOSTED_BROWSE_URL, commit_sha="abc123", ref=None)
        vcs = self._vcs(checkout, TRAVIS_COMMIT="abc123", TRAVIS_BRANCH="main")
        self.assertEqual(vcs.url, SELF_HOSTED_BROWSE_URL)
        self.assertEqual(vcs.commit_sha, "abc123")
        self.assertEqual(vcs.ref, "main")
        # An unrecognised forge gets no guessed commit link.
        self.assertIsNone(vcs.commit_url)

    def test_the_job_commit_wins_and_the_commit_url_follows_it(self):
        """A stale checkout SHA must not be linked as if it were this build's."""
        checkout = VcsInfo(url="https://gitlab.corp.example.com/group/app", commit_sha="stale")
        vcs = self._vcs(checkout, TRAVIS_COMMIT="abc123")
        self.assertEqual(vcs.commit_sha, "abc123")
        self.assertEqual(vcs.commit_url, "https://gitlab.corp.example.com/group/app/-/commit/abc123")

    def test_a_tag_build_reports_the_tag(self):
        """TRAVIS_BRANCH repeats the tag name on a tag build; TRAVIS_TAG is explicit."""
        checkout = VcsInfo(url=SELF_HOSTED_BROWSE_URL)
        self.assertEqual(self._vcs(checkout, TRAVIS_TAG="v1.2.3", TRAVIS_BRANCH="v1.2.3").ref, "v1.2.3")

    def test_a_pull_request_build_reports_the_source_branch(self):
        """TRAVIS_BRANCH on a PR build is the branch being merged *into*."""
        checkout = VcsInfo(url=SELF_HOSTED_BROWSE_URL)
        vcs = self._vcs(checkout, TRAVIS_BRANCH="main", TRAVIS_PULL_REQUEST_BRANCH="feature/x")
        self.assertEqual(vcs.ref, "feature/x")

    def test_nothing_is_reported_when_the_checkout_has_no_remote(self):
        """There is no repository URL to fall back on, so there is no metadata."""
        self.assertIsNone(self._vcs(None, TRAVIS_BRANCH="main"))


class TestCommitUrl(unittest.TestCase):
    """Per-forge commit URL layouts."""

    def test_github_layout(self):
        """GitHub uses /commit/<sha>."""
        self.assertEqual(
            commit_url_for("https://github.com/owner/repo", "abc123"),
            "https://github.com/owner/repo/commit/abc123",
        )

    def test_gitlab_layout(self):
        """GitLab uses /-/commit/<sha>."""
        self.assertEqual(
            commit_url_for("https://gitlab.com/group/project", "abc123"),
            "https://gitlab.com/group/project/-/commit/abc123",
        )

    def test_bitbucket_layout(self):
        """Bitbucket uses /commits/<sha>."""
        self.assertEqual(
            commit_url_for("https://bitbucket.org/team/repo", "abc123"),
            "https://bitbucket.org/team/repo/commits/abc123",
        )

    def test_self_hosted_instance_keeps_vendor_layout(self):
        """A self-hosted host is matched by vendor name."""
        self.assertEqual(
            commit_url_for("https://gitlab.mycompany.com/group/project", "abc123"),
            "https://gitlab.mycompany.com/group/project/-/commit/abc123",
        )

    def test_self_hosted_bitbucket_gets_no_commit_url(self):
        """Bitbucket Data Center does not keep the cloud path layout.

        Server puts commits under /projects/<KEY>/repos/<slug>/commits/<sha>, so
        matching on the host name alone would emit a URL that 404s -- and a dead
        link in an SBOM is worse than no link.
        """
        self.assertIsNone(commit_url_for("https://bitbucket.example.com/PROJ/repo", "abc123"))

    def test_unknown_forge_gets_no_commit_url(self):
        """An unrecognised host gets no URL rather than a guessed one."""
        self.assertIsNone(commit_url_for("https://git.example.org/owner/repo", "abc123"))

    def test_no_sha_gets_no_commit_url(self):
        """There is nothing to link to without a commit."""
        self.assertIsNone(commit_url_for("https://github.com/owner/repo", None))


class TestDetectVcs(unittest.TestCase):
    """Reading repository coordinates out of a git checkout."""

    @staticmethod
    def _git_responses(responses):
        """Build a _run_git side effect from an {args-tuple: output} mapping."""

        def side_effect(args, cwd):
            return responses.get(tuple(args))

        return side_effect

    @patch("sbomify_action._runtime.git._run_git")
    def test_reads_url_sha_and_branch(self, mock_git):
        """A normal checkout yields all four fields."""
        mock_git.side_effect = self._git_responses(
            {
                ("rev-parse", "--is-inside-work-tree"): "true",
                ("remote", "get-url", "origin"): "git@github.com:owner/repo.git",
                ("rev-parse", "HEAD"): "abc123def456",
                ("symbolic-ref", "--quiet", "--short", "HEAD"): "main",
            }
        )

        info = detect_vcs(Path("/repo"))

        self.assertEqual(info.url, "https://github.com/owner/repo")
        self.assertEqual(info.commit_sha, "abc123def456")
        self.assertEqual(info.ref, "main")
        self.assertEqual(info.commit_url, "https://github.com/owner/repo/commit/abc123def456")

    @patch("sbomify_action._runtime.git._run_git")
    def test_detached_head_falls_back_to_tag(self, mock_git):
        """CI checkouts are routinely detached; an exact tag is the useful ref."""
        mock_git.side_effect = self._git_responses(
            {
                ("rev-parse", "--is-inside-work-tree"): "true",
                ("remote", "get-url", "origin"): "https://github.com/owner/repo",
                ("rev-parse", "HEAD"): "abc123",
                # symbolic-ref fails on a detached HEAD
                ("describe", "--tags", "--exact-match"): "v1.2.3",
            }
        )

        self.assertEqual(detect_vcs(Path("/repo")).ref, "v1.2.3")

    @patch("sbomify_action._runtime.git._run_git")
    def test_detached_head_without_tag_has_no_ref(self, mock_git):
        """No branch and no tag simply means no ref."""
        mock_git.side_effect = self._git_responses(
            {
                ("rev-parse", "--is-inside-work-tree"): "true",
                ("remote", "get-url", "origin"): "https://github.com/owner/repo",
                ("rev-parse", "HEAD"): "abc123",
            }
        )

        info = detect_vcs(Path("/repo"))
        self.assertIsNone(info.ref)
        self.assertEqual(info.commit_sha, "abc123")

    @patch("sbomify_action._runtime.git._run_git")
    def test_falls_back_to_first_remote_when_no_origin(self, mock_git):
        """A checkout whose remote is not named origin still resolves."""
        mock_git.side_effect = self._git_responses(
            {
                ("rev-parse", "--is-inside-work-tree"): "true",
                ("remote",): "upstream\n",
                ("remote", "get-url", "upstream"): "https://github.com/owner/repo.git",
                ("rev-parse", "HEAD"): "abc123",
            }
        )

        self.assertEqual(detect_vcs(Path("/repo")).url, "https://github.com/owner/repo")

    @patch("sbomify_action._runtime.git._run_git")
    def test_returns_none_outside_a_work_tree(self, mock_git):
        """A directory that is not a repository yields nothing."""
        mock_git.side_effect = self._git_responses({})
        self.assertIsNone(detect_vcs(Path("/not-a-repo")))

    @patch("sbomify_action._runtime.git._run_git")
    def test_returns_none_without_a_remote(self, mock_git):
        """A repository with no remote has no URL worth recording."""
        mock_git.side_effect = self._git_responses(
            {
                ("rev-parse", "--is-inside-work-tree"): "true",
                ("remote",): "",
            }
        )
        self.assertIsNone(detect_vcs(Path("/repo")))

    def test_never_writes_to_git_config(self):
        """The ownership defence is passed per invocation, never persisted.

        Writing safe.directory into the user's global config would mutate state
        we do not own on what may be someone's own machine.
        """
        with patch("sbomify_action._runtime.git.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "true"
            mock_run.return_value.stderr = ""
            detect_vcs(Path("/repo"))

        self.assertTrue(mock_run.call_args_list)
        for call in mock_run.call_args_list:
            command = call.args[0]
            self.assertEqual(command[0], "git")
            self.assertNotIn("config", command)

    def test_ownership_defence_is_passed_to_every_call(self):
        """Each git invocation carries the safe.directory declaration.

        Git matches safe.directory against the repository top-level, not the
        directory the command runs in, which is why this is the wildcard from
        git_safe_directory_env rather than a path computed from the cwd: a
        WORKING_DIR pointing at a subdirectory would otherwise still be
        refused.
        """
        with patch("sbomify_action._runtime.git.subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "true"
            mock_run.return_value.stderr = ""
            detect_vcs(Path("/repo/packages/app"))

        self.assertTrue(mock_run.call_args_list)
        for call in mock_run.call_args_list:
            env = call.kwargs["env"]
            count = int(env["GIT_CONFIG_COUNT"])
            declared = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(count)}
            self.assertEqual(declared.get("safe.directory"), "*")

    def test_credentials_in_a_remote_never_reach_the_result(self):
        """A runner's tokenised origin must not be recorded in an SBOM."""
        mock_git = self._git_responses(
            {
                ("rev-parse", "--is-inside-work-tree"): "true",
                ("remote", "get-url", "origin"): "https://x-access-token:ghs_secret@github.com/owner/repo.git",
                ("rev-parse", "HEAD"): "abc123",
            }
        )
        with patch("sbomify_action._runtime.git._run_git", side_effect=mock_git):
            info = detect_vcs(Path("/repo"))

        self.assertEqual(info.url, "https://github.com/owner/repo")
        self.assertNotIn("ghs_secret", info.url)


class TestGitSafeDirectoryEnv(unittest.TestCase):
    """The environment handed to git and to the tools that run it."""

    @patch.dict(os.environ, {}, clear=True)
    def test_declares_the_workspace_safe(self):
        """With nothing preconfigured it declares exactly one setting."""
        env = git_safe_directory_env()
        self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "safe.directory")
        self.assertEqual(env["GIT_CONFIG_VALUE_0"], "*")

    @patch.dict(os.environ, {"GIT_CONFIG_COUNT": "2"}, clear=True)
    def test_appends_to_existing_settings(self):
        """A caller already configuring git this way keeps their settings."""
        env = git_safe_directory_env()
        self.assertEqual(env["GIT_CONFIG_COUNT"], "3")
        self.assertEqual(env["GIT_CONFIG_KEY_2"], "safe.directory")


class TestKnownGitHost(unittest.TestCase):
    """Matching a forge must not be defeated by the parts of a URL around it."""

    def test_a_plain_forge_url_matches(self):
        """The ordinary case."""
        self.assertTrue(_is_known_git_host("https://github.com/owner/repo"))

    def test_an_explicit_port_does_not_defeat_the_match(self):
        """netloc carries the port; hostname does not.

        `https://github.com:8443/o/r` is still GitHub, and reading netloc made
        it look like an unknown host.
        """
        self.assertTrue(_is_known_git_host("https://github.com:8443/owner/repo"))

    def test_userinfo_does_not_defeat_the_match(self):
        """Same for `user@` -- common on a CI runner's origin."""
        self.assertTrue(_is_known_git_host("https://user@github.com/owner/repo"))
        self.assertTrue(_is_known_git_host("https://user:token@gitlab.com/group/project"))

    def test_www_and_case_are_still_handled(self):
        """The prefix stripping and case folding survive the change."""
        self.assertTrue(_is_known_git_host("https://WWW.GitHub.com/owner/repo"))

    def test_an_unknown_host_still_does_not_match(self):
        """Widening the match must not make it match everything."""
        self.assertFalse(_is_known_git_host("https://git.corp.internal/owner/repo"))
        self.assertFalse(_is_known_git_host("not a url"))

    def test_a_malformed_port_still_reads_the_host(self):
        """`hostname` tolerates a non-numeric port (only `.port` raises).

        The host really is github.com, so matching is right -- and it must not
        raise either way, since this decides a normalization, not a security
        boundary.
        """
        self.assertTrue(_is_known_git_host("https://github.com:notaport/owner/repo"))


class TestRuntimeStaysALeaf(unittest.TestCase):
    """`_runtime` must not import the subsystems that import it.

    `console` resolves a platform while it is still being imported, so anything
    a platform reaches closes an import cycle. The dependency is easy to add by
    accident -- the TeamCity platform arrived with a function-level import of
    `_enrichment.sanitization`, which pulls in `console` and `logging_config` --
    and a plain module-level scan would not have caught it, so this walks every
    import node including the ones inside functions.
    """

    #: The one sanctioned reach-back: formatters fetch the Rich console lazily,
    #: inside the call, because writing to it is their whole job. By then
    #: console is fully imported. Nothing else may do this.
    ALLOWED = {("formatters.py", "sbomify_action.console")}

    #: Importing any of these from _runtime would close the cycle.
    FORBIDDEN = (
        "sbomify_action._augmentation",
        "sbomify_action._enrichment",
        "sbomify_action._generation",
        "sbomify_action._upload",
        "sbomify_action.console",
        "sbomify_action.logging_config",
    )

    def test_no_module_reaches_back_into_the_package(self):
        """No import anywhere under _runtime names a forbidden module."""
        import ast

        runtime = Path(__file__).parent.parent / "sbomify_action" / "_runtime"
        modules = sorted(runtime.rglob("*.py"))
        self.assertTrue(modules, "found no _runtime modules to check")

        for module in modules:
            tree = ast.parse(module.read_text(), filename=str(module))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    # level > 0 is a relative import, which stays inside _runtime.
                    names = [node.module] if node.module and node.level == 0 else []
                else:
                    continue

                for name in names:
                    if (module.name, name) in self.ALLOWED:
                        continue
                    for forbidden in self.FORBIDDEN:
                        with self.subTest(module=module.name, imports=name):
                            self.assertFalse(
                                name == forbidden or name.startswith(forbidden + "."),
                                f"{module.relative_to(runtime.parent)} line {node.lineno} imports {name}; "
                                f"_runtime may not depend on {forbidden}",
                            )


class TestVcsInfo(unittest.TestCase):
    """The VcsInfo value object."""

    def test_has_data_requires_a_url(self):
        """A SHA alone is not enough to record a repository."""
        self.assertTrue(VcsInfo(url="https://github.com/owner/repo").has_data())
        self.assertFalse(VcsInfo(commit_sha="abc123").has_data())
        self.assertFalse(VcsInfo().has_data())


if __name__ == "__main__":
    unittest.main()
