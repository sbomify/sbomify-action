"""Tests for the CI runtime platform subsystem (sbomify_action._runtime)."""

import os
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
    GenericCIPlatform,
    GitHubPlatform,
    GitLabPlatform,
    LocalPlatform,
    TeamCityPlatform,
)

GHA_ENV = {"GITHUB_ACTIONS": "true"}
GITLAB_ENV = {"GITLAB_CI": "true"}
BITBUCKET_ENV = {"BITBUCKET_PIPELINE_UUID": "{1234}"}


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

    @patch.dict(os.environ, {"JENKINS_URL": "https://ci.example.com"}, clear=True)
    def test_resolves_jenkins_as_generic_ci(self):
        """Jenkins is recognised by name through the generic platform."""
        self.assertEqual(get_platform().name, "jenkins")

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
            ["github-actions", "gitlab-ci", "bitbucket-pipelines", "teamcity", "generic-ci", "local"],
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

    @patch.dict(os.environ, {"JENKINS_URL": "https://ci", "WORKSPACE": "/var/jenkins/ws"}, clear=True)
    def test_generic_ci_uses_vendor_checkout_path(self):
        """A recognised vendor's checkout variable is used when it has one."""
        self.assertEqual(get_platform().workspace(), Path("/var/jenkins/ws"))

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


class TestWorkingDirConfinement(unittest.TestCase):
    """Only a platform that mounts a fixed checkout confines --working-dir."""

    def test_only_github_confines(self):
        """GitHub Actions confines; nothing else does."""
        self.assertTrue(GitHubPlatform().confines_working_dir)
        others = (GitLabPlatform(), BitbucketPlatform(), TeamCityPlatform(), GenericCIPlatform(), LocalPlatform())
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
        others = (GitLabPlatform(), BitbucketPlatform(), TeamCityPlatform(), GenericCIPlatform(), LocalPlatform())
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
        others = (GitLabPlatform(), BitbucketPlatform(), TeamCityPlatform(), GenericCIPlatform(), LocalPlatform())
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
    def test_local_reports_only_the_platform_name(self):
        """The local platform knows nothing it may safely report."""
        self.assertEqual(get_platform().telemetry_tags(), {"ci.platform": "local"})


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


class TestVcsInfo(unittest.TestCase):
    """The VcsInfo value object."""

    def test_has_data_requires_a_url(self):
        """A SHA alone is not enough to record a repository."""
        self.assertTrue(VcsInfo(url="https://github.com/owner/repo").has_data())
        self.assertFalse(VcsInfo(commit_sha="abc123").has_data())
        self.assertFalse(VcsInfo().has_data())


if __name__ == "__main__":
    unittest.main()
