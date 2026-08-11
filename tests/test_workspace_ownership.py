"""Child processes must be able to read the workspace git repository.

git refuses a repository owned by a different UID than the process reading it
-- "detected dubious ownership" -- which is the normal state of affairs when a
workspace is bind-mounted into this container. The action already handles that
for the git commands it runs itself, in ``submodule.py`` and the wizard's
``repo_facts.py``, by passing ``-c safe.directory=*``.

The generators never run git directly, so that defence did not reach them.
They run tools that run git. Composer asks git for the tag at HEAD to
establish the root package's version; when the call fails it uses
``1.0.0+no-version-set``, and a project that depends on its own version --
laravel/framework, symfony/symfony -- then resolves to nothing at all. cdxgen
exits 1 having written no document, the chain falls through to syft, and syft
writes zero components and exits 0.

Measured on laravel/framework v13.24.0 in the published image, changing only
this: 0 components before, 72 after.
"""

import os
import shutil

import pytest

from sbomify_action._generation.utils import git_safe_directory_env, run_command


def config_from(env: dict[str, str]) -> dict[str, str]:
    """The git settings an environment declares, as git itself would read them."""
    count = int(env["GIT_CONFIG_COUNT"])
    return {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(count)}


class TestTheEnvironmentItBuilds:
    def test_it_declares_the_workspace_safe(self, monkeypatch):
        monkeypatch.delenv("GIT_CONFIG_COUNT", raising=False)
        assert config_from(git_safe_directory_env()) == {"safe.directory": "*"}

    def test_it_appends_to_configuration_the_caller_already_set(self, monkeypatch):
        # Dropping these would silently discard settings the caller depends on,
        # and git reads only as many pairs as the count claims.
        monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
        monkeypatch.setenv("GIT_CONFIG_KEY_0", "user.name")
        monkeypatch.setenv("GIT_CONFIG_VALUE_0", "someone")

        merged = {**os.environ, **git_safe_directory_env()}
        assert config_from(merged) == {"user.name": "someone", "safe.directory": "*"}

    @pytest.mark.parametrize("garbage", ["", "not-a-number", "-1"])
    def test_an_unusable_count_starts_over_rather_than_propagating(self, monkeypatch, garbage):
        monkeypatch.setenv("GIT_CONFIG_COUNT", garbage)
        assert config_from(git_safe_directory_env()) == {"safe.directory": "*"}


class TestWhatChildrenActuallyReceive:
    def test_a_child_sees_the_setting(self, tmp_path):
        script = tmp_path / "show.py"
        script.write_text("import os; print(os.environ.get('GIT_CONFIG_VALUE_0', 'unset'))")

        result = run_command(["python3", str(script)], "show")

        assert result.stdout.strip() == "*"

    def test_the_caller_keeps_the_last_word(self, tmp_path):
        """An explicit env from the caller overrides the default rather than
        being overridden by it -- a generator that configures git deliberately
        must stay in control."""
        script = tmp_path / "show.py"
        script.write_text("import os; print(os.environ['GIT_CONFIG_VALUE_0'])")

        result = run_command(["python3", str(script)], "show", env={"GIT_CONFIG_VALUE_0": "/only/this"})

        assert result.stdout.strip() == "/only/this"

    def test_the_rest_of_the_environment_survives(self, tmp_path, monkeypatch):
        """Generators need the PATH, HOME and proxy settings they started with."""
        monkeypatch.setenv("SBOMIFY_CANARY", "still-here")
        script = tmp_path / "show.py"
        script.write_text("import os; print(os.environ.get('SBOMIFY_CANARY', 'lost'))")

        result = run_command(["python3", str(script)], "show")

        assert result.stdout.strip() == "still-here"


# shutil.which rather than shelling out to `which`: this is evaluated while
# the module is being collected, so a `which` that is itself missing -- a
# slim image, a non-POSIX host -- raises FileNotFoundError before skipif has
# any say, and the whole module fails to collect instead of skipping.
@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
class TestAgainstRealGit:
    def test_git_reads_the_setting_from_the_environment(self, tmp_path):
        """The whole mechanism rests on git honouring GIT_CONFIG_COUNT, so read
        the value back out of git rather than trusting the variable names."""
        script = tmp_path / "show.sh"
        script.write_text("#!/bin/sh\nexec git config --get-all safe.directory\n")
        script.chmod(0o755)

        result = run_command([str(script)], "git-config")

        assert "*" in result.stdout.split()
