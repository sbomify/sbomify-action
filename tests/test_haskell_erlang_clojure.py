"""Three ecosystems the shipped tools could already read.

None of Haskell, Erlang or Clojure was listed anywhere, so a project in any of
them was told its lock file was not a recognised type. Nothing new is
installed to fix that: syft has had a haskell and an erlang cataloger all
along, and cdxgen takes ``-t clojure``. What was missing was the file names.

Measured before writing any of this, against real repositories:

    PostgREST/postgrest   stack.yaml / stack.yaml.lock   7 hackage packages
    erlang/rebar3         rebar.lock                     9 hex packages
    clj-kondo/clj-kondo   deps.edn / project.clj         9 components each

Deliberately not added, having tested them the same way: OCaml (``*.opam``
returned lwt's own seven sub-packages and no dependencies), R
(``DESCRIPTION`` returned the project itself) and Lua (``*.rockspec``, the
same). Those are manifest reads that would ship one-component documents --
the case declined in #349 -- rather than support.
"""

import pytest

from sbomify_action._generation.generators.cdxgen import CDXGEN_TYPE_MAP, CdxgenFsGenerator
from sbomify_action._generation.generators.syft import SyftFsGenerator
from sbomify_action._generation.protocol import GenerationInput
from sbomify_action._generation.utils import (
    ALL_LOCK_FILES,
    CDXGEN_LOCK_FILES,
    SYFT_LOCK_FILES,
    get_lock_file_ecosystem,
    is_supported_input,
)
from sbomify_action.cli.wizard.discovery import discover


@pytest.mark.parametrize(
    "name,ecosystem",
    [
        ("stack.yaml.lock", "haskell"),
        ("stack.yaml", "haskell"),
        ("cabal.project.freeze", "haskell"),
        ("rebar.lock", "erlang"),
        ("deps.edn", "clojure"),
        ("project.clj", "clojure"),
    ],
)
def test_the_file_is_recognised_and_mapped(name, ecosystem):
    assert is_supported_input(name), f"{name} is still an unrecognised input"
    assert name in ALL_LOCK_FILES
    assert get_lock_file_ecosystem(name) == ecosystem


@pytest.mark.parametrize("name", ["stack.yaml.lock", "stack.yaml", "cabal.project.freeze", "rebar.lock"])
def test_syft_claims_the_haskell_and_erlang_files(tmp_path, name):
    """syft is the only tool here with a cataloger for either."""
    assert name in SYFT_LOCK_FILES
    lock = tmp_path / name
    lock.write_text("")

    claimed = SyftFsGenerator().supports(
        GenerationInput(lock_file=str(lock), output_file=str(tmp_path / "o.json"), output_format="cyclonedx")
    )

    assert claimed


@pytest.mark.parametrize("name", ["deps.edn", "project.clj"])
def test_cdxgen_claims_the_clojure_files(tmp_path, name):
    """cdxgen is the only tool here that reads Clojure at all."""
    assert name in CDXGEN_LOCK_FILES
    assert name not in SYFT_LOCK_FILES
    lock = tmp_path / name
    lock.write_text("")

    claimed = CdxgenFsGenerator().supports(
        GenerationInput(lock_file=str(lock), output_file=str(tmp_path / "o.json"), output_format="cyclonedx")
    )

    assert claimed


def test_clojure_has_a_cdxgen_type():
    """Without the mapping cdxgen is invoked with no -t and scans everything."""
    assert CDXGEN_TYPE_MAP.get("clojure") == "clojure"


@pytest.mark.parametrize(
    "name,ecosystem",
    [
        ("stack.yaml.lock", "haskell"),
        ("rebar.lock", "erlang"),
        ("deps.edn", "clojure"),
    ],
)
def test_the_wizard_offers_them(tmp_path, name, ecosystem):
    (tmp_path / name).write_text("")

    found = discover(tmp_path)

    assert [str(f.rel_path) for f in found] == [name]
    assert found[0].ecosystem == ecosystem


def test_stack_lock_outranks_the_manifest_beside_it(tmp_path):
    """stack resolves stack.yaml into the .lock; the resolved file is the better read."""
    (tmp_path / "stack.yaml").write_text("")
    (tmp_path / "stack.yaml.lock").write_text("")

    found = discover(tmp_path)

    assert [str(f.rel_path) for f in found] == ["stack.yaml.lock"]


def test_deps_edn_wins_over_project_clj(tmp_path):
    """One entry per directory and ecosystem, so the two Clojure files compete.

    Neither is a lock file -- tools.deps and Leiningen both resolve at build
    time -- so this is only about which cdxgen is happier with, not about
    authority.
    """
    (tmp_path / "deps.edn").write_text("")
    (tmp_path / "project.clj").write_text("")

    found = discover(tmp_path)

    assert [str(f.rel_path) for f in found] == ["deps.edn"]


def test_a_clojure_project_does_not_displace_another_ecosystem(tmp_path):
    """Ranking competes within an ecosystem, never across them.

    The final list is ordered by path, so this asserts that both survive --
    adding Clojure must not cost a polyglot repo its Python entry.
    """
    (tmp_path / "deps.edn").write_text("")
    (tmp_path / "uv.lock").write_text("")

    found = {str(f.rel_path): f.ecosystem for f in discover(tmp_path)}

    assert found == {"deps.edn": "clojure", "uv.lock": "python"}


def _captured_syft(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(
        "sbomify_action._generation.generators.syft.run_command",
        lambda cmd, *a, **k: seen.update(cmd=cmd),
    )
    monkeypatch.setattr("sbomify_action._generation.generators.syft.ensure_runtime", lambda _t: None)
    return seen


def test_rebar_lock_is_scanned_as_a_directory(tmp_path, monkeypatch):
    """syft returns nothing for rebar.lock on its own.

    Measured on erlang/rebar3: the file as subject yields 0 packages, the
    parent directory yields 9. Listing rebar.lock without this would have
    shipped an empty document for every rebar3 project.
    """
    seen = _captured_syft(monkeypatch)
    project = tmp_path / "myapp"
    project.mkdir()
    lock = project / "rebar.lock"
    lock.write_text("")
    out = tmp_path / "o.json"
    out.write_text("{}")

    SyftFsGenerator().generate(GenerationInput(lock_file=str(lock), output_file=str(out), output_format="cyclonedx"))

    cmd = seen["cmd"]
    assert f"dir:{project}" in cmd, "rebar.lock must be scanned via its directory"
    assert str(lock) not in cmd
    # Scoped to the ecosystem, or the directory's GitHub Actions arrive too --
    # 14 of them on rebar3, against 9 real packages. Exactly one
    # --select-catalogers, carrying the ecosystem instead of the usual -file:
    # naming a cataloger set replaces the defaults rather than adding to them,
    # so both would be redundant and their merge order would matter.
    # Exactly one --select-catalogers, carrying both terms. Scoping to the
    # ecosystem keeps out the directory's 14 GitHub Actions; keeping `-file`
    # matters because selecting an ecosystem does *not* displace the file
    # catalogers -- in CycloneDX output `erlang` alone returns 9 libraries and
    # 6 file entries, `erlang,-file` returns the 9 alone.
    assert cmd.count("--select-catalogers") == 1
    assert cmd[cmd.index("--select-catalogers") + 1] == "erlang,-file"


def test_other_lock_files_are_still_scanned_directly(tmp_path, monkeypatch):
    """The directory subject is for rebar.lock alone, not a change of approach."""
    seen = _captured_syft(monkeypatch)
    lock = tmp_path / "stack.yaml.lock"
    lock.write_text("")
    out = tmp_path / "o.json"
    out.write_text("{}")

    SyftFsGenerator().generate(GenerationInput(lock_file=str(lock), output_file=str(out), output_format="cyclonedx"))

    cmd = seen["cmd"]
    assert str(lock) in cmd
    assert f"dir:{tmp_path}" not in cmd
