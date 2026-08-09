#!/usr/bin/env python3
"""Detect when sbomify_action/_enrichment/lifecycle_data.py has gone stale.

The lifecycle tables are hand-maintained from vendor sources, and nothing in the
pipeline notices when they fall behind: `get_distro_lifecycle` returns None for
an unknown release and `enrich_os_component` simply adds no CLE properties. A
user running on a distro we have not heard of gets a silently emptier SBOM. That
failure mode is why this script exists.

Two independent checks, deliberately separated:

  Local invariants (offline, no network)
      Structural facts that must hold regardless of what upstream says: dates
      parse, EOS never falls after EOL, every distro still has at least one
      release that has not gone EOL, and the license-db generator's version list
      has not drifted away from the lifecycle table. tests/test_lifecycle_freshness.py
      runs these on every CI run.

  Upstream coverage (network, endoflife.date)
      Reports release cycles that upstream knows about and we do not.

      endoflife.date is a community aggregator and is explicitly NOT a source of
      truth for dates -- lifecycle_data.py requires vendor-published dates with
      the source URL recorded. It is used here only to answer "is there a release
      we have not noticed yet?", which is a question it is reliable enough for.
      When it flags something, go and read the vendor's page, then hand-write the
      entry. That is also why this compares cycle *coverage* rather than dates:
      our tier mappings are deliberate editorial choices (see the Ubuntu and
      Oracle notes in lifecycle_data.py) and will not match field-for-field.

Usage:
    python scripts/check_lifecycle_staleness.py            # both checks
    python scripts/check_lifecycle_staleness.py --offline  # invariants only
    python scripts/check_lifecycle_staleness.py --format=markdown

Exit codes: 0 clean, 1 problems found, 2 the check itself failed to run.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sbomify_action._enrichment.license_db_generator import (  # noqa: E402
    DEBIAN_CODENAMES,
    RPM_DISTRO_REPOS,
    UBUNTU_CODENAMES,
)
from sbomify_action._enrichment.lifecycle_data import (  # noqa: E402
    DISTRO_LIFECYCLE,
    PACKAGE_LIFECYCLE,
)

EOL_API = "https://endoflife.date/api/{product}.json"

#: Our table key -> endoflife.date product slug. Anything not listed here is not
#: checked upstream (Wolfi is a rolling release with no cycles to compare).
DISTRO_SLUGS = {
    "alpine": "alpine",
    "almalinux": "almalinux",
    "amazonlinux": "amazon-linux",
    "centos": "centos-stream",
    "debian": "debian",
    "fedora": "fedora",
    "opensuse-leap": "opensuse",
    "oracle": "oracle-linux",
    "rocky": "rocky-linux",
    "ubuntu": "ubuntu",
}

PACKAGE_SLUGS = {
    "dart": "dart",
    "django": "django",
    "flutter": "flutter",
    "golang": "go",
    "laravel": "laravel",
    "nodejs": "nodejs",
    "php": "php",
    "python": "python",
    "rails": "rails",
    "rust": "rust",
    "scala": "scala",
    "swift": "swift",
}


def _normalise_cycle(product: str, cycle: str) -> str:
    """Map an upstream cycle label onto the key style used in our tables."""
    if product == "centos":
        return f"stream{cycle}"
    return cycle


def _is_tracked_cycle(product: str, cycle: str) -> bool:
    """Should this upstream cycle appear in our table at all?

    Some lines are excluded on purpose, and without this the coverage check
    would report the same non-issues forever.
    """
    if product == "ubuntu":
        # Only LTS releases are tracked; interim releases get 9 months and are
        # not represented. LTS = an even year with an .04 month.
        try:
            year, month = cycle.split(".")
            return month == "04" and int(year) % 2 == 0
        except ValueError:
            return False
    return True


# =============================================================================
# Date handling
# =============================================================================


def parse_lifecycle_date(value: str) -> date | None:
    """Parse the date formats lifecycle_data.py allows, as an upper bound.

    Accepts 'YYYY-MM-DD', 'YYYY-MM' and 'YYYY-Qn'. Partial values resolve to the
    last day they could mean, so that "has this passed?" stays conservative: a
    release recorded as '2026-10' is not treated as expired until November.
    Returns None if the value is not a format we allow.
    """
    text = value.strip()

    try:
        if len(text) == 10:
            return date.fromisoformat(text)

        if len(text) == 7 and text[4] == "-":
            year = int(text[:4])
            if text[5] == "Q":
                quarter = int(text[6])
                if not 1 <= quarter <= 4:
                    return None
                month = quarter * 3
            else:
                month = int(text[5:])
                if not 1 <= month <= 12:
                    return None
            # Last day of that month.
            if month == 12:
                return date(year, 12, 31)
            return date.fromordinal(date(year, month + 1, 1).toordinal() - 1)
    except (ValueError, IndexError):
        return None

    return None


# =============================================================================
# Local invariants (offline)
# =============================================================================


def check_local_invariants(today: date | None = None) -> list[str]:
    """Structural checks that need no network. Returns a list of problems."""
    today = today or date.today()
    problems: list[str] = []

    # --- date well-formedness and EOS <= EOL, across both tables -------------
    def _check_cycles(label: str, name: str, cycles: dict) -> None:
        for cycle, dates in cycles.items():
            parsed = {}
            for field in ("release_date", "end_of_support", "end_of_life"):
                raw = dates.get(field)
                if raw is None:
                    continue
                value = parse_lifecycle_date(raw)
                if value is None:
                    problems.append(f"{label} {name} {cycle}: {field} {raw!r} is not a valid date format")
                else:
                    parsed[field] = value

            eos, eol = parsed.get("end_of_support"), parsed.get("end_of_life")
            if eos and eol and eos > eol:
                problems.append(
                    f"{label} {name} {cycle}: end_of_support ({dates['end_of_support']}) "
                    f"is after end_of_life ({dates['end_of_life']})"
                )

            release = parsed.get("release_date")
            if release and eol and release > eol:
                problems.append(
                    f"{label} {name} {cycle}: release_date ({dates['release_date']}) "
                    f"is after end_of_life ({dates['end_of_life']})"
                )

    for name, cycles in DISTRO_LIFECYCLE.items():
        _check_cycles("distro", name, cycles)
    for name, entry in PACKAGE_LIFECYCLE.items():
        _check_cycles("package", name, entry.get("cycles", {}))

    # --- every distro needs at least one release that is not yet EOL ---------
    # This is the check that would have caught openSUSE Leap sitting at 15.5/15.6
    # long after both had expired.
    for name, cycles in DISTRO_LIFECYCLE.items():
        if name == "wolfi":
            continue  # rolling release, no cycles
        live = False
        for dates in cycles.values():
            raw = dates.get("end_of_life")
            if raw is None:
                live = True  # still supported, EOL not yet published
                break
            value = parse_lifecycle_date(raw)
            if value is None or value >= today:
                live = True
                break
        if not live:
            newest = max(cycles, key=lambda c: cycles[c].get("end_of_life") or "")
            problems.append(
                f"distro {name}: every tracked release has passed end-of-life "
                f"(newest is {newest}, EOL {cycles[newest].get('end_of_life')}) -- "
                f"a newer release almost certainly exists"
            )

    # --- the license-db generator and the lifecycle table must agree ---------
    # These are maintained in different files and drift silently otherwise: a
    # distro version can get a license database built with no lifecycle data
    # attached, or lifecycle data that no database is ever built for.
    #
    # Only distros where the generator pins an explicit per-version config are
    # comparable. Alpine builds its repository URL straight from the version
    # string, and Wolfi is a rolling release, so neither has a version list to
    # compare against.
    generator_versions: dict[str, set[str]] = {
        "ubuntu": set(UBUNTU_CODENAMES),
        "debian": set(DEBIAN_CODENAMES),
    }
    for distro, versions in RPM_DISTRO_REPOS.items():
        generator_versions[distro] = set(versions)

    for distro, versions in sorted(generator_versions.items()):
        tracked = set(DISTRO_LIFECYCLE.get(distro, {}))
        for version in sorted(versions - tracked):
            problems.append(
                f"distro {distro} {version}: the license-db generator builds this version "
                f"but lifecycle_data.py has no entry for it"
            )
        for version in sorted(tracked - versions):
            # Retaining lifecycle data for a release the generator no longer
            # builds is correct and expected: SBOMs of old images still name
            # those releases, and we want to keep telling their consumers that
            # they are past EOL. Only a still-supported release missing from the
            # generator is a real gap.
            eol_raw = DISTRO_LIFECYCLE[distro][version].get("end_of_life")
            eol = parse_lifecycle_date(eol_raw) if eol_raw else None
            if eol is not None and eol < today:
                continue
            problems.append(
                f"distro {distro} {version}: lifecycle_data.py tracks this version "
                f"but the license-db generator has no repository configured for it"
            )

    return problems


# =============================================================================
# Upstream coverage (network)
# =============================================================================


def _fetch(product: str) -> list[dict] | None:
    url = EOL_API.format(product=product)
    req = urllib.request.Request(url, headers={"User-Agent": "sbomify-lifecycle-staleness-check"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # product not tracked upstream; not an error
        raise


#: How long after a release goes EOL upstream we still want to be told that we
#: never added it. Beyond this it is just history: we deliberately keep some
#: expired cycles (Alpine 3.13, Python 2.7) so that old images still get told
#: they are out of support, but we do not want to be nagged into backfilling
#: every release a project ever made.
RECENTLY_EOL_DAYS = 365

#: (product, cycle) pairs where endoflife.date is wrong and we have decided not
#: to follow it. Each needs a reason -- this is an override of the one signal we
#: have, so it should stay small and be revisited when upstream fixes its data.
UPSTREAM_NOISE = {
    # endoflife.date reports Scala 2.10 (December 2012) as having no EOL date,
    # which reads as "still supported". It is not: scala-lang.org lists 2.11.12
    # as the last 2.11 maintenance release and does not list 2.10 as maintained
    # at all. Adding it would mean inventing a support status Scala never gave.
    ("scala", "2.10"),
}


def _still_relevant(entry: dict, today: date) -> bool:
    """Is this upstream cycle current, or recent enough to be worth adding?"""
    raw = entry.get("eol")

    # endoflife.date uses `false` for "not end-of-life yet".
    if raw is False or raw is None:
        return True
    if raw is True:
        return False

    eol = parse_lifecycle_date(str(raw))
    if eol is None:
        return True  # unparseable, surface it rather than swallow it
    return (today - eol).days <= RECENTLY_EOL_DAYS


def check_upstream_coverage(today: date | None = None) -> tuple[list[str], list[str]]:
    """Report cycles upstream lists that we do not track.

    Only cycles that are still supported upstream -- or that went EOL within the
    last RECENTLY_EOL_DAYS -- are reported. Without that filter this returns
    every release each project ever made, which buries the one line that matters.

    Returns (findings, warnings). Warnings cover products we could not check.
    """
    today = today or date.today()
    findings: list[str] = []
    warnings: list[str] = []

    checks = [
        ("distro", DISTRO_SLUGS, lambda name: set(DISTRO_LIFECYCLE.get(name, {}))),
        ("package", PACKAGE_SLUGS, lambda name: set(PACKAGE_LIFECYCLE.get(name, {}).get("cycles", {}))),
    ]

    for label, slugs, tracked_for in checks:
        for name, slug in sorted(slugs.items()):
            try:
                upstream = _fetch(slug)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"{label} {name}: could not query endoflife.date/{slug} ({exc})")
                continue

            if upstream is None:
                warnings.append(f"{label} {name}: endoflife.date has no product '{slug}' -- check manually")
                continue

            tracked = tracked_for(name)
            for entry in upstream:
                cycle = str(entry.get("cycle", ""))
                if not cycle or not _is_tracked_cycle(name, cycle):
                    continue
                key = _normalise_cycle(name, cycle)
                if key in tracked or (name, key) in UPSTREAM_NOISE:
                    continue
                if not _still_relevant(entry, today):
                    continue
                released = entry.get("releaseDate") or "?"
                eol = entry.get("eol")
                state = "still supported" if eol in (False, None) else f"EOL {eol}"
                findings.append(
                    f"{label} {name}: cycle {key} (released {released}, {state}) is not in lifecycle_data.py"
                )

    return findings, warnings


# =============================================================================
# CLI
# =============================================================================


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="run only the local invariant checks")
    parser.add_argument("--format", choices=["text", "markdown"], default="text")
    args = parser.parse_args()

    try:
        problems = check_local_invariants()
        findings: list[str] = []
        warnings: list[str] = []
        if not args.offline:
            findings, warnings = check_upstream_coverage()
    except Exception as exc:  # noqa: BLE001
        print(f"lifecycle staleness check failed to run: {exc}", file=sys.stderr)
        return 2

    if args.format == "markdown":
        _report_markdown(problems, findings, warnings)
    else:
        _report_text(problems, findings, warnings)

    return 1 if (problems or findings) else 0


def _report_text(problems: list[str], findings: list[str], warnings: list[str]) -> None:
    if problems:
        print(f"Invariant failures ({len(problems)}):")
        for item in problems:
            print(f"  - {item}")
        print()
    if findings:
        print(f"Releases missing from lifecycle_data.py ({len(findings)}):")
        for item in findings:
            print(f"  - {item}")
        print()
    if warnings:
        print(f"Warnings ({len(warnings)}):")
        for item in warnings:
            print(f"  - {item}")
        print()
    if not problems and not findings:
        print("lifecycle_data.py is up to date.")


def _report_markdown(problems: list[str], findings: list[str], warnings: list[str]) -> None:
    if not problems and not findings:
        print("`lifecycle_data.py` is up to date.")
        return

    print("`sbomify_action/_enrichment/lifecycle_data.py` looks out of date.\n")
    print(
        "Dates must come from the vendor's own page, with the source URL recorded "
        "in the entry comment -- endoflife.date is only what noticed the gap, it is "
        "not an acceptable source for the values themselves.\n"
    )
    if problems:
        print(f"### Invariant failures ({len(problems)})\n")
        for item in problems:
            print(f"- {item}")
        print()
    if findings:
        print(f"### Releases we are not tracking ({len(findings)})\n")
        for item in findings:
            print(f"- {item}")
        print()
    if warnings:
        print("<details><summary>Warnings</summary>\n")
        for item in warnings:
            print(f"- {item}")
        print("\n</details>")


if __name__ == "__main__":
    sys.exit(main())
