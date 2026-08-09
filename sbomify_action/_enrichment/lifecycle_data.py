"""Lifecycle data for SBOM enrichment with CLE (Common Lifecycle Enumeration) fields.

This module centralizes lifecycle data for:
1. Linux distributions (used by license_db_generator and license_db source)
2. Language runtimes and frameworks (used by lifecycle enrichment source)

CLE fields follow ECMA-428 specification:
- release_date: First public stable release date for the cycle
- end_of_support: End of active/mainstream/bugfix support
- end_of_life: End of security support / extended support

See: https://sbomify.com/compliance/cle/

Data last updated: 2026-08-08

SOURCING RULE
-------------
Every date in this module MUST come from the vendor's own published lifecycle
page, and the URL it came from MUST be recorded in the block comment above the
entry. Third-party aggregators (endoflife.date, distrowatch, vendor-neutral
"EOL" sites) are NOT acceptable as the source of a date -- they are useful only
for *noticing* that we are out of date, which is what
`scripts/check_lifecycle_staleness.py` uses them for.

Where a vendor publishes a policy rather than a date (for example "supported for
24 months", or Go's "supported until there are two newer releases"), the value
is derived from that policy plus a vendor-published release date, and the
derivation is stated explicitly in the comment. Where a vendor has not published
a date at all, the field is None -- never a guess.
"""

from typing import Dict, List, Optional, TypedDict


class LifecycleDates(TypedDict, total=False):
    """Lifecycle dates for a single version/cycle."""

    release_date: Optional[str]  # ISO 8601 date or quarter string (e.g., "2026-Q1")
    end_of_support: Optional[str]  # ISO 8601 date or quarter string
    end_of_life: Optional[str]  # ISO 8601 date or quarter string


class PackageLifecycleEntry(TypedDict, total=False):
    """Lifecycle configuration for a package type."""

    name_patterns: List[str]  # Package name patterns to match (glob-style)
    purl_types: Optional[List[str]]  # PURL types to match, None = all types
    cycles: Dict[str, LifecycleDates]  # version cycle -> lifecycle dates
    version_extract: Optional[str]  # "major" or "major.minor" (default: major.minor)
    references: Optional[List[str]]  # Documentation references


# =============================================================================
# DISTRO_LIFECYCLE - Linux Distribution Lifecycle Data
# =============================================================================
#
# Schema:
#   release_date: ISO-8601 date (YYYY-MM-DD) or YYYY-MM when only month is known
#   end_of_support: When standard/active updates end (or same as EOL when upstream
#                   publishes only one date)
#   end_of_life: When all updates end (security support end)
#
# Sources and calculation methodology documented per-distro below.
# For rolling releases, all dates are None.

DISTRO_LIFECYCLE: Dict[str, Dict[str, LifecycleDates]] = {
    # -------------------------------------------------------------------------
    # Wolfi (Chainguard) - Rolling Release
    # Source: https://docs.chainguard.dev/open-source/wolfi/
    # Note: Wolfi is a rolling-release distribution; lifecycle is not expressed
    # as fixed version EOL dates. All fields are None.
    # -------------------------------------------------------------------------
    "wolfi": {
        "rolling": {
            "release_date": None,
            "end_of_support": None,
            "end_of_life": None,
        },
    },
    # -------------------------------------------------------------------------
    # Alpine Linux
    # Source: https://alpinelinux.org/releases/ (verified 2026-08-08)
    # Note: Alpine publishes a single per-branch end date. Alpine does not
    # separately publish EOS vs EOL for the branch, so the published end date
    # is used as both end_of_support and end_of_life.
    # Cadence: a release branch is cut from edge each May and November.
    # -------------------------------------------------------------------------
    "alpine": {
        "3.13": {
            "release_date": "2021-01-14",
            "end_of_support": "2022-11-01",
            "end_of_life": "2022-11-01",
        },
        "3.14": {
            "release_date": "2021-06-15",
            "end_of_support": "2023-05-01",
            "end_of_life": "2023-05-01",
        },
        "3.15": {
            "release_date": "2021-11-24",
            "end_of_support": "2023-11-01",
            "end_of_life": "2023-11-01",
        },
        "3.16": {
            "release_date": "2022-05-23",
            "end_of_support": "2024-05-23",
            "end_of_life": "2024-05-23",
        },
        "3.17": {
            "release_date": "2022-11-22",
            "end_of_support": "2024-11-22",
            "end_of_life": "2024-11-22",
        },
        "3.18": {
            "release_date": "2023-05-09",
            "end_of_support": "2025-05-09",
            "end_of_life": "2025-05-09",
        },
        "3.19": {
            "release_date": "2023-12-07",
            "end_of_support": "2025-11-01",
            "end_of_life": "2025-11-01",
        },
        "3.20": {
            "release_date": "2024-05-22",
            "end_of_support": "2026-04-01",
            "end_of_life": "2026-04-01",
        },
        "3.21": {
            "release_date": "2024-12-05",
            "end_of_support": "2026-11-01",
            "end_of_life": "2026-11-01",
        },
        "3.22": {
            "release_date": "2025-05-30",
            "end_of_support": "2027-05-01",
            "end_of_life": "2027-05-01",
        },
        "3.23": {
            "release_date": "2025-12-03",
            "end_of_support": "2027-11-01",
            "end_of_life": "2027-11-01",
        },
        "3.24": {
            "release_date": "2026-06-09",
            "end_of_support": "2028-06-01",
            "end_of_life": "2028-06-01",
        },
    },
    # -------------------------------------------------------------------------
    # Rocky Linux
    # Source: https://wiki.rockylinux.org/rocky/version/ (verified 2026-08-08)
    # Note: Rocky publishes 'Active Support Ends' (EOS) and 'End of Life' (EOL)
    # per major version: 10 years total, the first 5 being active support.
    # -------------------------------------------------------------------------
    "rocky": {
        "8": {
            "release_date": "2021-05-01",
            "end_of_support": "2024-05-31",  # Active support end
            "end_of_life": "2029-05-31",  # End of life
        },
        "9": {
            "release_date": "2022-07-14",
            "end_of_support": "2027-05-31",  # Active support end
            "end_of_life": "2032-05-31",  # End of life
        },
        "10": {
            "release_date": "2025-06-11",
            "end_of_support": "2030-05-31",  # Active support end
            "end_of_life": "2035-05-31",  # End of life
        },
    },
    # -------------------------------------------------------------------------
    # AlmaLinux
    # Source: https://wiki.almalinux.org/release-notes/ (verified 2026-08-08)
    # Note: AlmaLinux publishes 'active support until' (EOS) and 'security
    # support until' (EOL) dates. release_date is the major version's first
    # stable release.
    # -------------------------------------------------------------------------
    "almalinux": {
        "8": {
            "release_date": "2021-03-30",
            "end_of_support": "2024-05-31",  # Active support end
            "end_of_life": "2029-05-31",  # Security support end
        },
        "9": {
            "release_date": "2022-05-26",
            "end_of_support": "2027-05-31",  # Active support end
            "end_of_life": "2032-05-31",  # Security support end
        },
        "10": {
            "release_date": "2025-05-27",  # AlmaLinux 10.0
            "end_of_support": "2030-05-31",  # Active support end
            "end_of_life": "2035-05-31",  # Security support end
        },
    },
    # -------------------------------------------------------------------------
    # Amazon Linux
    # Sources:
    #   AL2:     https://aws.amazon.com/amazon-linux-2/faqs/
    #   AL2023:  https://docs.aws.amazon.com/linux/al2023/ug/release-cadence.html
    #            (verified 2026-08-08)
    # Note: AL2023 has two explicitly published phases -- standard support
    # (quarterly minor updates) ending 2027-06-30, then maintenance
    # (security-only) ending 2029-06-30. AL2 publishes a single end date.
    # -------------------------------------------------------------------------
    "amazonlinux": {
        "2": {
            "release_date": "2017-12-19",  # AWS announcement date
            "end_of_support": "2026-06-30",
            "end_of_life": "2026-06-30",
        },
        "2023": {
            "release_date": "2023-03",  # "released in March 2023", month precision
            "end_of_support": "2027-06-30",  # Standard support phase end
            "end_of_life": "2029-06-30",  # Maintenance phase end
        },
    },
    # -------------------------------------------------------------------------
    # CentOS Stream
    # Sources:
    #   Stream 8/9:  https://www.centos.org/cl-vs-cs/
    #   Stream 10:   https://blog.centos.org/2024/12/introducing-centos-stream-10/
    #                https://www.centos.org/centos10/  (verified 2026-08-08)
    # Note: CentOS publishes an 'expected end of life (EOL)' date. No separate
    # EOS date is published, so EOL is used for both.
    # Stream 10: CentOS states only "roughly a five year lifecycle ... maintained
    # until 2030", and that "the exact date will be contingent on the end of the
    # Full Support phase of RHEL 10". RHEL 10 reached GA in May 2025 and Red Hat's
    # Full Support phase runs 5 years, so this is recorded at month precision as
    # 2030-05 rather than inventing a day. Red Hat additionally notes that future
    # lifecycle dates are "close approximations, non definitive, and subject to
    # change".
    # -------------------------------------------------------------------------
    "centos": {
        "stream8": {
            "release_date": None,  # Not explicitly published
            "end_of_support": "2024-05-31",
            "end_of_life": "2024-05-31",
        },
        "stream9": {
            "release_date": None,  # Not explicitly published
            "end_of_support": "2027-05-31",
            "end_of_life": "2027-05-31",
        },
        "stream10": {
            "release_date": "2024-12-12",
            "end_of_support": "2030-05",  # Month precision, see note above
            "end_of_life": "2030-05",
        },
    },
    # -------------------------------------------------------------------------
    # Fedora
    # Sources:
    #   EOL table:  https://docs.fedoraproject.org/en-US/releases/eol/
    #   F43 GA:     https://fedoramagazine.org/announcing-fedora-linux-43/
    #   F44 GA:     https://fedoramagazine.org/announcing-fedora-linux-44/
    #               (verified 2026-08-08)
    # Note: Fedora publishes only one end date per release, so it is used for
    # both EOS and EOL. A release goes EOL roughly four weeks after the second
    # subsequent release ships, so the EOL of a still-supported release is not
    # a published date -- it is left as None until Fedora lists it in the EOL
    # table above. That is why F43 and F44 carry a release date but no EOL.
    # -------------------------------------------------------------------------
    "fedora": {
        "39": {
            "release_date": "2023-11-07",
            "end_of_support": "2024-11-26",
            "end_of_life": "2024-11-26",
        },
        "40": {
            "release_date": "2024-04-23",
            "end_of_support": "2025-05-13",
            "end_of_life": "2025-05-13",
        },
        "41": {
            "release_date": "2024-10-29",
            "end_of_support": "2025-12-15",
            "end_of_life": "2025-12-15",
        },
        "42": {
            "release_date": "2025-04-15",
            "end_of_support": "2026-05-27",
            "end_of_life": "2026-05-27",
        },
        "43": {
            "release_date": "2025-10-28",
            "end_of_support": None,  # Still supported; EOL not yet published
            "end_of_life": None,
        },
        "44": {
            "release_date": "2026-04-28",
            "end_of_support": None,  # Still supported; EOL not yet published
            "end_of_life": None,
        },
    },
    # -------------------------------------------------------------------------
    # openSUSE Leap
    # Sources:
    #   Support policy:  https://news.opensuse.org/2025/09/03/leap-16-doubles-support/
    #   Leap 16.0 GA:    https://news.opensuse.org/2025/10/01/next-chapter-opens-with-leap-release/
    #                    (verified 2026-08-08)
    # Note: there is no Leap 15.7. SUSE shipped SLES 15 SP7 without a matching
    # Leap release and the lifetime of Leap 15.6 was extended instead, to
    # 2026-04-30, closing out the Leap 15 line.
    # From Leap 16.0 onward each point release gets 24 months of maintenance and
    # security updates. openSUSE has not published a per-release EOL date for
    # 16.0, so its end dates are derived from the published 24-month commitment
    # applied to the published GA date, recorded at month precision.
    # -------------------------------------------------------------------------
    "opensuse-leap": {
        "15.5": {
            "release_date": "2023-06-07",
            "end_of_support": "2024-12-31",
            "end_of_life": "2024-12-31",
        },
        "15.6": {
            "release_date": "2024-06-12",
            "end_of_support": "2026-04-30",
            "end_of_life": "2026-04-30",
        },
        "16.0": {
            "release_date": "2025-10-01",
            "end_of_support": "2027-10",  # GA + 24 months, month precision
            "end_of_life": "2027-10",
        },
    },
    # -------------------------------------------------------------------------
    # Oracle Linux
    # Source: https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf
    #         ("Lifetime Support Policy: Coverage for Oracle Open Source Service
    #         Offerings", Oracle Linux Releases table, verified 2026-08-08)
    # Note: Oracle publishes its own lifecycle -- Premier Support for 10 years
    # from GA, then Extended Support, then indefinite Sustaining Support (which
    # carries no new security fixes and so is not an EOL extension). Oracle
    # Linux does NOT inherit Red Hat's dates; the values here previously mirrored
    # RHEL/Rocky and understated Oracle's Extended Support end by ~3 years.
    # Oracle publishes month precision only, so that is what is recorded.
    #   Release  GA        Premier ends  Extended ends
    #   OL8      Jul 2019  Jul 2029      Jul 2032
    #   OL9      Jun 2022  Jun 2032      Jun 2035
    #   OL10     Jun 2025  Jun 2035      Jun 2038
    # -------------------------------------------------------------------------
    "oracle": {
        "8": {
            "release_date": "2019-07",
            "end_of_support": "2029-07",  # Premier Support ends
            "end_of_life": "2032-07",  # Extended Support ends
        },
        "9": {
            "release_date": "2022-06",
            "end_of_support": "2032-06",  # Premier Support ends
            "end_of_life": "2035-06",  # Extended Support ends
        },
        "10": {
            "release_date": "2025-06",
            "end_of_support": "2035-06",  # Premier Support ends
            "end_of_life": "2038-06",  # Extended Support ends
        },
    },
    # -------------------------------------------------------------------------
    # Ubuntu
    # Sources: https://ubuntu.com/about/release-cycle
    #          https://ubuntu.com/pro  (verified 2026-08-08)
    # Note: Canonical now documents THREE tiers for an LTS release:
    #   1. Standard security maintenance  -- 5 years, free
    #   2. Expanded Security Maintenance  -- to 10 years, requires Ubuntu Pro
    #   3. Legacy add-on                  -- to 15 years, further paid add-on
    # The two CLE slots here map to tiers 1 and 2: end_of_support is the end of
    # free standard security maintenance, and end_of_life is the end of ESM
    # (release + 10 years). The 15-year Legacy figure that ubuntu.com/about/
    # release-cycle now headlines is deliberately NOT used, because it is a
    # second paid add-on beyond ESM rather than the baseline commitment.
    # Only LTS releases are tracked; interim releases (24.10, 25.04, 25.10, ...)
    # get 9 months of support and are not represented here.
    # Canonical publishes month precision, so that is what is recorded.
    # -------------------------------------------------------------------------
    "ubuntu": {
        "20.04": {
            "release_date": "2020-04",  # Month precision
            "end_of_support": "2025-05",  # Standard security maintenance end
            "end_of_life": "2030-04",  # Expanded security maintenance end
        },
        "22.04": {
            "release_date": "2022-04",
            "end_of_support": "2027-05",  # Standard security maintenance end
            "end_of_life": "2032-04",  # Expanded security maintenance end
        },
        "24.04": {
            "release_date": "2024-04",
            "end_of_support": "2029-05",
            "end_of_life": "2034-04",
        },
        "26.04": {
            "release_date": "2026-04",
            "end_of_support": "2031-05",
            "end_of_life": "2036-04",
        },
    },
    # -------------------------------------------------------------------------
    # Debian
    # Source: https://wiki.debian.org/LTS (LTS schedule table, verified 2026-08-08)
    # Note: Debian publishes 'Regular security support' (EOS) and 'Long Term
    # Support' (EOL/LTS) dates.
    # -------------------------------------------------------------------------
    "debian": {
        "10": {
            "release_date": "2019-07-06",
            "end_of_support": "2022-09-10",  # Regular security support end
            "end_of_life": "2024-06-30",  # LTS end
        },
        "11": {
            "release_date": "2021-08-14",
            "end_of_support": "2024-08-15",  # Regular security support end
            "end_of_life": "2026-08-31",  # LTS end
        },
        "12": {
            "release_date": "2023-06-10",
            "end_of_support": "2026-06-11",  # Regular security support end
            "end_of_life": "2028-06-30",  # LTS end
        },
        "13": {
            "release_date": "2025-08-09",
            "end_of_support": "2028-08-09",  # Regular security support end
            "end_of_life": "2030-06-30",  # LTS end
        },
    },
}


# =============================================================================
# PACKAGE_LIFECYCLE - Language Runtime and Framework Lifecycle Data
# =============================================================================
#
# Schema per package:
#   name_patterns: List of package name patterns to match (case-insensitive)
#                  Supports glob patterns: "python3.*" matches "python3.12"
#   purl_types: Optional list of PURL types to match (e.g., ["pypi", "deb"])
#               None means match all PURL types
#   cycles: Dict mapping version cycle to lifecycle dates
#   version_extract: How to extract cycle from version ("major" or "major.minor")
#                    Default is "major.minor"
#   references: List of documentation URLs
#
# Definitions:
#   release_date: First public stable release date for the cycle when available;
#                 otherwise null or quarter string (e.g., "2026-Q1")
#   end_of_support: End of active/mainstream/bugfix support, when the project
#                   stops providing regular bugfix releases (may still receive
#                   security fixes)
#   end_of_life: End of security support / extended support; after this, upstream
#                no longer provides security fixes
#
# Data as of: 2026-08-08. The sourcing rule in the module docstring applies here
# too: vendor-published dates only, with the source URL recorded per entry.

PACKAGE_LIFECYCLE: Dict[str, PackageLifecycleEntry] = {
    # -------------------------------------------------------------------------
    # Node.js
    # Source: https://github.com/nodejs/Release/blob/main/schedule.json
    #         (the Release Working Group's machine-readable schedule, which is
    #         what nodejs.org/en/about/previous-releases renders)
    #         Verified 2026-08-08.
    # Note: Node's schedule has four dates per line -- start, lts, maintenance,
    # end. Mapped here as:
    #   release_date    <- start        (initial release of the major line)
    #   end_of_support  <- maintenance  (drops to security/critical fixes only)
    #   end_of_life     <- end          (no further releases of any kind)
    # Odd-numbered lines never become LTS and get a short maintenance window.
    # Only released lines are listed; scheduled-but-unreleased lines are omitted.
    #
    # Common PURLs across ecosystems:
    #   npm:      pkg:npm/node@22.11.0 (rare -- npm packages pin the runtime via
    #             engines, they are not the runtime)
    #   Alpine:   pkg:apk/alpine/nodejs@22.11.0
    #   Debian:   pkg:deb/debian/nodejs@22.11.0, pkg:deb/debian/libnode115@22.11.0
    #   Ubuntu:   pkg:deb/ubuntu/nodejs@22.11.0
    #   Fedora:   pkg:rpm/fedora/nodejs@22.11.0, pkg:rpm/fedora/nodejs-libs@22.11.0
    #   Docker:   node:22, node:22-alpine, node:22-slim
    #
    # IMPORTANT: name_patterns must not use a bare "node-*" or "nodejs-*" glob.
    # Distros package thousands of npm libraries as node-<libname> (node-tar,
    # node-gyp, ...) whose versions are library versions, not runtime versions;
    # matching those would attach wildly wrong lifecycle dates. Only the specific
    # runtime subpackages are listed.
    # -------------------------------------------------------------------------
    "nodejs": {
        "name_patterns": [
            "node",
            "nodejs",
            "nodejs-libs",  # Fedora/RHEL runtime split
            "nodejs-full-i18n",
            "nodejs-devel",
            "nodejs-doc",
            "nodejs-docs",
            "libnode*",  # Debian/Ubuntu shared library (libnode109, libnode115, ...)
        ],
        "purl_types": None,  # Match all types (deb, rpm, apk, npm, docker, ...)
        "version_extract": "major",
        "references": [
            "https://github.com/nodejs/Release/blob/main/schedule.json",
            "https://nodejs.org/en/about/previous-releases",
        ],
        "cycles": {
            "14": {
                "release_date": "2020-04-21",
                "end_of_support": "2021-10-19",
                "end_of_life": "2023-04-30",
            },
            "16": {
                "release_date": "2021-04-20",
                "end_of_support": "2022-10-18",
                "end_of_life": "2023-09-11",
            },
            "18": {
                "release_date": "2022-04-19",
                "end_of_support": "2023-10-18",
                "end_of_life": "2025-04-30",
            },
            "19": {
                "release_date": "2022-10-18",
                "end_of_support": "2023-04-01",
                "end_of_life": "2023-06-01",
            },
            "20": {
                "release_date": "2023-04-18",
                "end_of_support": "2024-10-22",
                "end_of_life": "2026-04-30",
            },
            "21": {
                "release_date": "2023-10-17",
                "end_of_support": "2024-04-01",
                "end_of_life": "2024-06-01",
            },
            "22": {
                "release_date": "2024-04-24",
                "end_of_support": "2025-10-21",
                "end_of_life": "2027-04-30",
            },
            "23": {
                "release_date": "2024-10-16",
                "end_of_support": "2025-04-01",
                "end_of_life": "2025-06-01",
            },
            "24": {
                "release_date": "2025-05-06",
                "end_of_support": "2026-10-20",
                "end_of_life": "2028-04-30",
            },
            "25": {
                "release_date": "2025-10-15",
                "end_of_support": "2026-04-01",
                "end_of_life": "2026-06-01",
            },
            "26": {
                "release_date": "2026-05-05",
                "end_of_support": "2027-10-20",
                "end_of_life": "2029-04-30",
            },
        },
    },
    # -------------------------------------------------------------------------
    # Python
    # Source: https://devguide.python.org/versions/
    #         https://peps.python.org/pep-0373/ (Python 2.7)
    # Note: Python provides ~18-24 months of bugfix support after release,
    # then security-only fixes until EOL. Starting with 3.13, bugfix support
    # is 24 months.
    #
    # Common PURLs across ecosystems:
    #   PyPI:     pkg:pypi/python@3.12.1, pkg:pypi/cpython@3.12.1
    #   Alpine:   pkg:apk/alpine/python3@3.12.1, pkg:apk/alpine/python3.12@3.12.1
    #   Debian:   pkg:deb/debian/python3@3.12.1, pkg:deb/debian/python3.12@3.12.1
    #             pkg:deb/debian/python3.12-minimal@3.12.1
    #             pkg:deb/debian/libpython3.12-stdlib@3.12.1
    #   Ubuntu:   pkg:deb/ubuntu/python3@3.12.1, pkg:deb/ubuntu/python3.12@3.12.1
    #   Fedora:   pkg:rpm/fedora/python3@3.12.1
    #   Docker:   python:3.12, python:3.12-slim, python:3.12-alpine
    # -------------------------------------------------------------------------
    "python": {
        "name_patterns": [
            "python",
            "python2",
            "python2.*",
            "python3",
            "python3.*",
            "cpython",
            "libpython*",  # Debian stdlib packages
        ],
        "purl_types": None,  # Match all types (pypi, deb, rpm, apk, etc.)
        "version_extract": "major.minor",
        "references": [
            "https://devguide.python.org/versions/",
            "https://peps.python.org/pep-0373/",
        ],
        "cycles": {
            "2.7": {
                "release_date": None,
                "end_of_support": "2020-01-01",
                "end_of_life": "2020-04-20",
            },
            # 3.8 and 3.9 are past EOL; the devguide table lists their release
            # and EOL dates but no separate end-of-bugfix date, so EOS is None.
            "3.8": {
                "release_date": "2019-10-14",
                "end_of_support": None,
                "end_of_life": "2024-10-07",
            },
            "3.9": {
                "release_date": "2020-10-05",
                "end_of_support": None,
                "end_of_life": "2025-10-31",
            },
            "3.10": {
                "release_date": "2021-10-04",
                "end_of_support": "2023-04-04",
                "end_of_life": "2026-10-31",
            },
            "3.11": {
                "release_date": "2022-10-24",
                "end_of_support": "2024-04-24",
                "end_of_life": "2027-10-31",
            },
            "3.12": {
                "release_date": "2023-10-02",
                "end_of_support": "2025-04-02",
                "end_of_life": "2028-10-31",
            },
            "3.13": {
                "release_date": "2024-10-07",
                "end_of_support": "2026-10-07",
                "end_of_life": "2029-10-31",
            },
            "3.14": {
                "release_date": "2025-10-07",
                "end_of_support": "2027-10-07",
                "end_of_life": "2030-10-31",
            },
        },
    },
    # -------------------------------------------------------------------------
    # Django
    # Source: https://www.djangoproject.com/download/ ("Supported Versions" and
    #         the release roadmap, verified 2026-08-08)
    # Note: Django provides mainstream (bugfix) support until EOS, then
    # security-only until EOL. LTS releases (4.2, 5.2, ...) get a 3-year
    # extended support window.
    # The download page publishes support end dates but not initial release
    # dates, so release_date stays None rather than being sourced elsewhere.
    # Future dates are published at month precision and recorded that way.
    # 5.0 and 5.1 were previously missing entirely, so anything on those lines
    # silently received no lifecycle data at all.
    # -------------------------------------------------------------------------
    "django": {
        "name_patterns": ["django", "Django"],
        "purl_types": ["pypi"],
        "version_extract": "major.minor",
        "references": [
            "https://www.djangoproject.com/download/",
        ],
        "cycles": {
            "4.2": {  # LTS
                "release_date": None,
                "end_of_support": "2023-12-04",
                "end_of_life": "2026-04-07",
            },
            "5.0": {
                "release_date": None,
                "end_of_support": "2024-08-07",
                "end_of_life": "2025-04-02",
            },
            "5.1": {
                "release_date": None,
                "end_of_support": "2025-04-02",
                "end_of_life": "2025-12-03",
            },
            "5.2": {  # LTS
                "release_date": None,
                "end_of_support": "2025-12-03",
                "end_of_life": "2028-04",  # "April 2028", month precision
            },
            "6.0": {
                "release_date": None,
                "end_of_support": "2026-08-04",
                "end_of_life": "2027-04",  # "April 2027", month precision
            },
            "6.1": {
                "release_date": None,
                "end_of_support": "2027-04",  # "April 2027", month precision
                "end_of_life": "2027-12",  # "December 2027", month precision
            },
        },
    },
    # -------------------------------------------------------------------------
    # Ruby on Rails
    # Source: https://rubyonrails.org/2025/10/29/new-rails-releases-and-end-of-support-announcement
    # Note: Rails provides bugfix support for ~12 months, then security-only
    # for another ~6-12 months typically.
    #
    # Common PURLs across ecosystems:
    #   RubyGems:  pkg:gem/rails@8.0.1, pkg:gem/railties@8.0.1
    #              pkg:gem/actionpack@8.0.1, pkg:gem/activerecord@8.0.1
    #              pkg:gem/activesupport@8.0.1, pkg:gem/actionmailer@8.0.1
    #              pkg:gem/actioncable@8.0.1, pkg:gem/activestorage@8.0.1
    #              pkg:gem/actionview@8.0.1, pkg:gem/activejob@8.0.1
    #   Debian:    pkg:deb/debian/rails@8.0.1, pkg:deb/debian/ruby-rails@8.0.1
    # -------------------------------------------------------------------------
    "rails": {
        "name_patterns": [
            "rails",
            "railties",
            "actionpack",
            "activerecord",
            "activesupport",
            "actionmailer",
            "actioncable",
            "activestorage",
            "actionview",
            "activejob",
            "actionmailbox",
            "actiontext",
            "activemodel",
            "ruby-rails",
        ],
        "purl_types": ["gem"],
        "version_extract": "major.minor",
        "references": [
            "https://rubyonrails.org/maintenance",
            "https://rubyonrails.org/2025/10/29/new-rails-releases-and-end-of-support-announcement",
        ],
        "cycles": {
            "7.0": {
                "release_date": "2021-12-15",
                "end_of_support": "2025-10-29",
                "end_of_life": "2025-10-29",
            },
            "7.1": {
                "release_date": "2023-10-05",
                "end_of_support": "2025-10-29",
                "end_of_life": "2025-10-29",
            },
            "7.2": {
                # Per https://rubyonrails.org/maintenance : bug fixes for one
                # year from release, security fixes for two.
                "release_date": "2024-08-09",
                "end_of_support": "2025-08-09",
                "end_of_life": "2026-08-09",
            },
            "8.0": {
                "release_date": "2024-11-07",
                "end_of_support": "2026-05-07",
                "end_of_life": "2026-11-07",
            },
            "8.1": {
                "release_date": "2025-10-22",
                "end_of_support": "2026-10-10",
                "end_of_life": "2027-10-10",
            },
        },
    },
    # -------------------------------------------------------------------------
    # Laravel
    # Source: https://laravel.com/docs/13.x/releases (Support Policy table,
    #         verified 2026-08-08)
    # Note: Laravel's stated policy is bug fixes for 18 months and security
    # fixes for 2 years from release. end_of_support is the "Bug Fixes Until"
    # column, end_of_life is "Security Fixes Until".
    # The previous values here were shifted by roughly a release cycle -- e.g.
    # Laravel 10 was recorded as EOL 2026-02-04 when Laravel's own table says
    # security fixes ended 2025-02-04, and Laravel 13's EOL was a placeholder
    # quarter string ("2027-Q1") almost a year before the published 2028-03-17.
    # -------------------------------------------------------------------------
    "laravel": {
        "name_patterns": ["laravel/framework", "laravel"],
        "purl_types": ["composer"],
        "version_extract": "major",
        "references": [
            "https://laravel.com/docs/13.x/releases",
        ],
        "cycles": {
            "10": {
                "release_date": "2023-02-14",
                "end_of_support": "2024-08-06",
                "end_of_life": "2025-02-04",
            },
            "11": {
                "release_date": "2024-03-12",
                "end_of_support": "2025-09-03",
                "end_of_life": "2026-03-12",
            },
            "12": {
                "release_date": "2025-02-24",
                "end_of_support": "2026-08-13",
                "end_of_life": "2027-02-24",
            },
            "13": {
                "release_date": "2026-03-17",
                # Laravel publishes "Q3 2027" for this one; the security date is
                # a firm published date.
                "end_of_support": "2027-Q3",
                "end_of_life": "2028-03-17",
            },
        },
    },
    # -------------------------------------------------------------------------
    # PHP
    # Source: https://www.php.net/supported-versions.php
    #         https://www.php.net/eol.php
    # Note: PHP provides ~2 years of active support, then ~1 year of security-only
    # support. Older branches only show EOL date (end_of_support is None).
    #
    # Common PURLs across ecosystems:
    #   Composer: pkg:composer/php@8.4.1 (rarely used directly)
    #   Alpine:   pkg:apk/alpine/php@8.4.1, pkg:apk/alpine/php84@8.4.1
    #             pkg:apk/alpine/php84-fpm@8.4.1, pkg:apk/alpine/php84-cli@8.4.1
    #             pkg:apk/alpine/php83@8.3.6, pkg:apk/alpine/php83-common@8.3.6
    #   Debian:   pkg:deb/debian/php@8.4.1, pkg:deb/debian/php8.3@8.3.6
    #             pkg:deb/debian/php8.3-fpm@8.3.6, pkg:deb/debian/php8.3-cli@8.3.6
    #             pkg:deb/debian/php-fpm@8.3.6, pkg:deb/debian/php-cli@8.3.6
    #   Ubuntu:   pkg:deb/ubuntu/php@8.3.6, pkg:deb/ubuntu/php8.3@8.3.6
    #   Fedora:   pkg:rpm/fedora/php@8.3.6, pkg:rpm/fedora/php-fpm@8.3.6
    #   Docker:   php:8.4, php:8.4-fpm, php:8.4-alpine, php:8.4-fpm-alpine
    # -------------------------------------------------------------------------
    "php": {
        "name_patterns": [
            "php",
            "php-cli",
            "php-fpm",
            "php-cgi",
            "php-common",
            "php7",
            "php7.*",
            "php8",
            "php8.*",
            "php74",
            "php74-*",
            "php80",
            "php80-*",
            "php81",
            "php81-*",
            "php82",
            "php82-*",
            "php83",
            "php83-*",
            "php84",
            "php84-*",
            "php85",
            "php85-*",
            "libphp*",  # Shared libraries
        ],
        "purl_types": None,  # Match all types (composer, deb, rpm, apk, etc.)
        "version_extract": "major.minor",
        "references": [
            "https://www.php.net/supported-versions.php",
            "https://www.php.net/eol.php",
        ],
        "cycles": {
            "7.4": {
                "release_date": "2019-11-28",
                "end_of_support": None,
                "end_of_life": "2022-11-28",
            },
            "8.0": {
                "release_date": "2020-11-26",
                "end_of_support": None,
                "end_of_life": "2023-11-26",
            },
            "8.1": {
                "release_date": "2021-11-25",
                "end_of_support": None,
                "end_of_life": "2025-12-31",
            },
            "8.2": {
                "release_date": "2022-12-08",
                "end_of_support": "2024-12-31",
                "end_of_life": "2026-12-31",
            },
            "8.3": {
                "release_date": "2023-11-23",
                "end_of_support": "2025-12-31",
                "end_of_life": "2027-12-31",
            },
            "8.4": {
                "release_date": "2024-11-21",
                "end_of_support": "2026-12-31",
                "end_of_life": "2028-12-31",
            },
            "8.5": {
                "release_date": "2025-11-20",
                "end_of_support": "2027-12-31",
                "end_of_life": "2029-12-31",
            },
        },
    },
    # -------------------------------------------------------------------------
    # Go (Golang)
    # Source: https://go.dev/doc/devel/release
    # Note: Go's release policy (https://go.dev/doc/devel/release) is that "each
    # major Go release is supported until there are two newer major releases".
    # Go does not publish EOL dates directly, so a cycle's EOS/EOL is derived as
    # the published release date of the release two ahead of it; a cycle that is
    # still supported carries None. EOS and EOL are the same date.
    #
    # Common PURLs across ecosystems:
    #   Go modules: pkg:golang/golang.org/x/text@1.23.0 (libraries, not runtime)
    #   Alpine:     pkg:apk/alpine/go@1.23.4
    #   Debian:     pkg:deb/debian/golang@1.23.4, pkg:deb/debian/golang-go@1.23.4
    #               pkg:deb/debian/golang-1.23@1.23.4, pkg:deb/debian/golang-1.23-go@1.23.4
    #               pkg:deb/debian/golang-1.23-src@1.23.4
    #   Ubuntu:     pkg:deb/ubuntu/golang@1.23.4, pkg:deb/ubuntu/golang-1.23-go@1.23.4
    #   Fedora:     pkg:rpm/fedora/golang@1.23.4
    #   Docker:     golang:1.23, golang:1.23-alpine, golang:1.23-bookworm
    # -------------------------------------------------------------------------
    "golang": {
        "name_patterns": [
            "go",
            "golang",
            "golang-go",
            "golang-src",
            "golang-doc",
            "golang-1.*",  # Debian versioned packages
            "golang-1.*-go",
            "golang-1.*-src",
            "golang-1.*-doc",
        ],
        "purl_types": None,  # Match all types (golang, deb, rpm, apk, etc.)
        "version_extract": "major.minor",
        "references": [
            "https://go.dev/doc/devel/release",
        ],
        "cycles": {
            "1.22": {
                "release_date": "2024-02-06",
                "end_of_support": "2025-02-11",
                "end_of_life": "2025-02-11",
            },
            "1.23": {
                "release_date": "2024-08-13",
                "end_of_support": "2025-08-12",
                "end_of_life": "2025-08-12",
            },
            "1.24": {
                # Superseded by the Go 1.26 release on 2026-02-10.
                "release_date": "2025-02-11",
                "end_of_support": "2026-02-10",
                "end_of_life": "2026-02-10",
            },
            "1.25": {
                # Still supported: Go 1.27 has not shipped.
                "release_date": "2025-08-12",
                "end_of_support": None,
                "end_of_life": None,
            },
            "1.26": {
                "release_date": "2026-02-10",
                "end_of_support": None,
                "end_of_life": None,
            },
        },
    },
    # -------------------------------------------------------------------------
    # Rust
    # Source: https://rust-lang.org/policies/security/
    #         https://blog.rust-lang.org/releases/
    # Note: Rust only supports the most recent stable release. When a new stable
    # is released, the previous version is immediately unsupported, so a cycle's
    # EOS/EOL is the published release date of the following stable, and the
    # current stable carries None. EOS and EOL are the same date.
    # Rust ships every 6 weeks, so this table goes stale faster than any other
    # entry here -- the staleness checker exists largely because of it.
    # Release dates are from the official release announcements index at
    # https://blog.rust-lang.org/releases/ (verified 2026-08-08).
    #
    # Common PURLs across ecosystems:
    #   Cargo:    pkg:cargo/serde@1.91.0 (crates, not runtime itself)
    #   Alpine:   pkg:apk/alpine/rust@1.91.0, pkg:apk/alpine/cargo@1.91.0
    #   Debian:   pkg:deb/debian/rustc@1.91.0, pkg:deb/debian/cargo@1.91.0
    #             pkg:deb/debian/rust-all@1.91.0, pkg:deb/debian/rust-src@1.91.0
    #             pkg:deb/debian/libstd-rust-1.91@1.91.0, pkg:deb/debian/libstd-rust-dev@1.91.0
    #   Ubuntu:   pkg:deb/ubuntu/rustc@1.91.0, pkg:deb/ubuntu/cargo@1.91.0
    #             pkg:deb/ubuntu/rustc-1.77@1.77.0 (versioned)
    #   Fedora:   pkg:rpm/fedora/rust@1.91.0, pkg:rpm/fedora/cargo@1.91.0
    #   Docker:   rust:1.91, rust:1.91-slim, rust:1.91-alpine
    # -------------------------------------------------------------------------
    "rust": {
        "name_patterns": [
            "rust",
            "rustc",
            "rustc-*",  # Ubuntu versioned packages
            "cargo",
            "cargo-*",  # Ubuntu versioned packages
            "rust-all",
            "rust-src",
            "rust-doc",
            "rust-gdb",
            "rust-lldb",
            "libstd-rust*",  # Debian stdlib packages
        ],
        "purl_types": None,  # Match all types (cargo, deb, rpm, apk, etc.)
        "version_extract": "major.minor",
        "references": [
            "https://rust-lang.org/policies/security/",
            "https://blog.rust-lang.org/releases/",
        ],
        "cycles": {
            "1.89": {
                "release_date": "2025-08-07",
                "end_of_support": "2025-09-18",
                "end_of_life": "2025-09-18",
            },
            "1.90": {
                "release_date": "2025-09-18",
                "end_of_support": "2025-10-30",
                "end_of_life": "2025-10-30",
            },
            "1.91": {
                "release_date": "2025-10-30",
                "end_of_support": "2025-12-11",
                "end_of_life": "2025-12-11",
            },
            "1.92": {
                "release_date": "2025-12-11",
                "end_of_support": "2026-01-22",
                "end_of_life": "2026-01-22",
            },
            "1.93": {
                "release_date": "2026-01-22",
                "end_of_support": "2026-03-05",
                "end_of_life": "2026-03-05",
            },
            "1.94": {
                "release_date": "2026-03-05",
                "end_of_support": "2026-04-16",
                "end_of_life": "2026-04-16",
            },
            "1.95": {
                "release_date": "2026-04-16",
                "end_of_support": "2026-05-28",
                "end_of_life": "2026-05-28",
            },
            "1.96": {
                "release_date": "2026-05-28",
                "end_of_support": "2026-07-09",
                "end_of_life": "2026-07-09",
            },
            "1.97": {
                # Current stable as of 2026-08-08.
                "release_date": "2026-07-09",
                "end_of_support": None,
                "end_of_life": None,
            },
        },
    },
    # -------------------------------------------------------------------------
    # React
    # Source: https://react.dev/blog/
    # Note: React does not publish fixed end-of-support/end-of-life dates for
    # major versions. Only release dates are tracked.
    #
    # Common PURLs across ecosystems:
    #   npm:      pkg:npm/react@19.0.0, pkg:npm/react-dom@19.0.0
    #             pkg:npm/react-native@0.76.0 (different versioning, not tracked)
    # -------------------------------------------------------------------------
    "react": {
        "name_patterns": [
            "react",
            "react-dom",  # Usually same version as react
        ],
        "purl_types": ["npm"],
        "version_extract": "major",
        "references": [
            "https://react.dev/blog/2024/12/05/react-19",
            "https://react.dev/blog/2022/03/29/react-v18",
            "https://legacy.reactjs.org/blog/2020/10/20/react-v17.html",
        ],
        "cycles": {
            "17": {
                "release_date": "2020-10-20",
                "end_of_support": None,
                "end_of_life": None,
            },
            "18": {
                "release_date": "2022-03-29",
                "end_of_support": None,
                "end_of_life": None,
            },
            "19": {
                "release_date": "2024-12-05",
                "end_of_support": None,
                "end_of_life": None,
            },
        },
    },
    # -------------------------------------------------------------------------
    # Vue.js
    # Source: https://v2.vuejs.org/eol/
    #         https://vuejs.org/guide/introduction.html
    # Note: Vue 2 reached EOL on Dec 31, 2023. Vue 3 is current and does not
    # have a published EOL date.
    #
    # Common PURLs across ecosystems:
    #   npm:      pkg:npm/vue@3.4.0, pkg:npm/vue@2.7.14
    #             pkg:npm/@vue/runtime-core@3.4.0, pkg:npm/@vue/compiler-sfc@3.4.0
    # -------------------------------------------------------------------------
    "vue": {
        "name_patterns": [
            "vue",
            "@vue/runtime-core",  # Vue 3 core packages
            "@vue/compiler-sfc",
            "@vue/reactivity",
            "@vue/shared",
        ],
        "purl_types": ["npm"],
        "version_extract": "major",
        "references": [
            "https://v2.vuejs.org/eol/",
            "https://vuejs.org/guide/introduction.html",
        ],
        "cycles": {
            "2": {
                "release_date": None,
                "end_of_support": "2023-12-31",
                "end_of_life": "2023-12-31",
            },
            "3": {
                "release_date": None,
                "end_of_support": None,
                "end_of_life": None,
            },
        },
    },
    # -------------------------------------------------------------------------
    # Dart
    # Sources:
    #   Support policy:  https://dart.dev/tools/sdk#support-policy
    #   Release dates:   https://storage.googleapis.com/dart-archive/channels/stable/release/
    #                    (the official dart-archive bucket; each release carries a
    #                    VERSION file with its publication date)
    #                    Verified 2026-08-08.
    # Note: Dart publishes NO end-of-life dates. Its policy is explicitly
    # rolling -- "the Dart team supports only the latest stable release", and
    # "when a new major or minor version is released, older versions are no
    # longer supported". EOS/EOL are therefore derived the same way as Rust and
    # Go: a cycle ends when the next minor ships, and the current stable carries
    # None. Dart ships a stable roughly every 3 months.
    #
    # Common PURLs:
    #   Docker:   dart:3.12, dart:stable
    #   Alpine:   pkg:apk/alpine/dart@3.12.0
    # Note pkg:pub/... identifies Dart *packages*, not the SDK, so a pub-hosted
    # package coincidentally named "dart" would not carry SDK versions.
    # -------------------------------------------------------------------------
    "dart": {
        "name_patterns": [
            "dart",
            "dart-sdk",
            "dartsdk",
        ],
        "purl_types": None,
        "version_extract": "major.minor",
        "references": [
            "https://dart.dev/tools/sdk#support-policy",
            "https://dart.dev/get-dart/archive",
        ],
        "cycles": {
            "2.17": {
                "release_date": "2022-05-09",
                "end_of_support": "2022-08-26",
                "end_of_life": "2022-08-26",
            },
            "2.18": {
                "release_date": "2022-08-26",
                "end_of_support": "2023-01-23",
                "end_of_life": "2023-01-23",
            },
            "2.19": {
                "release_date": "2023-01-23",
                "end_of_support": "2023-05-04",
                "end_of_life": "2023-05-04",
            },
            "3.0": {
                "release_date": "2023-05-04",
                "end_of_support": "2023-08-15",
                "end_of_life": "2023-08-15",
            },
            "3.1": {
                "release_date": "2023-08-15",
                "end_of_support": "2023-11-14",
                "end_of_life": "2023-11-14",
            },
            "3.2": {
                "release_date": "2023-11-14",
                "end_of_support": "2024-02-13",
                "end_of_life": "2024-02-13",
            },
            "3.3": {
                "release_date": "2024-02-13",
                "end_of_support": "2024-05-06",
                "end_of_life": "2024-05-06",
            },
            "3.4": {
                "release_date": "2024-05-06",
                "end_of_support": "2024-07-30",
                "end_of_life": "2024-07-30",
            },
            "3.5": {
                "release_date": "2024-07-30",
                "end_of_support": "2024-12-05",
                "end_of_life": "2024-12-05",
            },
            "3.6": {
                "release_date": "2024-12-05",
                "end_of_support": "2025-02-05",
                "end_of_life": "2025-02-05",
            },
            "3.7": {
                "release_date": "2025-02-05",
                "end_of_support": "2025-05-14",
                "end_of_life": "2025-05-14",
            },
            "3.8": {
                "release_date": "2025-05-14",
                "end_of_support": "2025-08-11",
                "end_of_life": "2025-08-11",
            },
            "3.9": {
                "release_date": "2025-08-11",
                "end_of_support": "2025-11-06",
                "end_of_life": "2025-11-06",
            },
            "3.10": {
                "release_date": "2025-11-06",
                "end_of_support": "2026-02-09",
                "end_of_life": "2026-02-09",
            },
            "3.11": {
                "release_date": "2026-02-09",
                "end_of_support": "2026-05-08",
                "end_of_life": "2026-05-08",
            },
            "3.12": {
                # Current stable as of 2026-08-08.
                "release_date": "2026-05-08",
                "end_of_support": None,
                "end_of_life": None,
            },
        },
    },
    # -------------------------------------------------------------------------
    # Flutter
    # Source: https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json
    #         (Flutter's official release manifest, verified 2026-08-08)
    # Note: Flutter publishes NO support policy and NO end-of-life dates. Its
    # compatibility policy covers breaking API changes and deprecations only,
    # and says nothing about how long a stable release is maintained. Unlike
    # Dart, Flutter has not published a "latest stable only" statement either,
    # so there is no policy to derive an EOL from and EOS/EOL are left None
    # rather than guessed. Only the release date -- which maps to the CLE
    # generalAvailability milestone -- is recorded.
    # Flutter promotes roughly every third beta to stable, about quarterly.
    # -------------------------------------------------------------------------
    "flutter": {
        "name_patterns": [
            "flutter",
            "flutter-sdk",
        ],
        "purl_types": None,
        "version_extract": "major.minor",
        "references": [
            "https://docs.flutter.dev/release/archive",
        ],
        "cycles": {
            "3.0": {"release_date": "2022-05-11", "end_of_support": None, "end_of_life": None},
            "3.3": {"release_date": "2022-08-30", "end_of_support": None, "end_of_life": None},
            "3.7": {"release_date": "2023-01-24", "end_of_support": None, "end_of_life": None},
            "3.10": {"release_date": "2023-05-10", "end_of_support": None, "end_of_life": None},
            "3.13": {"release_date": "2023-08-16", "end_of_support": None, "end_of_life": None},
            "3.16": {"release_date": "2023-11-15", "end_of_support": None, "end_of_life": None},
            "3.19": {"release_date": "2024-02-15", "end_of_support": None, "end_of_life": None},
            "3.22": {"release_date": "2024-05-13", "end_of_support": None, "end_of_life": None},
            "3.24": {"release_date": "2024-08-06", "end_of_support": None, "end_of_life": None},
            "3.27": {"release_date": "2024-12-11", "end_of_support": None, "end_of_life": None},
            "3.29": {"release_date": "2025-02-12", "end_of_support": None, "end_of_life": None},
            "3.32": {"release_date": "2025-05-20", "end_of_support": None, "end_of_life": None},
            "3.35": {"release_date": "2025-08-14", "end_of_support": None, "end_of_life": None},
            "3.38": {"release_date": "2025-11-12", "end_of_support": None, "end_of_life": None},
            "3.41": {"release_date": "2026-02-11", "end_of_support": None, "end_of_life": None},
            "3.44": {"release_date": "2026-05-18", "end_of_support": None, "end_of_life": None},
        },
    },
    # -------------------------------------------------------------------------
    # Scala
    # Sources:
    #   Release dates:  https://github.com/scala/scala3/releases (Scala 3)
    #                   https://www.scala-lang.org/download/all.html (Scala 2)
    #   LTS policy:     https://www.scala-lang.org/blog/2022/08/17/long-term-compatibility-plans.html
    #                   Verified 2026-08-08.
    # Note: Scala publishes NO firm end-of-life dates. The 3.3.x LTS line is
    # documented as maintained "for at least three years" and then "at least
    # another year after the release of the next LTS", which are floors and
    # estimates rather than dates -- so EOS/EOL are left None. Scala is also not
    # a rolling line like Dart/Rust: 3.3.x LTS is still maintained alongside the
    # current 3.8.x, so a newer release does NOT end the previous one and the
    # derivation used for Dart/Rust/Go would be wrong here.
    #
    # Common PURLs:
    #   Maven:  pkg:maven/org.scala-lang/scala-library@2.13.18
    #           pkg:maven/org.scala-lang/scala3-library_3@3.3.8
    # -------------------------------------------------------------------------
    "scala": {
        "name_patterns": [
            "scala",
            "scala3",
            "scala-library",
            "scala-compiler",
            "scala-reflect",
            "scala3-library*",
            "scala3-compiler*",
        ],
        "purl_types": None,
        "version_extract": "major.minor",
        "references": [
            "https://www.scala-lang.org/download/all.html",
            "https://www.scala-lang.org/blog/2022/08/17/long-term-compatibility-plans.html",
        ],
        "cycles": {
            "2.11": {"release_date": None, "end_of_support": None, "end_of_life": None},
            "2.12": {"release_date": None, "end_of_support": None, "end_of_life": None},
            "2.13": {"release_date": None, "end_of_support": None, "end_of_life": None},
            "3.0": {"release_date": "2021-05-13", "end_of_support": None, "end_of_life": None},
            "3.1": {"release_date": "2021-10-18", "end_of_support": None, "end_of_life": None},
            "3.2": {"release_date": "2022-09-01", "end_of_support": None, "end_of_life": None},
            # 3.3.x is the current LTS line.
            "3.3": {"release_date": "2023-05-30", "end_of_support": None, "end_of_life": None},
            "3.4": {"release_date": "2024-02-29", "end_of_support": None, "end_of_life": None},
            "3.5": {"release_date": "2024-08-22", "end_of_support": None, "end_of_life": None},
            "3.6": {"release_date": "2024-12-10", "end_of_support": None, "end_of_life": None},
            "3.7": {"release_date": "2025-05-07", "end_of_support": None, "end_of_life": None},
            "3.8": {"release_date": "2026-01-22", "end_of_support": None, "end_of_life": None},
        },
    },
    # -------------------------------------------------------------------------
    # Swift
    # Source: https://github.com/swiftlang/swift/releases (the official Swift
    #         toolchain repo; swift-X.Y-RELEASE tags), verified 2026-08-08.
    # Note: Swift.org publishes NO support policy and NO end-of-life dates for
    # older toolchains, so only release dates are recorded here.
    #
    # NAME COLLISION WARNING: "swift" is also the name of OpenStack Swift, the
    # object storage service, published as pkg:pypi/swift and packaged by most
    # distros. Its versions (2.x) do not overlap the Swift language cycles
    # listed here, so a lookup for OpenStack Swift falls through to None rather
    # than picking up a wrong date -- but do not add 2.x cycles here without
    # first narrowing purl_types.
    # -------------------------------------------------------------------------
    "swift": {
        "name_patterns": [
            "swift",
            "swift-lang",
            "swiftlang",
        ],
        "purl_types": None,
        "version_extract": "major.minor",
        "references": [
            "https://www.swift.org/install/",
            "https://github.com/swiftlang/swift/releases",
        ],
        "cycles": {
            "5.0": {"release_date": "2019-04-03", "end_of_support": None, "end_of_life": None},
            "5.1": {"release_date": "2019-09-23", "end_of_support": None, "end_of_life": None},
            "5.2": {"release_date": "2020-03-24", "end_of_support": None, "end_of_life": None},
            "5.3": {"release_date": "2020-09-16", "end_of_support": None, "end_of_life": None},
            "5.4": {"release_date": "2021-04-26", "end_of_support": None, "end_of_life": None},
            "5.5": {"release_date": "2021-09-21", "end_of_support": None, "end_of_life": None},
            "5.6": {"release_date": "2022-03-14", "end_of_support": None, "end_of_life": None},
            "5.7": {"release_date": "2022-09-12", "end_of_support": None, "end_of_life": None},
            "5.8": {"release_date": "2023-03-30", "end_of_support": None, "end_of_life": None},
            "5.9": {"release_date": "2023-09-18", "end_of_support": None, "end_of_life": None},
            "5.10": {"release_date": "2024-03-05", "end_of_support": None, "end_of_life": None},
            "6.0": {"release_date": "2024-09-17", "end_of_support": None, "end_of_life": None},
            "6.1": {"release_date": "2025-04-01", "end_of_support": None, "end_of_life": None},
            "6.2": {"release_date": "2025-09-17", "end_of_support": None, "end_of_life": None},
            "6.3": {"release_date": "2026-03-27", "end_of_support": None, "end_of_life": None},
        },
    },
}


def get_package_lifecycle_entry(package_name: str) -> Optional[PackageLifecycleEntry]:
    """
    Find the lifecycle entry that matches a package name.

    Args:
        package_name: Package name to match

    Returns:
        PackageLifecycleEntry or None if no match found
    """
    import fnmatch

    name_lower = package_name.lower()

    for entry_key, entry in PACKAGE_LIFECYCLE.items():
        patterns = entry.get("name_patterns", [])
        for pattern in patterns:
            if fnmatch.fnmatch(name_lower, pattern.lower()):
                return entry

    return None


def extract_version_cycle(version: str, version_extract: Optional[str] = None) -> Optional[str]:
    """
    Extract the version cycle from a full version string.

    Args:
        version: Full version string (e.g., "3.12.7", "4.2.9", "19.0.1")
        version_extract: "major" or "major.minor" (default: "major.minor")

    Returns:
        Version cycle string (e.g., "3.12", "4.2", "19") or None
    """
    if not version:
        return None

    # Remove common prefixes
    v = version.lstrip("v")

    # Split on dots
    parts = v.split(".")

    if not parts:
        return None

    # Handle version_extract mode
    if version_extract == "major":
        # Return just the major version
        # Handle cases like "3.12" where there's no patch
        return parts[0] if parts[0].isdigit() else None
    else:
        # Default: major.minor
        if len(parts) >= 2:
            major, minor = parts[0], parts[1]
            # Handle minor versions with suffixes (e.g., "12-rc1")
            minor = minor.split("-")[0].split("+")[0]
            if major.isdigit() and minor.isdigit():
                return f"{major}.{minor}"
        elif len(parts) == 1 and parts[0].isdigit():
            # Single number version (e.g., "19") - return as-is
            return parts[0]

    return None


def get_package_lifecycle(
    package_name: str,
    version: str,
    purl_type: Optional[str] = None,
) -> Optional[LifecycleDates]:
    """
    Get lifecycle dates for a package version.

    Args:
        package_name: Package name (e.g., "django", "python3")
        version: Package version (e.g., "4.2.9", "3.12.1")
        purl_type: Optional PURL type to filter matches (e.g., "pypi", "npm")

    Returns:
        LifecycleDates dict or None if not found
    """
    entry = get_package_lifecycle_entry(package_name)
    if not entry:
        return None

    # Check PURL type filter
    allowed_types = entry.get("purl_types")
    if allowed_types is not None and purl_type is not None:
        if purl_type.lower() not in [t.lower() for t in allowed_types]:
            return None

    # Extract version cycle
    version_extract = entry.get("version_extract", "major.minor")
    cycle = extract_version_cycle(version, version_extract)
    if not cycle:
        return None

    # Look up cycle in the entry's cycles
    cycles = entry.get("cycles", {})
    return cycles.get(cycle)


def get_distro_lifecycle(distro_name: str, version: str) -> Optional[LifecycleDates]:
    """
    Get lifecycle dates for an operating system version.

    Args:
        distro_name: OS name (e.g., "debian", "ubuntu", "alpine")
        version: OS version (e.g., "12.12", "22.04", "3.20")

    Returns:
        LifecycleDates dict or None if not found
    """
    import re

    distro_lower = distro_name.lower()

    # Map common OS name variations to our canonical names
    distro_mappings = {
        "alma": "almalinux",
        "amazon": "amazonlinux",
        "amzn": "amazonlinux",
        "ol": "oracle",  # Oracle Linux
        "oraclelinux": "oracle",
    }
    distro_key = distro_mappings.get(distro_lower, distro_lower)

    distro_data = DISTRO_LIFECYCLE.get(distro_key)
    if not distro_data:
        return None

    # Normalize version string
    # Handle complex versions like "2023.10.20260105 (Amazon Linux)" -> "2023"
    # or "9.7 (Blue Onyx)" -> "9"
    version_clean = version.split("(")[0].strip()  # Remove parenthetical suffixes

    # Try exact match first
    if version_clean in distro_data:
        return distro_data[version_clean]

    # Try progressively shorter version prefixes
    # e.g., "12.12" -> "12", "3.20.1" -> "3.20" -> "3"
    parts = version_clean.split(".")
    for i in range(len(parts) - 1, 0, -1):
        prefix = ".".join(parts[:i])
        if prefix in distro_data:
            return distro_data[prefix]

    # For Amazon Linux, try extracting just the year (2023, 2)
    if distro_key == "amazonlinux":
        year_match = re.match(r"^(\d{4}|\d)", version_clean)
        if year_match:
            year = year_match.group(1)
            if year in distro_data:
                return distro_data[year]

    # For CentOS, version "9" should map to "stream9"
    # (CentOS Stream is the only supported CentOS now)
    if distro_key == "centos":
        stream_version = f"stream{version_clean}"
        if stream_version in distro_data:
            return distro_data[stream_version]

    return None
