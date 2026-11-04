# Monorepos

One run of sbomify-action reads one input (a lock file, a container image, an existing SBOM or a
directory) and writes one SBOM for one component. Set two of `LOCK_FILE`, `DOCKER_IMAGE`,
`SBOM_FILE` and `SOURCE_DIR` and the run stops with "Please provide only one of". A repository
with several packages runs the action once per package. On GitHub Actions that is a matrix job, and
[`examples/github/monorepo.yml`](../examples/github/monorepo.yml) is a complete one to copy.

The [setup wizard](../README.md#quick-start) builds this for you. It finds every lock file in the
repository, registers a component for each, and writes the matrix.

## One component per package

Give each package its own sbomify component and its own `COMPONENT_ID`. A component is one thing
with one version history. Two packages uploading to the same ID take turns being its latest SBOM,
and the history stops describing either of them.

It is also what compliance checks look for. NTIA minimum elements, the EU CRA and BSI TR-03183-2
identify what an SBOM describes by name, version and supplier, and a document that blends three
services has no single answer to any of those.

### No client-side merging

The action does not merge SBOMs, and that is by design: sbomify assembles the combined view per
release. Tag every package's upload into the same product release with `PRODUCT_RELEASE`:

```yaml
PRODUCT_RELEASE: '["your-product-id:v1.4.0"]'
```

The release then lists every component's SBOM side by side, and its aggregate download is the merged
view. Each job uploads on its own, so with `fail-fast: false` a failed package leaves only its own
component missing from the release.

Without a sbomify account, keep the per-package files. Each one is a complete SBOM for its package.

## Point each run at its package

`working-dir` (the action input) or `WORKING_DIR` (the environment variable, for the container
image and the CLI) moves the run into the package's directory before anything else happens. Give it
relative to the repository root. On GitHub Actions it must stay inside the checkout.

```yaml
- uses: sbomify/sbomify-action@57ca9ba7de2232b073a3799bc8c0dc002e6777b9 # v26.10.2
  with:
    working-dir: services/api
  env:
    LOCK_FILE: uv.lock
    OUTPUT_FILE: api.cdx.json
```

Everything relative then resolves inside that directory:

| What | Read or written in `WORKING_DIR` | If it is not there |
| --- | --- | --- |
| `LOCK_FILE`, `SBOM_FILE` | Read | The file of the same name at the repository root is used instead |
| `sbomify.json` | Read | The one at the repository root is used instead |
| `additional_packages.txt`, `ADDITIONAL_PACKAGES_FILE` | Read | Not used |
| `OUTPUT_FILE` | Written: `services/api/api.cdx.json` above | |

The other way to aim a run is `LOCK_FILE: services/api/uv.lock` from the root, which is what the
wizard writes. The dependencies come out the same, because the generator runs against the lock
file's own directory. But `sbomify.json` and `additional_packages.txt` are then read from the root
and the SBOM is written there. Use `WORKING_DIR` once packages carry their own `sbomify.json`, for
example because they have different suppliers or licenses.

## Matrix jobs

[`examples/github/monorepo.yml`](../examples/github/monorepo.yml) has one matrix entry per package:
a name, a directory, a lock file and a component ID. Three details in it are easy to lose:

- **`fail-fast: false`.** The default cancels every running job once one fails, so one broken
  package stops the others' SBOMs being produced.
- **A unique artifact name per job.** `actions/upload-artifact` v4 and later refuses a second
  artifact with the same name in one run, so the second job to finish fails.
- **The artifact path includes the working directory**, because `OUTPUT_FILE` is written inside it.
  `if-no-files-found: error` makes a wrong path fail the job. The default only warns, and the job
  goes green with no SBOM saved.

### GitLab CI

`parallel:matrix` does the same, with the container image:

```yaml
sbom:
  image: ghcr.io/sbomify/sbomify-action:26.10.2
  parallel:
    matrix:
      - WORKING_DIR: services/api
        LOCK_FILE: uv.lock
        COMPONENT_NAME: api
      - WORKING_DIR: services/web
        LOCK_FILE: package-lock.json
        COMPONENT_NAME: web
  variables:
    OUTPUT_FILE: sbom.cdx.json
    ENRICH: 'true'
    UPLOAD: 'false'
  script:
    - sbomify-action
  artifacts:
    paths:
      - $WORKING_DIR/sbom.cdx.json
```

GitLab keeps artifacts per job, so one file name is fine. To upload, add `COMPONENT_ID` to each
matrix entry and set `UPLOAD: 'true'`. The single-package version is
[`examples/gitlab/gitlab-ci.yml`](../examples/gitlab/gitlab-ci.yml).

### Bitbucket Pipelines

Bitbucket has no matrix. Put one step per package in a `parallel` block, each exporting its own
`WORKING_DIR`, `LOCK_FILE` and `COMPONENT_ID` and listing `<WORKING_DIR>/sbom.cdx.json` under
`artifacts`, starting from
[`examples/bitbucket/bitbucket-pipelines.yml`](../examples/bitbucket/bitbucket-pipelines.yml).

## Choosing `LOCK_FILE` per package

Name each package's own lock file, from the [supported lock files](../README.md#supported-lock-files).
Where a package has two for the same ecosystem, such as `pnpm-lock.yaml` and `yarn.lock`, naming
one is the only way to say which is real.

**Workspace lock files are the trap.** uv workspaces, npm, pnpm and Yarn workspaces, and Cargo
workspaces resolve every member into one lock file at the workspace root. Point each member at that
file and every component gets the whole workspace's dependencies. It also happens without asking:
`working-dir: packages/api` with `LOCK_FILE: uv.lock` and no `packages/api/uv.lock` reads the root
`uv.lock` and carries on. The log line `Using input file '/github/workspace/uv.lock'` is the only
sign.

Two ways out:

- If the workspace ships as one thing, make it one component, with one run against the root lock
  file.
- Otherwise give each member a lock file of its own in a step before the action runs, and point that
  member's `LOCK_FILE` at it. For uv:
  `uv export --package api -o packages/api/requirements.txt`, then `LOCK_FILE: requirements.txt`.

## Naming and versioning components

- **`COMPONENT_NAME`.** Set it per package. Unset, the name is whatever the generator reports: the
  manifest's package name when there is one, otherwise often the name of the directory it ran in.
  NTIA and the EU CRA both expect the component to be named for what you ship.
- **`COMPONENT_VERSION`.** Unset, the version is whatever the generator reports, usually the
  manifest's version. Set it when packages are versioned independently of anything the manifest
  says.
- **`COMPONENT_PURL`.** States the package's identity outright, for example
  `pkg:npm/@acme/web@1.4.0`, when the generated one is wrong or missing.
- **`OUTPUT_FILE`.** Name it per package so the files stay apart once they are collected.

Per-package tags such as `api-v1.4.0` need one extra step. Passed straight through as
`COMPONENT_VERSION`, the tag is kept as written and the run warns that it "looks like a release of
a different package". `VERSION_FROM_RELEASE_TAG: true` ignores such a tag altogether. Strip the
prefix yourself, and build only the package the tag names. In the matrix example, triggered on
`tags: ['*-v*']`:

```yaml
- id: ver # api-v1.4.0 gives 1.4.0 on the api row, nothing on the others
  env:
    PREFIX: ${{ matrix.name }}-v
  run: |
    case "$GITHUB_REF_NAME" in
      "$PREFIX"*) echo "version=${GITHUB_REF_NAME#"$PREFIX"}" >> "$GITHUB_OUTPUT" ;;
    esac
- uses: sbomify/sbomify-action@57ca9ba7de2232b073a3799bc8c0dc002e6777b9 # v26.10.2
  if: steps.ver.outputs.version != ''
  env:
    COMPONENT_VERSION: ${{ steps.ver.outputs.version }}
    # ...the rest as in the matrix example
```

Give the upload step the same `if`, or it fails on the rows that produced no SBOM.

## Pitfalls

Each of these produces a wrong or missing SBOM, most of them without failing the build:

| Symptom | Cause | Fix |
| --- | --- | --- |
| "Please provide only one of" | Two inputs in one run | One run per input, as a matrix |
| No merged SBOM | Not produced on the client, by design | `PRODUCT_RELEASE` into one release, download the release |
| Every package lists every dependency | A workspace lock file, or the root fallback for a missing `LOCK_FILE` | [Choosing `LOCK_FILE` per package](#choosing-lock_file-per-package) |
| Every package has the root's supplier and license | The root `sbomify.json` applies when the package has none | A `sbomify.json` per package, and `WORKING_DIR` |
| Job green, no artifact | Artifact path missing the working directory | Include it, and set `if-no-files-found: error` |
| Second matrix job fails to upload its artifact | Same artifact name in every job | Name it per package |
| One component's history mixes packages | Several packages share a `COMPONENT_ID` | One component per package |
| Version is `api-v1.4.0`, or the generator's | A per-package tag used as the version | Strip the prefix in a step |
| SBOMs missing after one package fails | `fail-fast` defaults to true | `fail-fast: false` |
