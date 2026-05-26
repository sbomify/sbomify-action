# Docker Hub upstream SBOM examples

End-to-end verification for the Docker Hub SBOM consumption feature. Covers
the direct path (user image _is_ a Docker Official / DHI image) and the
provenance path (user image was built FROM a Docker Hub base).

## Scenarios

| Dockerfile | Base image | What's tested |
|---|---|---|
| _(no file)_ | `python:3.11-slim` directly | Direct detection of a Docker Official Image, SBOM fetch via crane, merge with Syft |
| `Dockerfile.official` | `python:3.11-slim` | Provenance-based detection of a `library/*` base, SBOM fetch + merge |
| `Dockerfile.dhi` | `dhi.io/python:3.11` | DHI base detection + cosign-verified SBOM fetch |

## Requirements

- `docker` + `docker buildx` (default builder supports BuildKit v0.22+)
- `crane`, `cosign`, `syft` on `PATH` (or run from inside the sbomify-action image)
- A local registry to push to: `docker run -d -p 5000:5000 --name sbomify-registry registry:2`
- `docker login` with a Docker Hub account (free). Two reasons:
  - **Rate limits.** Anonymous pulls are capped at 100 manifest requests / 6 hours / IP. Each image scan uses ~3 requests, so a single run through all scenarios will exhaust the limit. A free Docker Hub account raises the limit to 200/6h; paid plans lift it entirely.
  - **DHI access.** Docker Hardened Images (`dhi.io/*`) require a logged-in Docker Hub account even though the images themselves are free.

## Running

```bash
./run-e2e.sh
```

The script builds each sample with `--provenance=mode=max --sbom=false`, pushes to
the local registry, runs `sbomify-action` against it, and summarises:

- Whether the Docker Hub branch fired (detection + SBOM fetch)
- Count of `docker-hub-upstream`-tagged vs `syft-overlay`-tagged components
- Whether the user-installed packages (`requests`, `click`, `curl`, `jq`) show up as overlays

See the script for exit codes and precise assertions.

## Why `--sbom=false`

BuildKit can attach its own whole-image SBOM when a user image is built with
`--sbom=true`. In that case the resulting image _already_ has a complete SBOM
attached, and sbomify-action could theoretically consume that directly. The
interesting case — and what this feature targets — is when a user's image has
build _provenance_ (naming its base image) but no full SBOM of its own, which
is the shape produced by `--provenance=mode=max --sbom=false`. That's the
default for many CI/CD setups and what this runner exercises.
