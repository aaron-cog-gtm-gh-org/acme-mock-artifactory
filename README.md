# Mock Artifactory (demo simulation)

> **This is a demo simulation, not JFrog Artifactory.** It is a ~250-line Python (stdlib only) proxy that
> imitates an Artifactory Maven *virtual repository* with an Xray "block download" policy, so CI builds can
> show a realistic `403` when a blocked dependency is resolved.

## What it does

`GET`/`HEAD /artifactory/maven-virtual/<path>` is resolved in this order:

| Source | When | Behaviour |
|---|---|---|
| `blocked` | `<path>` starts with any `BLOCKLIST` prefix | `HTTP/1.1 403 <reason>` with JSON body `{"errors":[{"status":403,"message":"<reason>"}]}` and header `X-Artifactory-Id: acme-artifactory-demo` |
| `internal` | `<path>` starts with `INTERNAL_PREFIX` | Read from branch `INTERNAL_GIT_BRANCH` of `INTERNAL_GIT_URL` (shallow `git fetch --depth 1`, at most once per `INTERNAL_REFRESH_SECONDS` and always on a miss). Never cached beyond that, so a newly pushed release shows up within seconds. Missing -> `404`. If a fetch fails the last fetched state is served. |
| `central` / `cache` | everything else | Proxied from Maven Central and cached on disk under `CACHE_DIR`. Upstream errors (e.g. `404`) are passed through and not cached. |

Other routes: `GET /` (HTML status page titled "Mock Artifactory (demo simulation)") and `GET /healthz` (`200 ok`).

For the demo blocklist entry `org/apache/httpcomponents/httpclient/4.5.12/` the reason phrase is:

```
Download blocked by Xray policy 'ACME-Critical-CVE' (watch: acme-maven-virtual). Artifact org.apache.httpcomponents:httpclient:4.5.12 violates rule 'Block critical CVEs' - CVE-2020-13956 (Critical). Contact #artifactory-support.
```

Other blocklist entries get a generic `ACME-Default-Block` reason with the artifact coordinates derived from the path.
Maven 3.9.x prints the reason phrase verbatim:
`... status code: 403, reason phrase: Download blocked by Xray policy ... (403)`.

Every request is logged as one line on stdout: `<METHOD> <path> <status> source=<central|cache|internal|blocked|local>`.

## Configuration (all optional)

| Variable | Default | Meaning |
|---|---|---|
| `BLOCKLIST` | *(empty: nothing blocked)* | Comma-separated repository path prefixes to block, e.g. `org/apache/httpcomponents/httpclient/4.5.12/` |
| `INTERNAL_PREFIX` | `com/acme/` | Paths served from the internal git-backed release repo |
| `INTERNAL_GIT_URL` | `https://github.com/aaron-cog-gtm-gh-org/acme-commons-http.git` | Git repo holding the Maven layout (unauthenticated fetch) |
| `INTERNAL_GIT_BRANCH` | `maven-repo` | Branch holding the Maven layout at its root |
| `INTERNAL_REFRESH_SECONDS` | `5` | Minimum seconds between fetches (a miss always fetches) |
| `CACHE_DIR` | `/var/cache/mock-artifactory` | Disk cache for Maven Central artifacts plus the internal bare clone |
| `CENTRAL_URL` | `https://repo1.maven.org/maven2` | Upstream base URL (override for tests or a Central mirror) |
| `PORT` | `8081` | Listen port |

## Run

Without Docker (Python 3.12 and `git` on `PATH`):

```bash
CACHE_DIR=/tmp/mock-artifactory BLOCKLIST=org/apache/httpcomponents/httpclient/4.5.12/ python3 mock_artifactory.py
```

With Docker:

```bash
docker build -t acme-mock-artifactory .
docker run --rm -p 8081:8081 -e BLOCKLIST=org/apache/httpcomponents/httpclient/4.5.12/ acme-mock-artifactory
# or the published image: ghcr.io/aaron-cog-gtm-gh-org/acme-mock-artifactory:latest
```

Point Maven at it with a mirror in `.mvn/settings.xml` (`<url>${env.ARTIFACTORY_URL}</url>`, `<mirrorOf>*</mirrorOf>`) and
`ARTIFACTORY_URL=http://localhost:8081/artifactory/maven-virtual`, then `mvn -B -s .mvn/settings.xml verify`.

As a GitHub Actions service container:

```yaml
services:
  artifactory:
    image: ghcr.io/aaron-cog-gtm-gh-org/acme-mock-artifactory:latest
    credentials:
      username: ${{ github.actor }}
      password: ${{ secrets.GITHUB_TOKEN }}
    ports: ["8081:8081"]
    env:
      BLOCKLIST: ${{ vars.ARTIFACTORY_BLOCKLIST }}
```

The image has a `HEALTHCHECK` on `/healthz`, so Actions waits until the proxy is up before running steps.

## Tests

```bash
python3 -m unittest -v
```

The tests need only `git`: they create a local `file://` git repo as the internal release repo and a local HTTP stub as Maven Central.

## Publishing

`.github/workflows/publish-image.yml` builds and pushes `ghcr.io/aaron-cog-gtm-gh-org/acme-mock-artifactory:latest` and
`:sha-<short>` on every push to `main` (and on manual dispatch). `.github/workflows/test.yml` runs the tests and a
`docker build` on pull requests.
