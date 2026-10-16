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

The demo policies are:

| Blocklist prefix | Policy | Rule / finding |
|---|---|---|
| `org/apache/httpcomponents/httpclient/` | `ACME-EOL-Components` | `Block end-of-life components` |
| `org/apache/httpcomponents/httpclient/4.5.12/` | `ACME-Critical-CVE` | `Block critical CVEs` - `CVE-2020-13956 (Critical)` |

When multiple entries match a path, the longest matching prefix selects the policy. HttpClient 5 artifacts under
`org/apache/httpcomponents/client5/` are not matched by the HttpClient 4.x block.

For `org/apache/httpcomponents/httpclient/4.5.14/httpclient-4.5.14.pom`, the reason is:

```
Download blocked by Xray policy 'ACME-EOL-Components' (watch: acme-maven-virtual). Artifact org.apache.httpcomponents:httpclient:4.5.14 violates rule 'Block end-of-life components' - Apache HttpClient 4.x is end-of-life; migrate to HttpClient 5.x (org.apache.httpcomponents.client5:httpclient5). Contact #artifactory-support.
```

Other blocklist entries get a generic `ACME-Default-Block` reason with the artifact coordinates derived from the path.
GitHub-hosted runners' Maven shows only `HTTP Status: 403`, so the reason is also written to the access log.

Every request is logged as one line on stdout: `<METHOD> <path> <status> source=<central|cache|internal|blocked|local>`; responses with a reason and status >= 400 append ` reason="<reason>"`.

## Configuration (all optional)

| Variable | Default | Meaning |
|---|---|---|
| `BLOCKLIST` | *(empty: nothing blocked)* | Comma-separated repository path prefixes to block, e.g. `org/apache/httpcomponents/httpclient/` |
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
CACHE_DIR=/tmp/mock-artifactory BLOCKLIST=org/apache/httpcomponents/httpclient/ python3 mock_artifactory.py
```

With Docker:

```bash
docker build -t acme-mock-artifactory .
docker run --rm -p 8081:8081 -e BLOCKLIST=org/apache/httpcomponents/httpclient/ acme-mock-artifactory
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
