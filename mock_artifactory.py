#!/usr/bin/env python3
"""Mock Artifactory (demo simulation): a tiny Maven "virtual repo" proxy.

GET/HEAD /artifactory/maven-virtual/<path> is resolved, in order, as:
  blocked  -> 403 with an Xray-style reason phrase (BLOCKLIST path prefixes)
  internal -> read from the INTERNAL_GIT_BRANCH of INTERNAL_GIT_URL (never cached)
  central  -> proxied from Maven Central and cached on disk under CACHE_DIR
"""
import html
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO_PREFIX = "/artifactory/maven-virtual/"
ARTIFACTORY_ID = "acme-artifactory-demo"
DEFAULTS = {
    "BLOCKLIST": "",
    "INTERNAL_PREFIX": "com/acme/",
    "INTERNAL_GIT_URL": "https://github.com/aaron-cog-gtm-gh-org/acme-commons-http.git",
    "INTERNAL_GIT_BRANCH": "maven-repo",
    "INTERNAL_REFRESH_SECONDS": "5",
    "CACHE_DIR": "/var/cache/mock-artifactory",
    "CENTRAL_URL": "https://repo1.maven.org/maven2",
    "PORT": "8081",
}
# (policy, watch, rule, finding) keyed by blocklist entry; anything else uses the fallback.
POLICIES = {
    "org/apache/httpcomponents/httpclient/4.5.12/": (
        "ACME-Critical-CVE", "acme-maven-virtual", "Block critical CVEs", "CVE-2020-13956 (Critical)"),
}
FALLBACK_POLICY = ("ACME-Default-Block", "acme-maven-virtual", "Blocked by repository administrator", None)
CONTENT_TYPES = {".pom": "application/xml", ".xml": "application/xml", ".jar": "application/java-archive",
                 ".sha1": "text/plain", ".md5": "text/plain", ".sha256": "text/plain", ".sha512": "text/plain",
                 ".asc": "text/plain"}


def log(msg):
    print(msg, file=sys.stdout, flush=True)


def gav_from_path(path):
    """org/apache/x/lib/1.0/lib-1.0.jar -> org.apache.x:lib:1.0 (best effort)."""
    parts = [p for p in path.split("/") if p]
    if parts and not path.endswith("/"):
        filename = parts.pop()
        if filename.startswith("maven-metadata") and len(parts) >= 2:
            return "%s:%s" % (".".join(parts[:-1]), parts[-1])
    if len(parts) >= 3:
        return "%s:%s:%s" % (".".join(parts[:-2]), parts[-2], parts[-1])
    return ".".join(parts) or path


def block_reason(entry, path):
    policy, watch, rule, finding = POLICIES.get(entry, FALLBACK_POLICY)
    text = "Download blocked by Xray policy '%s' (watch: %s). Artifact %s violates rule '%s'" % (
        policy, watch, gav_from_path(path), rule)
    text += (" - %s." % finding) if finding else "."
    return text + " Contact #artifactory-support."


class InternalRepo:
    """Shallow, bare mirror of one branch; refreshed at most every `refresh` seconds and on every miss."""

    def __init__(self, url, branch, git_dir, refresh):
        self.url, self.branch, self.git_dir, self.refresh = url, branch, git_dir, refresh
        self.ref = "refs/mock/" + branch
        self.lock = threading.Lock()
        self.last_fetch = None

    def _git(self, *args):
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        return subprocess.run(["git", "--git-dir", self.git_dir, *args], capture_output=True, env=env, timeout=60)

    def _fetch(self):
        self.last_fetch = time.monotonic()
        if not os.path.isdir(self.git_dir):
            subprocess.run(["git", "init", "-q", "--bare", self.git_dir], capture_output=True, check=True)
        res = self._git("fetch", "-q", "--depth", "1", "--no-tags", self.url, "+refs/heads/%s:%s" % (self.branch, self.ref))
        if res.returncode != 0:
            err = res.stderr.decode(errors="replace").strip().replace("\n", " | ")
            log("internal fetch of %s@%s failed (serving last fetched state): %s" % (self.url, self.branch, err))
        return res.returncode == 0

    def _show(self, path):
        res = self._git("show", "%s:%s" % (self.ref, path))
        return res.stdout if res.returncode == 0 else None

    def get(self, path):
        with self.lock:
            fetched = False
            if self.last_fetch is None or time.monotonic() - self.last_fetch >= self.refresh:
                self._fetch()
                fetched = True
            data = self._show(path)
            if data is None and not fetched:
                self._fetch()
                data = self._show(path)
            return data


class Config:
    def __init__(self, env=None, **overrides):
        merged = dict(DEFAULTS)
        merged.update({k: v for k, v in (os.environ if env is None else env).items() if k in DEFAULTS})
        merged.update({k.upper(): str(v) for k, v in overrides.items()})
        self.blocklist = [e.strip().lstrip("/") for e in merged["BLOCKLIST"].split(",") if e.strip()]
        self.internal_prefix = merged["INTERNAL_PREFIX"].lstrip("/")
        self.internal_git_url = merged["INTERNAL_GIT_URL"]
        self.internal_git_branch = merged["INTERNAL_GIT_BRANCH"]
        self.refresh_seconds = float(merged["INTERNAL_REFRESH_SECONDS"])
        self.cache_dir = merged["CACHE_DIR"]
        self.central_url = merged["CENTRAL_URL"].rstrip("/")
        self.port = int(merged["PORT"])


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def version_string(self):
        return "mock-artifactory/1.0"

    def log_message(self, fmt, *args):  # replaced by the one-line-per-request log in _send
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        cfg = self.server.config
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            return self._send(200, b"ok\n", "text/plain", "local")
        if path == "/":
            return self._send(200, self._index(cfg).encode(), "text/html; charset=utf-8", "local")
        if not path.startswith(REPO_PREFIX):
            return self._error(404, "Not found", "local")
        rel = urllib.parse.unquote(path[len(REPO_PREFIX):])
        if not rel or any(p in ("..", ".") for p in rel.split("/")):
            return self._error(400, "Bad request", "local")
        for entry in cfg.blocklist:
            if rel.startswith(entry):
                return self._error(403, block_reason(entry, rel), "blocked")
        if rel.startswith(cfg.internal_prefix):
            data = self.server.internal.get(rel)
            if data is None:
                return self._error(404, "Could not find resource", "internal")
            return self._send(200, data, content_type(rel), "internal")
        self._central(cfg, rel)

    def _central(self, cfg, rel):
        cached = os.path.join(cfg.cache_dir, "central", *rel.split("/"))
        if os.path.isfile(cached):
            with open(cached, "rb") as f:
                return self._send(200, f.read(), content_type(rel), "cache")
        req = urllib.request.Request(cfg.central_url + "/" + urllib.parse.quote(rel),
                                     headers={"User-Agent": "mock-artifactory/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
        except urllib.error.HTTPError as e:
            return self._error(e.code, e.reason or "Upstream error", "central")
        except (urllib.error.URLError, OSError) as e:
            log("central fetch failed for %s: %s" % (rel, e))
            return self._error(502, "Bad gateway", "central")
        os.makedirs(os.path.dirname(cached), exist_ok=True)
        tmp = "%s.tmp.%d" % (cached, threading.get_ident())
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, cached)
        self._send(200, data, content_type(rel), "central")

    def _error(self, status, message, source):
        body = json.dumps({"errors": [{"status": status, "message": message}]}).encode()
        self._send(status, body, "application/json", source, reason=message)

    def _send(self, status, body, ctype, source, reason=None):
        self.send_response(status, reason)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Artifactory-Id", ARTIFACTORY_ID)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        log("%s %s %d source=%s" % (self.command, self.path, status, source))

    @staticmethod
    def _index(cfg):
        rows = "".join("<tr><th>%s</th><td>%s</td></tr>" % (k, html.escape(str(v))) for k, v in [
            ("Repository", REPO_PREFIX), ("BLOCKLIST", ", ".join(cfg.blocklist) or "(nothing blocked)"),
            ("INTERNAL_PREFIX", cfg.internal_prefix),
            ("INTERNAL_GIT_URL", "%s @ %s" % (cfg.internal_git_url, cfg.internal_git_branch)),
            ("INTERNAL_REFRESH_SECONDS", cfg.refresh_seconds), ("Upstream", cfg.central_url)])
        return ("<!doctype html><html><head><title>Mock Artifactory (demo simulation)</title></head><body>"
                "<h1>Mock Artifactory (demo simulation)</h1><table>%s</table></body></html>\n" % rows)


def content_type(path):
    return CONTENT_TYPES.get(os.path.splitext(path)[1], "application/octet-stream")


def make_server(config=None, host="0.0.0.0", port=None):
    config = config or Config()
    os.makedirs(config.cache_dir, exist_ok=True)
    server = ThreadingHTTPServer((host, config.port if port is None else port), Handler)
    server.daemon_threads = True
    server.config = config
    server.internal = InternalRepo(config.internal_git_url, config.internal_git_branch,
                                   os.path.join(config.cache_dir, "internal.git"), config.refresh_seconds)
    return server


def main():
    config = Config()
    server = make_server(config)
    log("Mock Artifactory (demo simulation) listening on :%d%s blocklist=%s internal=%s@%s (%s*)" % (
        config.port, REPO_PREFIX, config.blocklist or "[]", config.internal_git_url,
        config.internal_git_branch, config.internal_prefix))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
