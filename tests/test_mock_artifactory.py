import http.client
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import mock_artifactory as ma

HTTPCLIENT4 = "org/apache/httpcomponents/httpclient/"
BLOCKED = HTTPCLIENT4 + "4.5.12/"
CLIENT5_POM = "org/apache/httpcomponents/client5/httpclient5/5.3.1/httpclient5-5.3.1.pom"
EXPECTED_REASON = (
    "Download blocked by Xray policy 'ACME-Critical-CVE' (watch: acme-maven-virtual). "
    "Artifact org.apache.httpcomponents:httpclient:4.5.12 violates rule 'Block critical CVEs' - "
    "CVE-2020-13956 (Critical). Contact #artifactory-support.")
LIB = "com/acme/commons/acme-commons-http/"
REFRESH = 1.0


def metadata(*versions):
    vs = "".join("<version>%s</version>" % v for v in versions)
    return ("<metadata><groupId>com.acme.commons</groupId><artifactId>acme-commons-http</artifactId>"
            "<versioning><release>%s</release><versions>%s</versions></versioning></metadata>" % (versions[-1], vs))


def eol_reason(version):
    return ("Download blocked by Xray policy 'ACME-EOL-Components' (watch: acme-maven-virtual). "
            "Artifact org.apache.httpcomponents:httpclient:%s violates rule 'Block end-of-life components' - "
            "Apache HttpClient 4.x is end-of-life; migrate to HttpClient 5.x "
            "(org.apache.httpcomponents.client5:httpclient5). Contact #artifactory-support." % version)


class Upstream(BaseHTTPRequestHandler):
    """Stub Maven Central: serves FILES, counts hits per path."""
    FILES = {"/maven2/" + BLOCKED + "httpclient-4.5.12.pom": b"<project>httpclient</project>",
             "/maven2/" + CLIENT5_POM: b"<project>httpclient5</project>",
             "/maven2/junit/junit/4.13.2/junit-4.13.2.jar": b"PK\x03\x04fake-jar"}
    hits = {}
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        Upstream.hits[self.path] = Upstream.hits.get(self.path, 0) + 1
        body = self.FILES.get(self.path)
        self.send_response(200 if body else 404)
        body = body or b"not found"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                   cwd=cwd, check=True, capture_output=True)


def stop(server):
    server.shutdown()
    server.server_close()


def serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class CapturedStdout(StringIO):
    def __init__(self, expected):
        super().__init__()
        self.expected = expected
        self.logged = threading.Event()

    def write(self, text):
        written = super().write(text)
        if self.expected in self.getvalue():
            self.logged.set()
        return written


class MockArtifactoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.src = os.path.join(cls.tmp, "acme-commons-http")
        os.makedirs(os.path.join(cls.src, LIB, "1.4.0"))
        git(cls.src, "init", "-q", "-b", "maven-repo")
        cls.write(LIB + "1.4.0/acme-commons-http-1.4.0.pom", "<project>1.4.0</project>")
        cls.write(LIB + "maven-metadata.xml", metadata("1.4.0"))
        git(cls.src, "add", "-A")
        git(cls.src, "commit", "-q", "-m", "release 1.4.0")
        cls.upstream = serve(ThreadingHTTPServer(("127.0.0.1", 0), Upstream))
        cls.central = "http://127.0.0.1:%d/maven2" % cls.upstream.server_port
        cls.server = cls.start(BLOCKLIST=BLOCKED)

    @classmethod
    def tearDownClass(cls):
        stop(cls.server)
        stop(cls.upstream)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def write(cls, rel, text):
        path = os.path.join(cls.src, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    @classmethod
    def start(cls, env=None, **overrides):
        base = {"INTERNAL_GIT_URL": "file://" + cls.src, "INTERNAL_REFRESH_SECONDS": str(REFRESH),
                "CACHE_DIR": tempfile.mkdtemp(dir=cls.tmp), "CENTRAL_URL": cls.central}
        base.update(overrides)
        return serve(ma.make_server(ma.Config(env=env or {}, **base), host="127.0.0.1", port=0))

    def request(self, path, method="GET", server=None):
        conn = http.client.HTTPConnection("127.0.0.1", (server or self.server).server_port, timeout=30)
        conn.request(method, path)
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp, body

    def repo(self, rel, method="GET", server=None):
        return self.request(ma.REPO_PREFIX + rel, method, server)

    def assert_blocked_response(self, server, rel, expected_reason):
        expected = "GET %s%s 403 source=blocked" % (ma.REPO_PREFIX, rel)
        output = CapturedStdout(expected)
        with redirect_stdout(output):
            resp, body = self.repo(rel, server=server)
            self.assertTrue(output.logged.wait(1))

        self.assertEqual(resp.status, 403)
        self.assertEqual(resp.reason, expected_reason)
        self.assertEqual(json.loads(body), {"errors": [{"status": 403, "message": expected_reason}]})
        self.assertEqual(resp.getheader("X-Artifactory-Id"), "acme-artifactory-demo")
        line = next(line for line in output.getvalue().splitlines() if expected in line)
        self.assertIn('reason="%s"' % expected_reason, line)

    def test_blocked_get_logs_xray_reason(self):
        rel = BLOCKED + "httpclient-4.5.12.pom"
        expected = "GET %s%s 403 source=blocked" % (ma.REPO_PREFIX, rel)
        output = CapturedStdout(expected)
        with redirect_stdout(output):
            resp, _ = self.repo(rel)
            self.assertTrue(output.logged.wait(1))

        self.assertEqual(resp.status, 403)
        line = next(line for line in output.getvalue().splitlines() if expected in line)
        self.assertIn("source=blocked", line)
        self.assertIn("Download blocked by Xray policy 'ACME-Critical-CVE'", line)

    def test_httpclient4_eol_policy_and_httpclient5_passthrough(self):
        server = self.start(BLOCKLIST=HTTPCLIENT4)
        try:
            for version in ("4.5.12", "4.5.14"):
                rel = HTTPCLIENT4 + version + "/httpclient-%s.pom" % version
                self.assert_blocked_response(server, rel, eol_reason(version))

            upstream_path = "/maven2/" + CLIENT5_POM
            before = Upstream.hits.get(upstream_path, 0)
            resp, body = self.repo(CLIENT5_POM, server=server)
            self.assertEqual((resp.status, body), (200, b"<project>httpclient5</project>"))
            self.assertEqual(Upstream.hits.get(upstream_path, 0), before + 1)
        finally:
            stop(server)

    def test_longest_blocklist_prefix_selects_specific_policy(self):
        server = self.start(BLOCKLIST=HTTPCLIENT4 + "," + BLOCKED)
        try:
            self.assert_blocked_response(
                server, BLOCKED + "httpclient-4.5.12.pom", EXPECTED_REASON)
        finally:
            stop(server)

    def test_blocked_path_returns_403_with_reason_body_and_header(self):
        rel = BLOCKED + "httpclient-4.5.12.pom"
        before = Upstream.hits.get("/maven2/" + rel, 0)
        resp, body = self.repo(rel)
        self.assertEqual(resp.status, 403)
        self.assertEqual(resp.reason, EXPECTED_REASON)
        self.assertEqual(resp.version, 11)
        self.assertEqual(json.loads(body), {"errors": [{"status": 403, "message": EXPECTED_REASON}]})
        self.assertEqual(resp.getheader("X-Artifactory-Id"), "acme-artifactory-demo")
        self.assertEqual(resp.getheader("Content-Type"), "application/json")
        self.assertEqual(int(resp.getheader("Content-Length")), len(body))
        self.assertEqual(Upstream.hits.get("/maven2/" + rel, 0), before)

    def test_blocked_head(self):
        resp, body = self.repo(BLOCKED + "httpclient-4.5.12.jar", "HEAD")
        self.assertEqual((resp.status, resp.reason, body), (403, EXPECTED_REASON, b""))
        self.assertGreater(int(resp.getheader("Content-Length")), 0)

    def test_empty_or_unset_blocklist_passes_through(self):
        for env in ({"BLOCKLIST": ""}, {"BLOCKLIST": " , "}, {}):
            self.assertEqual(ma.Config(env=env).blocklist, [])
            server = self.start(env=env)
            try:
                resp, body = self.repo(BLOCKED + "httpclient-4.5.12.pom", server=server)
                self.assertEqual((resp.status, body), (200, b"<project>httpclient</project>"))
            finally:
                stop(server)

    def test_generic_reason_for_unmapped_blocklist_entry(self):
        server = self.start(BLOCKLIST="junit/")
        try:
            resp, _ = self.repo("junit/junit/4.13.2/junit-4.13.2.jar", server=server)
            self.assertEqual(resp.status, 403)
            self.assertIn("Artifact junit:junit:4.13.2 violates rule", resp.reason)
        finally:
            stop(server)

    def test_internal_served_from_git_and_new_release_visible_without_restart(self):
        resp, body = self.repo(LIB + "1.4.0/acme-commons-http-1.4.0.pom")
        self.assertEqual((resp.status, body), (200, b"<project>1.4.0</project>"))
        self.assertEqual(resp.getheader("Content-Type"), "application/xml")
        _, meta = self.repo(LIB + "maven-metadata.xml")
        self.assertIn(b"<release>1.4.0</release>", meta)

        self.write(LIB + "1.5.0/acme-commons-http-1.5.0.pom", "<project>1.5.0</project>")
        self.write(LIB + "maven-metadata.xml", metadata("1.4.0", "1.5.0"))
        git(self.src, "add", "-A")
        git(self.src, "commit", "-q", "-m", "release 1.5.0")
        time.sleep(REFRESH + 0.2)

        _, meta = self.repo(LIB + "maven-metadata.xml")
        self.assertIn(b"<release>1.5.0</release>", meta)
        resp, body = self.repo(LIB + "1.5.0/acme-commons-http-1.5.0.pom")
        self.assertEqual((resp.status, body), (200, b"<project>1.5.0</project>"))

    def test_internal_miss_is_404(self):
        resp, body = self.repo(LIB + "9.9.9/acme-commons-http-9.9.9.pom")
        self.assertEqual(resp.status, 404)
        self.assertEqual(json.loads(body)["errors"][0]["status"], 404)

    def test_internal_fetch_failure_serves_last_state_and_missing_branch_is_404(self):
        src = os.path.join(self.tmp, "moving-repo")
        shutil.copytree(self.src, src)
        server = self.start(INTERNAL_GIT_URL="file://" + src)
        missing = self.start(INTERNAL_GIT_BRANCH="no-such-branch")
        try:
            self.assertEqual(self.repo(LIB + "maven-metadata.xml", server=server)[0].status, 200)
            shutil.rmtree(src)
            time.sleep(REFRESH + 0.2)
            self.assertEqual(self.repo(LIB + "maven-metadata.xml", server=server)[0].status, 200)
            self.assertEqual(self.repo(LIB + "maven-metadata.xml", server=missing)[0].status, 404)
        finally:
            stop(server)
            stop(missing)

    def test_central_artifact_cached_on_disk(self):
        server = self.start()
        try:
            rel = "junit/junit/4.13.2/junit-4.13.2.jar"
            before = Upstream.hits.get("/maven2/" + rel, 0)
            for _ in range(2):
                resp, body = self.repo(rel, server=server)
                self.assertEqual((resp.status, body), (200, b"PK\x03\x04fake-jar"))
                self.assertEqual(resp.getheader("Content-Type"), "application/java-archive")
            self.assertEqual(Upstream.hits["/maven2/" + rel], before + 1)
            cached = os.path.join(server.config.cache_dir, "central", *rel.split("/"))
            self.assertTrue(os.path.isfile(cached))
        finally:
            stop(server)

    def test_upstream_404_passed_through_and_not_cached(self):
        rel = "org/example/missing/1.0/missing-1.0.pom"
        for _ in range(2):
            resp, body = self.repo(rel)
            self.assertEqual(resp.status, 404)
            self.assertEqual(json.loads(body)["errors"][0]["status"], 404)
        self.assertEqual(Upstream.hits["/maven2/" + rel], 2)

    def test_head_supported(self):
        for rel, length in ((LIB + "1.4.0/acme-commons-http-1.4.0.pom", None),
                            ("junit/junit/4.13.2/junit-4.13.2.jar", len(b"PK\x03\x04fake-jar"))):
            resp, body = self.repo(rel, "HEAD")
            self.assertEqual((resp.status, body), (200, b""))
            self.assertGreater(int(resp.getheader("Content-Length")), 0)
            if length:
                self.assertEqual(int(resp.getheader("Content-Length")), length)

    def test_index_healthz_and_unknown_paths(self):
        resp, body = self.request("/")
        self.assertEqual(resp.status, 200)
        self.assertIn(b"<title>Mock Artifactory (demo simulation)</title>", body)
        self.assertEqual(self.request("/healthz")[0].status, 200)
        self.assertEqual(self.request("/other")[0].status, 404)
        self.assertEqual(self.repo("com/../etc/passwd")[0].status, 400)

    def test_gav_from_path(self):
        self.assertEqual(ma.gav_from_path(BLOCKED + "httpclient-4.5.12.jar"), "org.apache.httpcomponents:httpclient:4.5.12")
        self.assertEqual(ma.gav_from_path(BLOCKED), "org.apache.httpcomponents:httpclient:4.5.12")
        self.assertEqual(ma.gav_from_path("org/apache/httpcomponents/httpclient/maven-metadata.xml"),
                         "org.apache.httpcomponents:httpclient")


if __name__ == "__main__":
    unittest.main()
