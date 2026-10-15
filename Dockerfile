FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/aaron-cog-gtm-gh-org/acme-mock-artifactory" \
      org.opencontainers.image.title="Mock Artifactory (demo simulation)" \
      org.opencontainers.image.description="Maven virtual-repo proxy that simulates Artifactory/Xray download blocking"

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /home/artifactory artifactory \
 && mkdir -p /var/cache/mock-artifactory \
 && chown artifactory:artifactory /var/cache/mock-artifactory

ENV CACHE_DIR=/var/cache/mock-artifactory \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY mock_artifactory.py /app/mock_artifactory.py

USER artifactory
EXPOSE 8081

# Short interval: GitHub Actions waits for service containers to be healthy before running steps.
HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=15 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz', timeout=2)"]

CMD ["python", "/app/mock_artifactory.py"]
