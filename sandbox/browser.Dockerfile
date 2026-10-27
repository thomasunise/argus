# Browser discovery image: headless Chromium + the request-capturing runner.
# Build from the repository root:  docker build -f sandbox/browser.Dockerfile -t argus-browser .
# Expect ~1.2 GB: Chromium and its libraries are not small.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN pip install "playwright>=1.45,<2" \
    && playwright install --with-deps chromium \
    && useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin browser \
    && mkdir -p /workspace && chown 65532:65532 /workspace

COPY sandbox/browser_runner.py /usr/local/bin/argus-browser-run
RUN chmod 0755 /usr/local/bin/argus-browser-run

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/argus-browser-run"]
