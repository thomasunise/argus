# The offensive engine image: Strix plus the wrapper that normalizes its report.
# Build from the repository root:  docker build -f sandbox/strix.Dockerfile -t argus-strix .
#
# The pod the executor creates is the sandbox (gVisor, read-only root, pinned egress). Strix's own
# nested Docker sandbox is not available inside it; set ARGUS_STRIX_EXTRA_ARGS if your Strix
# version needs flags for single-container operation.
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install "strix-agent>=0.6,<1"
COPY sandbox/strix_runner.py /usr/local/bin/argus-strix-run
RUN chmod 0755 /usr/local/bin/argus-strix-run \
    && useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin strix \
    && mkdir -p /workspace && chown 65532:65532 /workspace

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/argus-strix-run"]
