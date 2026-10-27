# The recon image: bounded discovery for one asset origin. Build from the repository root:
#   docker build -f sandbox/recon.Dockerfile -t argus-recon .
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install "httpx>=0.27,<1"
COPY sandbox/recon_runner.py /usr/local/bin/argus-recon-run
RUN chmod 0755 /usr/local/bin/argus-recon-run \
    && useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin recon \
    && mkdir -p /workspace && chown 65532:65532 /workspace

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/argus-recon-run"]
