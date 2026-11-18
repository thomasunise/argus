# The PoC runtime image. Runs one generated script inside the Job the executor creates.
# Build from the repository root:  docker build -f sandbox/Dockerfile -t argus-sandbox .
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install "httpx>=0.27,<1"
COPY sandbox/poc_runner.py /usr/local/bin/argus-poc-run
RUN chmod 0755 /usr/local/bin/argus-poc-run \
    && useradd --uid 65532 --no-create-home --shell /usr/sbin/nologin sandbox

USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/argus-poc-run"]
