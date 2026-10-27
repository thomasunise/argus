# syntax=docker/dockerfile:1.7
# Offensive-tools worker image: layers pinned, SHA256-verified scanner binaries onto the
# Argus runtime image so Phase 2 coverage adapters (nmap_sv, ffuf_dir, nuclei, gitleaks,
# trufflehog_verify, trivy) execute with real CLI tools inside the worker container.
#
# Build from the repository root:
#   docker build -t argus:local .
#   docker build -f sandbox/offensive-tools.Dockerfile -t argus-worker-tools:local .

ARG BASE_IMAGE=argus:local

FROM debian:bookworm-slim AS tools-fetch
SHELL ["/bin/bash", "-euo pipefail", "-c"]
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl tar unzip \
 && rm -rf /var/lib/apt/lists/*

# Pinned versions and linux/amd64 archive SHA-256 digests.
ARG NUCLEI_VERSION=3.3.5
ARG NUCLEI_SHA256=5e88ae9e24ce74dd0f2ee52736d7c4996e4ac801a28a0f1244abec285e7f881d
ARG FFUF_VERSION=2.1.0
ARG FFUF_SHA256=6cab3bbd0acbe2f7eb3c9f52b3ef0f54608982f84f7f563d8d912f7e8a9c46ef
ARG GITLEAKS_VERSION=8.21.2
ARG GITLEAKS_SHA256=7cabef46cdcb8af7d989d6b34d55efad8a9d6a00e1cf1be2c4a82a3dfac8fc52
ARG TRUFFLEHOG_VERSION=3.83.7
ARG TRUFFLEHOG_SHA256=1e953c5267a99923d4bf7bc1ef57d42989e8923a830ab278db3e4909356e1053
ARG TRIVY_VERSION=0.56.2
ARG TRIVY_SHA256=fd52ba6dc6a2dd5ca6ee08dc4d6fd44de69571e63f6f9660be2c1de5b95bd255

WORKDIR /tmp/tools
RUN mkdir -p /out/bin \
 && curl -fsSL -o nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
 && echo "${NUCLEI_SHA256}  nuclei.zip" | sha256sum -c - \
 && unzip -q nuclei.zip nuclei -d /out/bin \
 && curl -fsSL -o ffuf.tar.gz "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
 && echo "${FFUF_SHA256}  ffuf.tar.gz" | sha256sum -c - \
 && tar -xzf ffuf.tar.gz -C /out/bin ffuf \
 && curl -fsSL -o gitleaks.tar.gz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
 && echo "${GITLEAKS_SHA256}  gitleaks.tar.gz" | sha256sum -c - \
 && tar -xzf gitleaks.tar.gz -C /out/bin gitleaks \
 && curl -fsSL -o trufflehog.tar.gz "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
 && echo "${TRUFFLEHOG_SHA256}  trufflehog.tar.gz" | sha256sum -c - \
 && tar -xzf trufflehog.tar.gz -C /out/bin trufflehog \
 && curl -fsSL -o trivy.tar.gz "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
 && echo "${TRIVY_SHA256}  trivy.tar.gz" | sha256sum -c - \
 && tar -xzf trivy.tar.gz -C /out/bin trivy \
 && chmod 0755 /out/bin/*

FROM ${BASE_IMAGE}
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*
COPY --from=tools-fetch /out/bin/ /usr/local/bin/
USER 10001:10001
HEALTHCHECK NONE
CMD ["worker"]
