# The sandbox executor control API. Build from the repository root:
#   docker build -f sandbox/executor.Dockerfile -t argus-sandbox-executor .
FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install "fastapi>=0.115,<1" "uvicorn[standard]>=0.30,<1" "kubernetes>=29,<35" "pydantic>=2.5,<3"

WORKDIR /app
COPY app/exploit/executor /app/executor
USER 65532:65532
EXPOSE 8080
CMD ["uvicorn", "executor.server:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
