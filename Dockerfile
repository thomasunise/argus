FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && groupadd -r sentinel && useradd -r -g sentinel sentinel
COPY app ./app
RUN mkdir -p /app/data /app/targets && chown -R sentinel:sentinel /app/data /app/targets
USER sentinel
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--no-server-header"]
