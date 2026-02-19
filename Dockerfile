FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml .
COPY src/ src/

RUN pip install --no-cache-dir build && \
    python -m build --wheel --outdir /build/dist

FROM python:3.12-slim

LABEL maintainer="Security Team <security@example.com>"
LABEL description="Security Scanner — cross-origin web attack vulnerability detection"

RUN groupadd -r scanner && useradd -r -g scanner scanner

WORKDIR /app

COPY --from=builder /build/dist/*.whl /tmp/

RUN pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

RUN mkdir -p /app/data /app/logs /app/reports && \
    chown -R scanner:scanner /app

USER scanner

EXPOSE 8000

ENV DATABASE_PATH=/app/data/security_scanner.db \
    LOG_FILE=/app/logs/security_scanner.log \
    REPORT_OUTPUT_DIR=/app/reports

ENTRYPOINT ["security-scanner"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
