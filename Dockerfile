FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY sanitized_db_mcp/ sanitized_db_mcp/

RUN pip install --no-cache-dir .

FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY sanitized_db_mcp/ sanitized_db_mcp/

ENTRYPOINT ["python", "-m", "sanitized_db_mcp.server"]
