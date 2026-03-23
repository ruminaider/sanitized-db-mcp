FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip

COPY pyproject.toml README.md ./
COPY sanitized_db_mcp/ sanitized_db_mcp/

RUN pip install --no-cache-dir '.[sse]'

FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY sanitized_db_mcp/ sanitized_db_mcp/

EXPOSE 8000

ENTRYPOINT ["python", "-m", "sanitized_db_mcp.server"]
