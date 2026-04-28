FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl wget git gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Go 1.22 and ProjectDiscovery tools (nuclei + httpx)
ARG TARGETARCH
RUN wget -qO- https://go.dev/dl/go1.22.5.linux-${TARGETARCH}.tar.gz | tar -C /usr/local -xzf - && \
    export PATH=$PATH:/usr/local/go/bin:/root/go/bin && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}"

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

RUN useradd -m -r appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
