# Clarix backend image — supports both the web API (default) and the CLI.
#
# Run modes:
#   docker run --rm -p 8000:8000 clarix                  # web API on :8000
#   docker run --rm clarix scan /src --format sarif      # one-shot CLI scan
#   docker run --rm -v $(pwd):/src clarix scan /src     # scan a local repo
#
# Image layers (in order, cached independently for fast rebuilds):
#   1. System deps (git, tini)
#   2. Python deps from pyproject.toml
#   3. Application source (app/, clarix_cli/, entrypoint.sh)

FROM python:3.12-slim AS deps

# System packages we need: git for any future git-based installs, tini for
# proper signal handling in containers.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so this layer caches independently of source changes.
COPY pyproject.toml ./
COPY app/ ./app/
COPY clarix_cli/ ./clarix_cli/
RUN pip install --no-cache-dir .

# ---- runtime stage (kept as a single stage here; Clarix image is small) -----
FROM python:3.12-slim

# Same system packages as the builder.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r clarix && useradd -r -g clarix clarix

WORKDIR /app

# Copy installed Python packages and the application source.
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin
COPY --from=deps /app/app/ ./app/
COPY --from=deps /app/clarix_cli/ ./clarix_cli/
COPY entrypoint.sh /usr/local/bin/clarix-docker
RUN chmod +x /usr/local/bin/clarix-docker

USER clarix

ENV PORT=8000
EXPOSE 8000

# tini reaps zombies and forwards signals — important for clean shutdown.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/clarix-docker"]
CMD ["serve"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/health', timeout=2).status == 200 else 1)" \
    || exit 1
