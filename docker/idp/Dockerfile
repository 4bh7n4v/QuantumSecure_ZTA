# SDP standalone Identity Provider.
#
# Build context is the project root (ztna-sdp/), never this folder — the IDP
# imports the shared/ package:
#   docker build -f ./docker/idp/Dockerfile -t sdp-idp .
#
# The IDP is a separate component from the SDP Controller. It is the only
# service (besides the Gateway) the client contacts. It never calls the
# Controller or the Gateway.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app:/app/sdp-idp

WORKDIR /app

# Dependencies first, for layer caching.
COPY sdp-idp/requirements.txt ./sdp-idp/requirements.txt
RUN pip install --no-cache-dir -r sdp-idp/requirements.txt

# Application code: only what the IDP needs.
COPY shared/ ./shared/
COPY sdp-idp/ ./sdp-idp/

# Runtime state lives under the working dir (relative paths in settings:
# ./data/idp.db, ./certs/idp_jwt_*.pem) — mount volumes here to persist the
# SQLite DB and the RS256 signing key across restarts.
WORKDIR /app/sdp-idp
# Strip any host dev state that slipped into the build context (SQLite DB,
# dev signing key, local venv, bytecode). data/ and certs/ must be empty in
# the image so the first container start generates its own.
RUN rm -rf data certs .venv __pycache__ */__pycache__ */*/__pycache__ \
    && mkdir -p data certs \
    && useradd --system --uid 10001 --home /app idp \
    && chown -R idp:idp /app
USER idp

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9000/healthz').status==200 else 1)"]

CMD ["python", "main.py"]
