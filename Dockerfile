# syntax=docker/dockerfile:1
# VulnWatch: dashboard + scanner in one image.
# Build context is the parent folder (it also needs ../vulnfeed). From vulnwatch/:  docker compose up -d --build

# --- Go toolchain + govulncheck (Go call-graph reachability, `go get` fixes) ---
FROM golang:1.27-bookworm AS gotools
RUN GOBIN=/out go install golang.org/x/vuln/cmd/govulncheck@v1.9.0

# --- Node.js + npm (lockfile-only npm fixes) ---
FROM node:22-bookworm-slim AS nodejs

# --- runtime ---
FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    HOST=0.0.0.0 PORT=8000 \
    PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local

# git, ripgrep and the GitHub CLI (from GitHub's own apt repository)
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ripgrep curl ca-certificates gnupg \
 && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
 && apt-get update && apt-get install -y --no-install-recommends gh \
 && apt-get purge -y gnupg && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
 # clones live on a mounted volume that may belong to another uid
 && git config --system safe.directory '*'

COPY --from=gotools /usr/local/go /usr/local/go
COPY --from=gotools /out/govulncheck /usr/local/bin/govulncheck
COPY --from=nodejs /usr/local/bin/node /usr/local/bin/node
COPY --from=nodejs /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm

RUN useradd --create-home --uid 10001 vulnwatch
WORKDIR /app
COPY vulnwatch/requirements.txt vulnwatch/requirements.txt
RUN pip install -r vulnwatch/requirements.txt
COPY vulnfeed/vulnfeed.py vulnfeed/feeds.json vulnfeed/
COPY vulnwatch/ vulnwatch/
RUN mkdir -p vulnwatch/data vulnwatch/db vulnwatch/secrets && chown -R vulnwatch:vulnwatch /app/vulnwatch/data /app/vulnwatch/db

USER vulnwatch
ENV HOME=/home/vulnwatch GOPATH=/home/vulnwatch/go npm_config_cache=/home/vulnwatch/.npm
WORKDIR /app/vulnwatch
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('PORT', '8000') + '/api/job', timeout=4)"
CMD ["python", "run.py"]
