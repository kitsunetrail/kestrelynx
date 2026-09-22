# case 27 (coverage-validation case): an Express web application whose
# package.json declares about 25 npm packages across three groups. Build
# context is cases/images/27-node-webapp (see cases/run.sh).
#
# The base image is Debian-based (node:22-bookworm-slim), not Alpine, so
# its OS package family matches the Debian-based Python and Java cases.
#
# curl, git and openssl back this case's operational OS-package activity.
# strace is installed unconditionally alongside them; see case 26's
# Dockerfile for why, and entrypoint.sh for how TRACE_MODE switches it on.
FROM node:22-bookworm-slim@sha256:83f487e0a63425e5b4d146fb5e5be574bcbe1b7b843d3ebafdd95eaf7767a7e5
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git openssl strace \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json /app/
# npm's own download/verification cache and debug log are build-time
# artifacts with fetch timestamps baked into them; removing them keeps
# the image's own content (rather than npm's bookkeeping about how it
# got there) reproducible across builds.
RUN npm ci --no-audit --no-fund \
    && rm -rf /root/.npm /tmp/node-compile-cache
COPY app.js /app/app.js
COPY os-ops.sh /os-ops.sh
COPY optime /usr/local/bin/optime
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /os-ops.sh /usr/local/bin/optime /entrypoint.sh \
    && mkdir -p /opt/fixture-repo \
    && cd /opt/fixture-repo \
    && git init -q \
    && git config user.email fixture@example.invalid \
    && git config user.name fixture \
    && echo "case27 fixture" > README.md \
    && git add README.md \
    && GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" GIT_COMMITTER_DATE="2026-01-01T00:00:00Z" \
       git commit -q -m "fixture" \
    && printf 'kestrelynx-coverage-fixture-digest-input\n%.0s' $(seq 1 128) > digest-input.txt \
    && git add digest-input.txt \
    && GIT_AUTHOR_DATE="2026-01-01T00:00:01Z" GIT_COMMITTER_DATE="2026-01-01T00:00:01Z" \
       git commit -q -m "digest input"
ENV CASE_ID=27
ENV HEALTH_URL=http://127.0.0.1:8080/health
ENTRYPOINT ["/entrypoint.sh"]
