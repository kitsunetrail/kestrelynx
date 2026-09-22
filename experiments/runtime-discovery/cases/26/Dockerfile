# case 26 (coverage-validation case): a Flask web application bundling
# about 28 pip distributions across three declared groups. Build context
# is cases/images/26-python-webapp (see cases/run.sh).
#
# curl, git and openssl back this case's operational OS-package activity.
# strace is installed unconditionally, alongside them, so the ground-truth
# tool's dedicated run (tools/truth-run.sh) uses this exact image rather
# than a rebuilt one; it is invoked only when the container is started
# with TRACE_MODE=1, which an ordinary measurement run never sets.
#
# A fixed local git repository and a fixed local file back the operational
# loop's git and openssl commands, so their inputs never depend on network
# access or on anything that changes between runs.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git openssl strace \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /requirements.txt
# Compiling to .pyc during install embeds each source file's own
# extraction-time mtime in the compiled file, which differs between
# otherwise identical builds and would make the image's own content
# non-reproducible for a reason that has nothing to do with the packages
# themselves; skipping it here leaves every import to compile from
# source at run time instead, the same as this case already does for
# every used_lazily package.
RUN pip install --no-cache-dir --no-compile -r /requirements.txt \
    && find /usr/local/lib/python3.12 -name '__pycache__' -type d -prune -exec rm -rf {} +
RUN mkdir -p /opt/fixture-repo \
    && cd /opt/fixture-repo \
    && git init -q \
    && git config user.email fixture@example.invalid \
    && git config user.name fixture \
    && echo "case26 fixture" > README.md \
    && git add README.md \
    && GIT_AUTHOR_DATE="2026-01-01T00:00:00Z" GIT_COMMITTER_DATE="2026-01-01T00:00:00Z" \
       git commit -q -m "fixture" \
    && printf 'kestrelynx-coverage-fixture-digest-input\n%.0s' $(seq 1 128) > digest-input.txt \
    && git add digest-input.txt \
    && GIT_AUTHOR_DATE="2026-01-01T00:00:01Z" GIT_COMMITTER_DATE="2026-01-01T00:00:01Z" \
       git commit -q -m "digest input"
COPY server.py /server.py
COPY os-ops.sh /os-ops.sh
COPY optime /usr/local/bin/optime
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /os-ops.sh /usr/local/bin/optime /entrypoint.sh
ENV CASE_ID=26
ENV HEALTH_URL=http://127.0.0.1:8000/health
ENTRYPOINT ["/entrypoint.sh"]
