# case 15: a Python interpreter that imports a package carrying a compiled
# extension, on a signal rather than at startup, and records each import
# individually. Build context is cases/images/15-python-import (see
# cases/run.sh).
#
# The compiled-module cache is the case's second condition. Building with
# it and running without it are different things: PYTHONDONTWRITEBYTECODE
# only stops new cache files being written, so the cache produced during
# installation is removed outright for the no-cache variant. Which files an
# import reads differs between the two, which is the point.
#
# The base image is pinned by digest so the scan and the run describe the
# same bytes however the tag moves. The dependency's version is pinned for
# the same reason, and is chosen in the case definition, which records why.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
ARG CRYPTOGRAPHY_VERSION=41.0.0
ARG PYC_CACHE=1
RUN pip install --no-cache-dir "cryptography==${CRYPTOGRAPHY_VERSION}"
RUN if [ "$PYC_CACHE" = "0" ]; then \
      find /usr/local/lib/python3.12 -name '__pycache__' -type d -prune -exec rm -rf {} + ; \
    fi
COPY server.py /server.py
ENV CASE_ID=15
# The no-cache variant is also started with PYTHONDONTWRITEBYTECODE set, so
# the cache it was built without is not written back on the first import.
# That is a run-time setting rather than a build-time one, and cases/run.sh
# passes it.
ENTRYPOINT ["python", "-u", "/server.py"]
