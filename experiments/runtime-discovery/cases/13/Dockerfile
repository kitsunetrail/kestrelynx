# case 13: curl and git are installed at build time, so they are part of this
# image's own scanned package set, and are then run briefly every five
# seconds — but only after the observation says it is ready. Build context
# is cases/images/13-short-lived (see cases/run.sh).
#
# The base image is pinned by digest so the scan and the run describe the
# same bytes however the tag moves.
FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY loop.sh /loop.sh
RUN chmod +x /loop.sh
ENV CASE_ID=13
ENTRYPOINT ["/loop.sh"]
