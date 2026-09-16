# case 9: curl and git are installed at build time (part of this ImageID's own
# Trivy-scanned package set), then invoked briefly every 5 seconds. Build
# context is cases/images/9-short-lived (see cases/run.sh).
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY loop.sh /loop.sh
RUN chmod +x /loop.sh
CMD ["/loop.sh"]
