# R8: three processes exercising the three ways a mapped file can stop
# matching what's on disk: an unlinked executable, an unlinked shared
# library, and a shared library overwritten in place after being loaded.
# Build context is cases/images/r8-delete-replace (see cases/run.sh).
FROM debian:12-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY loader.c sleeper.c ./
RUN mkdir -p /build \
    && gcc -O2 -o /build/loader loader.c -ldl \
    && gcc -O2 -o /build/server-a-src sleeper.c

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/loader /opt/bin/loader
COPY --from=build /build/server-a-src /opt/bin/server-a-src
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
CMD ["/entrypoint.sh"]
