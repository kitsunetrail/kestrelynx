# R6: a dynamically-linked C server on gcr.io/distroless/cc-debian12, whose
# status.d/*.md5sums metadata is the only way to resolve a path to a
# package on this base (there is no dpkg .list/*.info directory at all).
# Build context is cases/images/r6-dynamic-server (see cases/run.sh).
# The build stage uses debian:12 (not -slim) rather than
# gcr.io/distroless/cc-debian12's own base, so the produced binary links
# glibc at the same ABI version the final stage's distroless base ships.
FROM debian:12 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY server.c .
RUN mkdir -p /build \
    && gcc -O2 -o /build/server server.c

FROM gcr.io/distroless/cc-debian12
COPY --from=build /build/server /server
ENTRYPOINT ["/server"]
