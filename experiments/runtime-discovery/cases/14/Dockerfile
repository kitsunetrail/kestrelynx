# case 14: a program that loads and unloads a shared library on a fixed cycle,
# so a sampling collector and an event collector can be compared on the
# same individually identified loads. Build context is
# cases/images/14-dlopen-loop (see cases/run.sh).
#
# Both stages are pinned by digest so the scan and the run describe the
# same bytes however the tags move.
FROM debian:12@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY dlopen_loop.c .
RUN mkdir -p /build \
    && gcc -O2 -o /build/dlopen_loop dlopen_loop.c -ldl

FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/dlopen_loop /dlopen_loop
ENV CASE_ID=14
ENTRYPOINT ["/dlopen_loop"]
