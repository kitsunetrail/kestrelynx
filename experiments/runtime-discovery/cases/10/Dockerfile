# case 10: a C program that explicitly dlopen()s and dlclose()s libsqlite3 on
# a 7-second-loaded / 7-second-unloaded cycle. Build context is
# cases/images/10-dlopen-loop (see cases/run.sh).
FROM debian:12 AS build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY dlopen_loop.c .
RUN mkdir -p /build \
    && gcc -O2 -o /build/dlopen_loop dlopen_loop.c -ldl

FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/dlopen_loop /dlopen_loop
ENTRYPOINT ["/dlopen_loop"]
