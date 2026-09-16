# case 22: a statically linked binary carrying a module with known reported
# vulnerabilities, placed on an ordinary base image. Build context is
# cases/images/22-static-go (see cases/run.sh).
#
# The binary links nothing at run time, so nothing about it appears in a
# process's mapped files beyond the binary itself. What identifies it is
# its own path, which is what a scan report names for a compiled binary —
# and the packages the report hangs off that path are every module built
# into it, which is why executing it confirms the file and nothing finer.
#
# Both stages are pinned by digest, and the toolchain is pinned by the
# build image, so the same source produces the same binary. The module's
# version is pinned in the build context's own module file, and the case
# definition records why that version was chosen.
FROM golang:1.26@sha256:3c3e25a4da13fd0478eed2df1eb35a0e667094a7124d3993a6a1d30f71c17e79 AS build
WORKDIR /src
COPY go.mod go.sum main.go ./
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN go build -trimpath -o /server .

FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
COPY --from=build /server /server
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV CASE_ID=22
ENTRYPOINT ["/entrypoint.sh"]
