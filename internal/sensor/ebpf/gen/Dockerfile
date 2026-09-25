# Build image for compiling the Sensor's BPF C sources into CO-RE objects.
# Pinned to a Debian release so the clang/llvm/libbpf-dev versions used to
# produce the committed .o files are reproducible; bump the tag deliberately
# when a newer toolchain is needed and re-run gen.sh for both target arches.
FROM debian:bookworm-20250908-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang llvm libbpf-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*
