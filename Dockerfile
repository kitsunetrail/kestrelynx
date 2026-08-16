# Build the static kestrelynx binary.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# -tags timetzdata embeds the IANA timezone database in the binary so daily_at is
# interpreted in TZ (e.g. Asia/Tokyo) even on base images without tzdata.
RUN CGO_ENABLED=0 go build -trimpath -tags timetzdata -ldflags="-s -w" -o /out/kestrelynx ./cmd/kestrelynx

# Final image is the official Trivy image (Trivy + its DB tooling already on PATH),
# so KestreLynx shells out to a pinned trivy version (ADR-002).
FROM aquasec/trivy:0.71.2
COPY --from=build /out/kestrelynx /usr/local/bin/kestrelynx
# The base image's entrypoint is trivy; run kestrelynx instead.
ENTRYPOINT ["kestrelynx"]
CMD ["--config", "/etc/kestrelynx/config.yml"]
