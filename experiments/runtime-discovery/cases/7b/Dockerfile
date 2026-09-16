# case 7b: the same statically-linked server as case 7a, on
# gcr.io/distroless/static-debian12, which carries essentially no package
# database at all. Build context is cases/images/7-static-server (see
# cases/run.sh).
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /server .

FROM gcr.io/distroless/static-debian12
COPY --from=build /server /server
ENTRYPOINT ["/server"]
