# case 7a: debian:12-slim with an intact dpkg database, running only a
# statically-linked server that never touches any of the base image's
# shared libraries. Build context is cases/images/7-static-server (see
# cases/run.sh). Paired with case 7b (same binary, distroless/static-debian12
# base) to separate "database resolution works but nothing is confirmed"
# from "there is effectively no database to resolve against".
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /server .

FROM debian:12-slim
COPY --from=build /server /server
ENTRYPOINT ["/server"]
