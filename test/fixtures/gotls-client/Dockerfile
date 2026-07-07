# syntax=docker/dockerfile:1
#
# Builds the e2e Go crypto/tls test client. Kept as a fixture (not inlined in
# test/e2e.sh) so it compiles like any Go program and so the host needs no Go
# toolchain — only Docker, which CI and the dev box already have.
#
#   docker build --target bin --output type=local,dest=out test/fixtures/gotls-client
#     -> out/gotls-client
#
# Default `go build` keeps the symbol table (no -s/-w), so ebfw's
# crypto/tls.(*Conn).Write uprobe can resolve the symbol and attach.
FROM golang:1.26-trixie AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/gotls-client .

# Export just the static binary for host runs / e2e.
FROM scratch AS bin
COPY --from=build /out/gotls-client /gotls-client
