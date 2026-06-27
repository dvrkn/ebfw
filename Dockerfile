# syntax=docker/dockerfile:1

# ── build stage: compile the BPF object + static Go binary ──────────────────
# trixie ships clang ~19 and libbpf >= 1.5 (modern BPF macros incl. BPF_UPROBE).
FROM golang:1.26-trixie AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libbpf-dev \
        linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum* ./
RUN go mod download

# Build.
COPY . .
RUN go generate ./...          # bpf2go: compile egress + sslsnoop BPF -> Go bindings
RUN go mod tidy
RUN CGO_ENABLED=0 go build -trimpath -o /out/ebfw .

# ── bin export: extract the static binary for host runs / e2e ───────────────
#   docker build --target bin --output type=local,dest=out .  -> out/ebfw
FROM scratch AS bin
COPY --from=build /out/ebfw /ebfw

# ── runtime image (default target): static binary, BPF object embedded ──────
FROM gcr.io/distroless/static-debian12 AS image
COPY --from=build /out/ebfw /usr/bin/ebfw
ENTRYPOINT ["/usr/bin/ebfw"]
