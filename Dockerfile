# syntax=docker/dockerfile:1

# ── build stage: compile the BPF object + static Go binary ──────────────────
FROM golang:1.26-bookworm AS build

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
RUN go generate ./...          # bpf2go: clang compiles bpf/egress.bpf.c -> bpf_bpfel.{go,o}
RUN go mod tidy
RUN CGO_ENABLED=0 go build -trimpath -o /out/ebfw .

# ── runtime stage: just the static binary (BPF object is embedded) ──────────
FROM gcr.io/distroless/static-debian12

COPY --from=build /out/ebfw /usr/bin/ebfw
ENTRYPOINT ["/usr/bin/ebfw"]
