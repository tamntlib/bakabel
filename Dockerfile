# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM --platform=$BUILDPLATFORM golang:1.26.8-bookworm@sha256:dc9ad6c05acc7a88e5b71bde60a5fe3bd4b9f0db209011711b464107438a8107 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOAMD64=v1 \
    go build -trimpath -ldflags='-s -w' -o /out/bakabel ./cmd/bakabel && \
    mkdir -p /out/tmp

FROM restic/restic:0.18.1@sha256:39d9072fb5651c80d75c7a811612eb60b4c06b32ffe87c2e9f3c7222e1797e76 AS restic

FROM scratch
COPY --from=build /out/bakabel /usr/local/bin/bakabel
COPY --from=restic /usr/bin/restic /usr/bin/restic
COPY --from=restic /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
# Runtime UID 0 is required for the supported private Docker/state mounts.
COPY --from=build --chmod=0700 /out/tmp /tmp
ENTRYPOINT ["/usr/local/bin/bakabel"]
