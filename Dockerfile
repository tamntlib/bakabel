# syntax=docker/dockerfile:1.7
FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" GOAMD64=v1 \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/bakabel ./cmd/bakabel && \
    mkdir -p /out/tmp /out/var/lib/bakabel

FROM restic/restic:0.18.1 AS restic

FROM scratch
COPY --from=build /out/bakabel /usr/local/bin/bakabel
COPY --from=restic /usr/bin/restic /usr/bin/restic
COPY --from=restic /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chmod=0700 /out/tmp /tmp
COPY --from=build --chmod=0700 /out/var/lib/bakabel /var/lib/bakabel
ENTRYPOINT ["/usr/local/bin/bakabel"]
CMD ["serve"]
