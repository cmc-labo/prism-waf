# Container image of PrismWAF, e.g. to run it as a sidecar in front of an
# application in the same pod. See docs/deployment.md.
#
#   docker build -t prismwaf .
#   docker run --rm -p 8080:8080 -e PRISMWAF_BACKEND=http://app:3000 prismwaf

FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /prismwaf ./cmd/prismwaf

# No shell or package manager; runs as an unprivileged user (UID 65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /prismwaf /prismwaf
# Every flag can be set with a PRISMWAF_ variable; the probes listen on
# their own port for the orchestrator.
ENV PRISMWAF_PROBE_LISTEN=:9090
EXPOSE 8080 9090
# For Docker and Compose; Kubernetes uses the probes in the pod spec.
HEALTHCHECK --interval=10s --timeout=6s CMD ["/prismwaf", "healthcheck"]
ENTRYPOINT ["/prismwaf"]
