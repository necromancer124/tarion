# tariond, the Tarion directory server.
#
#   docker build -t tariond .
#   docker run -d --name tariond -p 63425:63425/udp -v tariond-data:/data tariond
#   docker exec tariond /tariond invite      # operator commands use the same /data
#
# Run it on a Linux host. Docker Desktop (Windows/macOS) rewrites client
# source addresses, so the server would hand out wrong addresses and hole
# punching would fail. See server/README.md.

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tariond ./server \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tariond /tariond
# The volume starts out owned by the non-root user, so the key and
# account files can be created on first start.
COPY --from=build --chown=65532:65532 /out/data /data
ENV TARIOND_DATA=/data
VOLUME /data
EXPOSE 63425/udp
USER 65532:65532
ENTRYPOINT ["/tariond"]
