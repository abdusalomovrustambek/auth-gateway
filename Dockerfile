FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth-gateway ./cmd/auth-gateway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/auth-gateway /usr/local/bin/auth-gateway
WORKDIR /app
USER nonroot:nonroot
ENV ASSETS_DIR=.
EXPOSE 8080
ENTRYPOINT ["auth-gateway"]
