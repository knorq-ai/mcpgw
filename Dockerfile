FROM golang:1.25-alpine AS builder
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /mcpgw .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /mcpgw /mcpgw
ENTRYPOINT ["/mcpgw"]
