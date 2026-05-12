FROM golang:1.24-alpine AS builder

RUN apk add --no-cache ca-certificates git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /vault-unsealer-tpm ./cmd/unseal

FROM scratch

COPY --from=builder /vault-unsealer-tpm /vault-unsealer-tpm
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

VOLUME /keys

ENTRYPOINT ["/vault-unsealer-tpm"]
