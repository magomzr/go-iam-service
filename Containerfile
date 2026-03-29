FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o iam-server ./cmd/server

FROM alpine:3.21

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/iam-server .
COPY --from=builder /app/db/migrations ./db/migrations

EXPOSE 8080

USER nobody

ENTRYPOINT ["./iam-server"]
