FROM golang:latest AS builder
COPY . /src

WORKDIR /src

RUN CGO_ENABLED=0 go build -ldflags="-extldflags=-static -s -w" -o csswaf

FROM alpine:latest

COPY --from=builder /src/csswaf /app/csswaf

RUN chmod +x /app/csswaf

CMD ["/app/csswaf"]