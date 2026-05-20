# httpfromtcp

An HTTP/1.1 server built from scratch on top of raw TCP sockets — no `net/http`. Includes a from-scratch TLS 1.3 implementation (in progress).

End-to-end working: a client can connect, send an HTTP request over TCP (or TLS), and receive a correct HTTP response.

## Features

- Manual HTTP request parsing (request line, headers with validation, body via Content-Length)
- Stateful response writer enforcing correct write order (status → headers → body)
- Chunked transfer encoding with custom trailers
- Reverse proxy: `GET /httpbin/*` → https://httpbin.org
- Static file serving: `GET /video` serves an MP4 from `assets/`
- Concurrent connections, graceful shutdown
- TLS 1.3 record layer, handshake framing, and ClientHello parser (RFC 8446)

## Build & Run

```bash
go build ./cmd/httpserver/       # Build HTTP server
go run ./cmd/httpserver/         # Start on port 42069
go test ./...                    # Run all tests
```

## TLS Setup

Generate a self-signed certificate for local development:

```bash
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

The server loads `server.crt` and `server.key` from the project root when TLS mode is enabled.

## Testing

```bash
# Plain HTTP
curl http://localhost:42069/

# HTTPS with TLS (skip cert verification for self-signed)
curl -k https://localhost:42069/

# Stream video
curl http://localhost:42069/video -o /dev/null

# Proxy to httpbin
curl http://localhost:42069/httpbin/anything
```

### Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Returns a text response |
| `GET /httpbin/*` | Proxies to httpbin.org |
| `GET /video` | Streams `assets/vim.mp4` |

## Project Structure

| Directory | Purpose |
|---|---|
| `cmd/httpserver/` | HTTP server entry point |
| `cmd/tcplistener/` | Debug TCP listener |
| `internal/server/` | Server core (accept loop, graceful shutdown) |
| `internal/request/` | HTTP request parser (state machine) |
| `internal/response/` | HTTP response writer (state machine) |
| `internal/headers/` | HTTP header parser |
| `internal/tls13/` | TLS 1.3 from scratch (WIP) |
| `docs/` | Implementation plans |

## Dependencies

Zero runtime dependencies — only the Go standard library. Test dependencies via testify.
