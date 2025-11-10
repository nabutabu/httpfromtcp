package main

import (
	"crypto/sha256"
	"httpFromTcp/internal/request"
	"httpFromTcp/internal/response"
	"httpFromTcp/internal/server"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const (
	port = 42069

	BadRequestHTML = `<html>
  <head>
    <title>400 Bad Request</title>
  </head>
  <body>
    <h1>Bad Request</h1>
    <p>Your request honestly kinda sucked.</p>
  </body>
</html>`

	ServerErrorHTML = `<html>
  <head>
    <title>500 Internal Server Error</title>
  </head>
  <body>
    <h1>Internal Server Error</h1>
    <p>Okay, you know what? This one is on me.</p>
  </body>
</html>`

	SuccessHTML = `<html>
  <head>
    <title>200 OK</title>
  </head>
  <body>
    <h1>Success!</h1>
    <p>Your request was an absolute banger.</p>
  </body>
</html>`

	HTTPBIN    = `https://httpbin.org`
	CHUNK_SIZE = 1024
)

func main() {
	server, err := server.Serve(port, handler)
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
	defer server.Close()
	log.Println("Server started on port", port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Server gracefully stopped")
}

func handler(w io.Writer, req *request.Request) {
	// init a writer that now calls the writing functions
	writer := response.Writer{
		W:           w,
		WriterState: 0,
	}

	if req.RequestLine.RequestTarget == "/yourProblem" {
		writer.WriteStatusLine(400)
		writer.WriteHeaders(response.GetDefaultHeaders(len(BadRequestHTML), "text/html"))
		writer.WriteBody([]byte(BadRequestHTML))

		return
	} else if req.RequestLine.RequestTarget == "/myProblem" {
		writer.WriteStatusLine(500)
		writer.WriteHeaders(response.GetDefaultHeaders(len(ServerErrorHTML), "text/html"))
		writer.WriteBody([]byte(ServerErrorHTML))

		return
	} else if strings.HasPrefix(req.RequestLine.RequestTarget, "/httpbin") {
		writer.WriteStatusLine(200)
		// get then change headers
		headers := response.GetDefaultHeaders(len(SuccessHTML), "text/html")
		delete(headers, "Content-Length")
		headers["Transfer-Encoding"] = "chunked"
		writer.WriteHeaders(headers)

		response, err := http.Get(HTTPBIN + strings.TrimPrefix(req.RequestLine.RequestTarget, "/httpbin"))
		if err != nil || response == nil {
			log.Fatal(err)
		}

		buf := make([]byte, CHUNK_SIZE)
		var totalBody []byte
		for {
			n, err := response.Body.Read(buf)
			if err != nil {
				if err == io.EOF {
					log.Println("EOF Reached")
				} else {
					log.Fatal("Error reading resopnse from httpbin.org")
				}
				break
			}

			log.Printf("Writing %d bytes", n)

			totalBody = append(totalBody, buf[:n]...)
			_, err = writer.WriteChunkedBody(buf[:n])
			if err != nil {
				log.Fatal(err)
			}
		}

		_, err = writer.WriteChunkedBodyDone()
		if err != nil {
			log.Fatal(err)
		}

		trailers := make(map[string]string)
		checkSumStr := sha256.Sum256(totalBody)
		trailers["X-Content-SHA256"] = string(checkSumStr[:])
		trailers["X-Content-Length"] = string(len(totalBody))

		return
	} else if req.RequestLine.RequestTarget == "/video" {
		writer.WriteStatusLine(200)
		writer.WriteHeaders(response.GetDefaultHeaders(len(SuccessHTML), "video/mp4"))
		file, err := os.ReadFile("./assets/vim.mp4")
		if err != nil {
			log.Fatal(err)
		}
		writer.WriteBody(file)

		return
	}

	writer.WriteStatusLine(200)
	writer.WriteHeaders(response.GetDefaultHeaders(len(SuccessHTML), "text/html"))
	writer.WriteBody([]byte(SuccessHTML))

	return
}
