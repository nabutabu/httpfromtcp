package main

import (
	"httpFromTcp/internal/request"
	"httpFromTcp/internal/response"
	"httpFromTcp/internal/server"
	"io"
	"log"
	"os"
	"os/signal"
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
	}

	writer.WriteStatusLine(200)
	writer.WriteHeaders(response.GetDefaultHeaders(len(SuccessHTML), "text/html"))
	writer.WriteBody([]byte(SuccessHTML))

	return
}
