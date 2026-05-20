package server

import (
	"bytes"
	"httpFromTcp/internal/request"
	"httpFromTcp/internal/response"
	"httpFromTcp/internal/tls13"
	"io"
	"log"
	"net"
	"strconv"
	"sync/atomic"
)

type HandlerError struct {
	StatusCode response.StatusCode
	Message    string
}

type Handler func(w io.Writer, req *request.Request)

type Server struct {
	Addr           string
	Listener       net.Listener
	Handler        Handler
	TLSConfig      *tls13.Config // nil = plain TCP, backward compatible
	IsServerClosed atomic.Bool
}

func Serve(port int, handler Handler) (*Server, error) {
	listener, err := net.Listen("tcp", "localhost:"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}

	server := Server{Addr: "localhost:" + strconv.Itoa(port), Listener: listener, Handler: handler}
	server.IsServerClosed.Store(false)

	go server.listen()

	return &server, nil
}

func (s *Server) Close() error {
	s.IsServerClosed.Store(true)
	return s.Listener.Close()
}

func (s *Server) listen() {
	for {
		// Wait for a connection.
		conn, err := s.Listener.Accept()
		if err != nil {
			if s.IsServerClosed.Load() {
				log.Println("Accept error after server shutdown. Gracefully breaking loop.")
				break
			}
			log.Fatal(err)
		}

		log.Println("Connection Accepted")

		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go s.handle(conn)
	}
}

func (h *HandlerError) WriteErrorToStream(w io.Writer) {
	response.WriteStatusLine(w, h.StatusCode)
	headers := response.GetDefaultHeaders(len(h.Message), "text/html")
	response.WriteHeaders(w, headers)

	w.Write([]byte(h.Message))
}

func (s *Server) handle(conn net.Conn) {
	log.Println("Handling connection")
	if s.TLSConfig != nil {
		tlsConn := tls13.NewServerConn(conn, s.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake failed: %v", err)
			conn.Close()
			return
		}
		conn = tlsConn
	}

	req, err := request.RequestFromReader(conn)
	if err != nil {
		hErr := &HandlerError{
			StatusCode: response.ServerError,
			Message:    err.Error(),
		}
		hErr.WriteErrorToStream(conn)
		return
	}

	var buf bytes.Buffer
	s.Handler(&buf, req)

	b := buf.Bytes()

	conn.Write(b)

	log.Println("Response sent. Closing Connection.")

	// Shut down the connection.
	defer conn.Close()
}
