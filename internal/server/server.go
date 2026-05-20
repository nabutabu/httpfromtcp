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
	TLSConfig      *tls13.Config
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

func (s *Server) Start() {
    s.IsServerClosed.Store(false)
    go s.listen()
}

func (s *Server) listen() {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			if s.IsServerClosed.Load() {
				log.Println("Accept error after server shutdown. Gracefully breaking loop.")
				break
			}
			log.Fatal(err)
		}

		log.Println("Connection Accepted")
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
	defer conn.Close()

	var rw io.ReadWriter = conn

	if s.TLSConfig != nil {
		tlsConn := tls13.NewServerConn(conn, s.TLSConfig)
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake failed: %v", err)
			return
		}
		rw = tlsConn
	}

	req, err := request.RequestFromReader(rw)
	if err != nil {
		hErr := &HandlerError{
			StatusCode: response.ServerError,
			Message:    err.Error(),
		}
		hErr.WriteErrorToStream(rw)
		return
	}

	var buf bytes.Buffer
	s.Handler(&buf, req)
	rw.Write(buf.Bytes())

	log.Println("Response sent. Closing Connection.")
}