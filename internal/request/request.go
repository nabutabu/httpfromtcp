package request

import (
	"errors"
	"httpFromTcp/internal/headers"
	"io"
	"log"
	"strconv"
	"strings"
	"unicode"
)

const (
	Initialized                int = 0
	RequestStateParsingHeaders int = 1
	RequestLineDone            int = 2
	RequestStateParsingBody    int = 3
	RequestStateDone           int = 4

	LengthOfRN = 2
)

type Request struct {
	RequestLine RequestLine
	Headers     headers.Headers
	Body        []byte
	state       int
}

type RequestLine struct {
	HttpVersion   string
	RequestTarget string
	Method        string
}

func IsAllCaps(s string) bool {
	if s == "" {
		return false // Or return true if an empty string should be considered valid.
	}
	for _, r := range s {
		if !unicode.IsUpper(r) {
			return false
		}
	}
	return true
}

func parseRequestLine(start_line string) (*RequestLine, error) {
	start_line_parts := strings.Split(start_line, " ")
	if len(start_line_parts) != 3 {
		return nil, errors.New("Not a valid request-line")
	}

	// verify that Method only contains alpha
	Method := start_line_parts[0]
	if !IsAllCaps(Method) {
		return nil, errors.New("Method is not only Alpha")
	}

	// verify that HTTP version is 1.1
	version := start_line_parts[2]
	HttpVersion := strings.Split(version, "/")[1]
	if HttpVersion != "1.1" {
		return nil, errors.New("Version incompatible")
	}

	RequestTarget := start_line_parts[1]

	return &RequestLine{HttpVersion, RequestTarget, Method}, nil
}

func (r *Request) parseSingle(data []byte) (int, error) {
	// based on current state of request, handle next step
	switch r.state {

	case Initialized:
		// for now this is first called when we have completely seen the request line
		parts := strings.Split(string(data), "\r\n")
		reqLine, err := parseRequestLine(parts[0])
		if err != nil {
			return 0, err
		}

		r.RequestLine = *reqLine
		r.state = RequestLineDone

		return strings.Index(string(data), "\r\n") + LengthOfRN, nil

	case RequestLineDone, RequestStateParsingHeaders:
		// set state to processing
		r.state = RequestStateParsingHeaders

		if r.Headers == nil {
			r.Headers = headers.NewHeaders()
		}

		// get one header at a time and add to request
		n, done, err := r.Headers.Parse(data)
		if err != nil {
			return 0, nil
		}

		if done {
			r.state = RequestStateParsingBody
		}

		return n, nil

	case RequestStateParsingBody:
		r.state = RequestStateParsingBody

		contentLength := r.Headers.Get("content-length")

		if contentLength == "" {
			if len(data) > 0 {
				return 0, errors.New("Invalid Body: Content-Length not specified in Headers")
			}
			r.state = RequestStateDone
			return 0, nil
		}

		// got some amount of content to parse
		size, err := strconv.Atoi(contentLength)
		if err != nil {
			return 0, err
		}

		r.Body = append(r.Body, data...)

		if len(r.Body) > size {
			return 0, errors.New("Invalid Body: Too many characters")
		}

		if len(r.Body) == size {
			r.state = RequestStateDone
			return len(data), nil
		}

		return len(data), nil
	}

	return 0, nil
}

func (r *Request) parse(data []byte) (int, error) {
	// called when any data is recieved
	// need to check if we have atleast one line but only if we are not parsing the body currently
	if !strings.Contains(string(data), "\r\n") && r.state != RequestStateParsingBody {
		// does not even have one line
		return 0, nil
	}

	// because our current chunk can have multiple parts of the request
	// (both request line and headers for ex)
	// run the loop until either the entire request is parsed or all bytes are consumed
	bytesParsed := 0
	for r.state != RequestStateDone {
		n, err := r.parseSingle(data[bytesParsed:])
		if err != nil {
			return bytesParsed, err
		}

		if n == 0 {
			return bytesParsed, nil
		}

		bytesParsed += n
	}

	return bytesParsed, nil
}

func RequestFromReader(reader io.Reader) (*Request, error) {
	log.Println("/RequestFromReader")
	//req_str, err := io.ReadAll(reader)

	buf := make([]byte, 8)
	var request Request
	var line string
	var bytesRead int
	var bytesParsed int

	for {
		if request.state == RequestStateDone {
			return &request, nil
		}

		// if there is a request in flight read more bytes
		n, err := reader.Read(buf)
		if err != nil {
			return nil, errors.New("Error reading data")
		}

		line += string(buf[:n])
		bytesRead += n

		// received some amount of text
		bytes, err := request.parse([]byte(line))
		if err != nil {
			return nil, err
		}

		// after parsing set line to the remainder of parts
		bytesParsed += bytes
		line = line[bytes:]
	}

}
