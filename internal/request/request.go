package request

import (
	"errors"
	"io"
	"log"
	"strings"
	"unicode"
)

type Request struct {
	RequestLine RequestLine
	state       int // 0 initialized, 1 done
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

func (r *Request) parse(data []byte) (int, error) {
	// for now this is first called when we have completely seen the request line
	reqLine, err := parseRequestLine(string(data))
	if err != nil {
		return 0, err
	}

	r.RequestLine = *reqLine
	r.state = 1

	return len(data), nil
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
		if request.state == 1 {
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
		// once we recieve a \r\n we know we have
		// received atleast one part of the request
		if strings.Contains(line, "\r\n") {
			// parse the string before \r\n
			parts := strings.Split(line, "\r\n")
			bytes, err := request.parse([]byte(parts[0]))
			if err != nil {
				return nil, err
			}

			// after parsing set line to the remainder of parts
			bytesParsed += bytes
			line = line[bytes:]
		}
	}

}
