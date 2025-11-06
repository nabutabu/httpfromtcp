package response

import (
	"httpFromTcp/internal/headers"
	"io"
	"strconv"
)

type StatusCode int

const (
	OK          StatusCode = 200
	ClientError StatusCode = 400
	ServerError StatusCode = 500

	RegisteredNurse string = "\r\n"
)

func WriteStatusLine(w io.Writer, statusCode StatusCode) error {
	var reasonPhrase string
	switch statusCode {
	case OK:
		reasonPhrase = "OK"
		break
	case ClientError:
		reasonPhrase = "Bad Request"
		break
	case ServerError:
		reasonPhrase = "Internal Server Error"
	}

	_, err := w.Write([]byte("HTTP/1.1 " + strconv.Itoa(int(statusCode)) + " " + reasonPhrase + RegisteredNurse))
	return err
}

func GetDefaultHeaders(contentLen int) headers.Headers {
	return headers.Headers{
		"Content-Length": strconv.Itoa(contentLen),
		"Connection":     "close",
		"Content-Type":   "text/plain",
	}
}

func WriteHeaders(w io.Writer, headers headers.Headers) error {
	var res string
	for k, v := range headers {
		res += k + ": "
		res += v + RegisteredNurse
	}

	res += RegisteredNurse // to mark that Body is next

	_, err := w.Write([]byte(res))
	return err
}
