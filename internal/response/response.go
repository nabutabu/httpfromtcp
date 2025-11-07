package response

import (
	"errors"
	"httpFromTcp/internal/headers"
	"io"
	"strconv"
)

type StatusCode int

const (
	OK          StatusCode = 200
	ClientError StatusCode = 400
	ServerError StatusCode = 500

	WriterStateInitialized = 0
	WriterStateStatusDone  = 1
	WriterStateHeadersDone = 2
	WriterStateBodyDone    = 3

	RegisteredNurse string = "\r\n"
)

type Writer struct {
	W           io.Writer
	WriterState int
}

func (writer *Writer) WriteStatusLine(statusCode StatusCode) error {
	if writer.WriterState != WriterStateInitialized {
		return errors.New("Invalid writer state")
	}
	writer.WriterState = WriterStateStatusDone
	return WriteStatusLine(writer.W, statusCode)
}

func (writer *Writer) WriteHeaders(headers headers.Headers) error {
	if writer.WriterState != WriterStateStatusDone {
		return errors.New("Invalid writer state")
	}
	writer.WriterState = WriterStateHeadersDone
	return WriteHeaders(writer.W, headers)
}

func (writer *Writer) WriteBody(p []byte) (int, error) {
	if writer.WriterState != WriterStateHeadersDone {
		return 0, errors.New("Invalid writer state")
	}
	writer.WriterState = WriterStateBodyDone
	return writer.W.Write(p)
}

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

func GetDefaultHeaders(contentLen int, contentType string) headers.Headers {
	return headers.Headers{
		"Content-Length": strconv.Itoa(contentLen),
		"Connection":     "close",
		"Content-Type":   contentType,
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
