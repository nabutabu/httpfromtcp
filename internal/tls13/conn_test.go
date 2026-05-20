package tls13

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestConnHandshakeWithCryptoTLSClient(t *testing.T) {
	cert := generateTestCertificate(t)

	serverRaw, clientRaw := net.Pipe()

	errCh := make(chan error, 1)

	go func() {
		defer serverRaw.Close()

		server := NewServerConn(serverRaw, &Config{Certificate: cert})

		if err := server.Handshake(); err != nil {
			errCh <- fmt.Errorf("server handshake: %w", err)
			return
		}

		request := "GET / HTTP/1.1\r\nHost: test\r\n\r\n"
		if _, err := server.Write([]byte(request)); err != nil {
			errCh <- fmt.Errorf("server write: %w", err)
			return
		}

		buf := make([]byte, 1024)
		n, err := server.Read(buf)
		if err != nil {
			errCh <- fmt.Errorf("server read: %w", err)
			return
		}

		expected := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
		if string(buf[:n]) != expected {
			errCh <- errors.New("unexpected response")
			return
		}

		errCh <- nil
	}()

	tlsClient := tls.Client(clientRaw, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})

	if err := tlsClient.Handshake(); err != nil {
		serverErr := <-errCh
		t.Fatalf("client handshake: %v\nserver error: %v", err, serverErr)
	}

	buf := make([]byte, 1024)
	n, err := tlsClient.Read(buf)
	if err != nil {
		serverErr := <-errCh
		t.Fatalf("client read: %v\nserver error: %v", err, serverErr)
	}

	expectedReq := "GET / HTTP/1.1\r\nHost: test\r\n\r\n"
	if string(buf[:n]) != expectedReq {
		t.Fatalf("unexpected request: got %q, want %q", string(buf[:n]), expectedReq)
	}

	response := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	if _, err := tlsClient.Write([]byte(response)); err != nil {
		t.Fatal(err)
	}

	// Remove clientRaw.Close() from where it is now
	tlsClient.Close()
	serverErr := <-errCh
	clientRaw.Close()

	if serverErr != nil {
		t.Fatal(serverErr)
	}
}

func generateTestCertificate(t testing.TB) tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}
