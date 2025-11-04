package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

func readMessages(c chan string, cn net.Conn) {
	buf := make([]byte, 8)
	var line string
	for {
		n, _ := cn.Read(buf)

		if n == 0 {
			cn.Close()
			break
		}

		// at this point i have 8 bytes
		// split the buffer to only use the bytes read
		// if we don't do this we will also re-use bytes that
		// were read in the previous iteration for indices > n
		line += string(buf[:n])

		// split this line at '\n' char
		parts := strings.Split(line, "\n")

		// init currLine
		var currLine string

		for i, part := range parts {
			if i != len(parts)-1 {
				currLine += part
			}
		}

		if currLine != "" {
			c <- currLine
		}

		// reset line
		line = parts[len(parts)-1]
	}

	if line != "" {
		c <- line
	}

	close(c)
}

func getLinesChannel(f net.Conn) <-chan string {
	c := make(chan string)

	go readMessages(c, f)

	return c
}

func main() {
	l, err := net.Listen("tcp", ":42069")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		//fmt.Println("Connection Accepted")

		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(cn net.Conn) {
			// Echo all incoming data.
			c := getLinesChannel(cn)

			for s := range c {
				fmt.Printf("%s", s)
			}

			// Shut down the connection.
			//fmt.Println("Closing Connection")
			cn.Close()
		}(conn)
	}

	l.Close()
}
