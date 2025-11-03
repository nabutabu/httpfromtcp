package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

func readMessages(c chan string, f io.ReadCloser) {
	buf := make([]byte, 8)
	var line string
	for {
		n, _ := f.Read(buf)

		if n == 0 {
			f.Close()
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

func getLinesChannel(f io.ReadCloser) <-chan string {
	c := make(chan string)

	go readMessages(c, f)

	return c
}

func main() {
	file, err := os.Open("messages.txt")
	if err != nil {
		fmt.Println("err")
		panic(err)
	}

	c := getLinesChannel(file)

	for s := range c {
		fmt.Printf("read: %s\n", s)
	}
}
