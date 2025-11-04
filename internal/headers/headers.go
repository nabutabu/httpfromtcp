package headers

import (
	"errors"
	"log"
	"strings"
	"unicode"
)

type Headers map[string]string

func NewHeaders() Headers {
	return make(Headers)
}

// isValidCharSetNoRegex checks if the input string contains only the
// specified set of allowed characters without using regular expressions.
func isValidCharSetNoRegex(s string) bool {
	// allowedChars is a map used as a set for quick O(1) character lookup.
	var allowedChars = map[rune]bool{
		'!':  true,
		'#':  true,
		'$':  true,
		'%':  true,
		'&':  true,
		'\'': true,
		'*':  true,
		'+':  true,
		'-':  true,
		'.':  true,
		'^':  true,
		'_':  true,
		'`':  true,
		'|':  true,
		'~':  true,
	}

	if s == "" {
		return false // Or true, depending on if an empty string is considered valid.
	}

	for _, char := range s {
		// Check for A-Z, a-z, 0-9
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') {
			continue
		}

		// Check if the character is in the allowed special characters map
		if _, exists := allowedChars[char]; exists {
			continue
		}

		// If the character doesn't match any of the above conditions, it's invalid
		return false
	}

	// If the loop completes without returning false, all characters are valid
	return true
}

func (h Headers) Parse(data []byte) (n int, done bool, err error) {
	log.Println("/ParseHeader")
	if !strings.Contains(string(data), "\r\n") {
		return 0, false, nil
	}

	// data contains \r\n
	// check if EOF (indexOf("\r\n") == 0)
	if strings.Index(string(data), "\r\n") == 0 {
		return 0, true, nil
	}

	// get parts of data
	parts := strings.Split(string(data), "\r\n")

	// parts[0] should contain the header
	// remove whitespace and verify whether correct header or not
	header := strings.TrimSpace(parts[0])

	// check space between :
	ind := strings.Index(header, ":")
	if !unicode.IsLetter(rune(header[ind-1])) || header[ind+1] != ' ' {
		return 0, false, errors.New("Invalid header: whitespace")
	}

	header_parts := strings.Split(header, ": ")
	//header_parts[0] = strings.ToLower(header_parts[0])

	// check header_parts[0] for invalid chars
	if !isValidCharSetNoRegex(header_parts[0]) {
		return 0, false, errors.New("Invalid header: characters")
	}

	if _, ok := h[header_parts[0]]; !ok {
		h[header_parts[0]] = header_parts[1]
	} else {
		h[header_parts[0]] += ", " + header_parts[1]
	}

	return strings.Index(string(data), "\r\n") + 2, false, nil
}
