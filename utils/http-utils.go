package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strconv"
)

const (
	regexToken        = `(\x21|[\x23-\x27]|\x2a|\x2b|\x2d|\x2e|[\x5e-\x60]|\x7c|\x7e|[\x30-\x39]|[\x41-\x5a]|[\x61-\x7a])`
	regexRequestLine  = `(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE)\x20[\x21-\x7F]+\x20HTTP/\d[.]\d(\r\n){1}`
	regexResponseLine = `HTTP/\d[.]\d\x20\d\d\d\x20.+(\r\n){1}`
	regexHeaderLines  = `((.+)(\r\n)?)+`
	regexValidHeader  = `^((` + regexToken + `+:((\x09|\x20)?([\x21-\xFF]))*(\x09|\x20)?))$`
	regexHeaderEnd    = `(\r\n\r\n){1}`
)

//CreateResponse returns a full http response with custom response code and body.
//The content-length header is set dynamically matching the body length.
func CreateResponse(code int, message string, body []byte) []byte {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n", code, message, len(body))
	return append([]byte(response), body...)
}

//IsRequest checks whether a data array has a valid http request format.
//It considers the request line, lines separated by \r\n and the occurance of \r\n\r\n.
func IsRequest(data []byte) bool {
	re, _ := regexp.Compile(regexRequestLine + regexHeaderLines + regexHeaderEnd)
	return re.Match(data)
}

func IsResponse(data []byte) bool {
	re, _ := regexp.Compile(regexResponseLine + regexHeaderLines + regexHeaderEnd)
	return re.Match(data)
}

func IsValidHeader(data []byte) bool {
	re, _ := regexp.Compile(regexValidHeader)
	return re.Match(data)
}

func GetHeaderFieldName(headerLine []byte) []byte {
	index := bytes.Index(headerLine, []byte(":"))
	if index > -1 {
		return headerLine[:index]
	}
	return nil
}

//GetHeaderFieldValues returns an array with all values of headers with the matching field value.
func GetHeaderFieldValues(data []byte, key []byte) [][]byte {
	var values [][]byte
	lines := bytes.Split(data, []byte("\r\n"))
	var index int
	for i := 0; i < len(lines); i++ {
		if IsValidHeader(lines[i]) {
			index = bytes.Index(lines[i], []byte(":"))
			if index > -1 && bytes.Equal(bytes.ToLower(lines[i][:index]), bytes.ToLower(key)) {
				if len(lines[i]) > index {
					values = append(values, bytes.TrimSpace(lines[i][index+1:]))
				} else {
					values = append(values, []byte(""))
				}
			}
		}
	}
	return values
}

//AddHeader adds a header to a request/response. The data array requires a valid format validated with IsRequest() or IsResponse().
func AddHeader(data []byte, key string, val string) []byte {
	var result []byte
	fragments := bytes.Split(data, []byte("\r\n\r\n"))
	fragments[0] = append(fragments[0], []byte("\r\n"+key+": "+val)...)
	if len(fragments) > 1 {
		result = bytes.Join(fragments, []byte("\r\n\r\n"))
	} else {
		result = append(fragments[0], []byte("\r\n\r\n")...)
	}

	return result

}

//SetHeaderValue replaces the value of header with a certain key. If index is 0, all headers with the matching key will be modified.
//If index is > 0, only the nth occurance of the header will be modified.
func SetHeaderValue(data []byte, key string, val string, index int) []byte {
	var result []byte
	fragments := bytes.Split(data, []byte("\r\n\r\n"))
	lines := bytes.Split(fragments[0], []byte("\r\n"))

	re, _ := regexp.Compile(`^((((?i)` + key + `): ?.*))$`)
	counter := 1
	for i := range lines {
		if re.Match(lines[i]) {
			if index == 0 || counter == index {
				lines[i] = []byte(key + ": " + val)
			}
			counter++
		}
	}
	fragments[0] = bytes.Join(lines, []byte("\r\n"))
	if len(fragments) > 1 {
		result = bytes.Join(fragments, []byte("\r\n\r\n"))
	} else {
		result = append(fragments[0], []byte("\r\n\r\n")...)
	}

	return result
}

//RemoveHeader removes a header with a certain key. If index is 0, all headers with the matching key will be removed.
//If index is > 0, only the nth occurance of the header will be removed.
func RemoveHeader(data []byte, key string, index int) []byte {
	var result []byte
	fragments := bytes.Split(data, []byte("\r\n\r\n"))
	lines := bytes.Split(fragments[0], []byte("\r\n"))
	var newLines [][]byte
	re, _ := regexp.Compile(`^((((?i)` + key + `): ?.*))$`)
	counter := 1
	var remove bool
	for i := range lines {
		remove = false
		if re.Match(lines[i]) {
			if index == 0 || counter == index {
				remove = true
			}
			counter++
		}
		if !remove {
			newLines = append(newLines, lines[i])
		}
	}
	fragments[0] = bytes.Join(newLines, []byte("\r\n"))
	if len(fragments) > 1 {
		result = bytes.Join(fragments, []byte("\r\n\r\n"))
	} else {
		result = append(fragments[0], []byte("\r\n\r\n")...)
	}

	return result
}

//ReadHTTPBody reads the expected body of an http stream.
//The data parameter must contain the previously received headers.
func ReadHTTPBody(br *bufio.Reader, data []byte, modifyHeaders bool) ([]byte, error) {
	contentLength := GetHeaderFieldValues(data, []byte("Content-Length"))
	transferEncoding := GetHeaderFieldValues(data, []byte("Transfer-Encoding"))
	if len(transferEncoding) > 0 && bytes.Equal(transferEncoding[0], []byte("chunked")) {
		if modifyHeaders {
			data = RemoveHeader(data, "Content-Length", 0)
		}
		body, err := ReadChunks(br)
		if err != nil {
			return nil, err
		}
		data = append(data, body...)
	} else if len(contentLength) > 0 {
		clNum, err := strconv.Atoi(string(contentLength[0]))
		if err != nil {
			return nil, err
		}
		body, err := ReadByContentLength(br, clNum)
		if err != nil {
			return nil, err
		}
		data = append(data, body...)
	}
	return data, nil
}
