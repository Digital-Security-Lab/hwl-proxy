package utils_test

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/digital-security-lab/hwl-proxy/utils"
)

func TestCreateResponse(t *testing.T) {
	responseCode := 200
	responseMessage := "OK"
	responseBody := []byte("Successful Request")

	response := utils.CreateResponse(responseCode, responseMessage, responseBody)
	lines := bytes.Split(response, []byte("\r\n"))
	if len(lines) != 4 {
		t.Error("Invalid response")
		return
	}

	if bytes.Equal(lines[0], []byte("HTTP/1.1 "+strconv.Itoa(responseCode)+" "+responseMessage)) == false {
		t.Error("Invalid response line:", string(lines[0]), "Expected:", "HTTP/1.1 "+strconv.Itoa(responseCode)+" "+responseMessage)
	}

	if bytes.Equal(lines[1], []byte("Content-Length: "+strconv.Itoa(len(responseBody)))) == false {
		t.Error("Invalid content-length header:", string(lines[1]), "Expected", "Content-Length: "+strconv.Itoa(len(responseBody)))
	}

	if bytes.Equal(lines[2], []byte("")) == false {
		t.Error("Invalid empty line:", string(lines[2]))
	}

	if bytes.Equal(lines[3], responseBody) == false {
		t.Error("Invalid body:", string(lines[3]), "Expected:", string(responseBody))
	}
}

func TestIsRequest(t *testing.T) {

	requestBytes := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if utils.IsRequest(requestBytes) == false {
		t.Error("Wrong request validation")
	}

	requestBytes = []byte("GET /index.html HTTP/1.1\rHost: example.com\r\n\r\n")
	if utils.IsRequest(requestBytes) == true {
		t.Error("Wrong request validation")
	}

	requestBytes = []byte("GET /index.html HTTP/1.1\nHost: example.com\r\n\r\n")
	if utils.IsRequest(requestBytes) == true {
		t.Error("Wrong request validation")
	}

	requestBytes = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\r\n")
	if utils.IsRequest(requestBytes) == true {
		t.Error("Wrong request validation")
	}

	requestBytes = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n")
	if utils.IsRequest(requestBytes) == true {
		t.Error("Wrong request validation")
	}

	requestBytes = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r")
	if utils.IsRequest(requestBytes) == true {
		t.Error("Wrong request validation")
	}

	requestBytes = []byte("GET/index.html HTTP/1.1\nHost: example.com\r\n\r\n")
	if utils.IsRequest(requestBytes) == true {
		t.Error("Wrong request validation")
	}
}

func TestIsResponse(t *testing.T) {
	responseBytes := []byte("HTTP/1.1 200 OK\r\nHost: example.com\r\n\r\n")
	if utils.IsResponse(responseBytes) == false {
		t.Error("Wrong response validation")
	}

	responseBytes = []byte("HTTP/1.1 200 OK\rHost: example.com\r\n\r\n")
	if utils.IsResponse(responseBytes) == true {
		t.Error("Wrong response validation")
	}

	responseBytes = []byte("HTTP/1.1 200 OK\nHost: example.com\r\n\r\n")
	if utils.IsResponse(responseBytes) == true {
		t.Error("Wrong response validation")
	}

	responseBytes = []byte("HTTP/1.1 200 OK\r\nHost: example.com\r\r\n")
	if utils.IsResponse(responseBytes) == true {
		t.Error("Wrong response validation")
	}

	responseBytes = []byte("HTTP/1.1 200 OK\r\nHost: example.com\r\n")
	if utils.IsResponse(responseBytes) == true {
		t.Error("Wrong response validation")
	}

	responseBytes = []byte("HTTP/1.1 200 OK\r\nHost: example.com\r")
	if utils.IsResponse(responseBytes) == true {
		t.Error("Wrong response validation")
	}

	responseBytes = []byte("HTTP/1.1 a0 OK\nHost: example.com\r\n\r\n")
	if utils.IsResponse(responseBytes) == true {
		t.Error("Wrong response validation")
	}
}

func TestIsValidHeader(t *testing.T) {
	// invalid character
	if utils.IsValidHeader([]byte("Test:\r value")) {
		t.Error("Multiple header field values not accepted")
	}
	// invalid space
	if utils.IsValidHeader([]byte("Test:  value")) {
		t.Error("Multiple header field values not accepted")
	}
	// valid
	if !utils.IsValidHeader([]byte("Test: value")) {
		t.Error("Multiple header field values not accepted")
	}
	// valid multiple values
	if !utils.IsValidHeader([]byte("Set-Cookie: id=123 expires=Sat, 15-Jul-2017 23:58:22 GMT; path=/; domain=x.com; httponly")) {
		t.Error("Multiple header field values not accepted")
	}
}

func TestAddHeader(t *testing.T) {
	// Without body
	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	result := utils.AddHeader(data, "X-Test", "1234")
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: 1234\r\n\r\n")) == false {
		t.Fail()
	}

	// With body
	data = []byte("GET /index.html HTTP/1.1\r\nContent-Length: 3\r\nHost: example.com\r\n\r\n123")
	result = utils.AddHeader(data, "X-Test", "1234")
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nContent-Length: 3\r\nHost: example.com\r\nX-Test: 1234\r\n\r\n123")) == false {
		t.Fail()
	}
}

func TestSetHeaderValue(t *testing.T) {
	// first header with key
	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: old\r\n\r\n123")
	result := utils.SetHeaderValue(data, "X-Test", "new", 1)
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: new\r\n\r\n123")) == false {
		t.Fail()
	}

	// second header with key
	data = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: old\r\nX-Test: old\r\nX-Test: old\r\n\r\n")
	result = utils.SetHeaderValue(data, "X-Test", "new", 2)
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: old\r\nX-Test: new\r\nX-Test: old\r\n\r\n")) == false {
		t.Fail()
	}

	// all headers with key
	data = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: old\r\nX-Test: old\r\nX-Test: old\r\n\r\n")
	result = utils.SetHeaderValue(data, "X-Test", "new", 0)
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: new\r\nX-Test: new\r\nX-Test: new\r\n\r\n")) == false {
		t.Fail()
	}
}

func TestRemoveAllHeadersByKey(t *testing.T) {
	data := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: 1\r\nX-Test: 2\r\n\r\n")
	result := utils.RemoveHeader(data, "X-Test", 0)
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")) == false {
		t.Fail()
	}

	data = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: 1\r\nX-Test: 2\r\n\r\n")
	result = utils.RemoveHeader(data, "X-Test", 1)
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: 2\r\n\r\n")) == false {
		t.Fail()
	}

	data = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: 1\r\nX-Test: 2\r\n\r\n")
	result = utils.RemoveHeader(data, "X-Test", 2)
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: 1\r\n\r\n")) == false {
		t.Fail()
	}
}

func TestGetHeaderValue(t *testing.T) {
	// single header
	requestBytes := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: example\r\n\r\n")
	result := utils.GetHeaderFieldValues(requestBytes, []byte("X-Test"))
	if len(result) != 1 || bytes.Equal(result[0], []byte("example")) == false {
		t.Error("Header not found", string(requestBytes), "X-Test")
	}

	// duplicate header
	requestBytes = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: example1\r\nX-test: example2\r\n\r\n")
	result = utils.GetHeaderFieldValues(requestBytes, []byte("X-Test"))
	if len(result) != 2 || bytes.Equal(result[0], []byte("example1")) == false || bytes.Equal(result[1], []byte("example2")) == false {
		t.Error("Header not found", string(requestBytes), "X-Test")
	}
}
