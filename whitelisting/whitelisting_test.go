package whitelisting_test

import (
	"bytes"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/digital-security-lab/hwl-proxy/whitelisting"
)

var tmpQuantity = 2

var whitelistDefault = whitelisting.Whitelist{
	whitelisting.WhitelistItem{Key: "host"},
	whitelisting.WhitelistItem{Key: "connection", Val: `(?i)(close|keep-alive)`},
	whitelisting.WhitelistItem{Key: "content-length", Val: `\d+`},
	whitelisting.WhitelistItem{Key: "transfer-encoding", Val: `(?i)(chunked)`},
	whitelisting.WhitelistItem{Key: "cookie", Val: `( |\S)*`},
}

func TestLoadWhitelist(t *testing.T) {
	_, b, _, _ := runtime.Caller(0)
	basepath := filepath.Dir(b)

	var whitelist whitelisting.Whitelist
	err := whitelist.Load(basepath + "/../test/" + "whitelist.json")
	if err != nil {
		t.Error(err)
	}

}

func TestRequestHeaderWhitelisting(t *testing.T) {
	requestBytes := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: example\r\n\r\n")
	whitelisted, nonWhitelisted, ok := whitelistDefault.Apply(requestBytes)

	if !ok {
		t.Error()
	}

	if bytes.Equal(whitelisted, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")) == false {
		t.Error("Invalid whitelisted return value", "("+string(whitelisted)+")", len(whitelisted), len([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")))
	}

	if bytes.Equal(nonWhitelisted, []byte("X-Test: example\r\n")) == false {
		t.Error("Invalid non whitelisted return value", "("+string(nonWhitelisted)+")")
	}
}

func TestRequestHeaderWhitelistingDuplicateHeaders(t *testing.T) {
	requestBytes := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: example\r\nConnection: keep-alive\r\nConnection: keep-alive\r\nCookie: c1\r\nCookie: c2\r\n\r\n")
	whitelisted, nonWhitelisted, ok := whitelistDefault.Apply(requestBytes)

	if !ok {
		t.Error()
	}

	if bytes.Equal(whitelisted, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nCookie: c1\r\n\r\n")) == false {
		t.Error("Invalid whitelisted return value", "("+string(whitelisted)+")")
	}

	if bytes.Equal(nonWhitelisted, []byte("X-Test: example\r\nConnection: keep-alive\r\nCookie: c2\r\n")) == false {
		t.Error("Invalid non whitelisted return value", "("+string(nonWhitelisted)+")")
	}
}

func TestRequestHeaderWhitelistingInvalidHeaders(t *testing.T) {
	requestBytes := []byte("GET /index.html HTTP/1.1\r\nHost\r: example.com\r\nX-Test: example\r\nConnection: keep-alive\r\nConnection: keep-alive\r\nCookie: c1\r\nCookie: c2\r\n\r\n")
	whitelisted, nonWhitelisted, ok := whitelistDefault.Apply(requestBytes)

	if ok || whitelisted != nil || nonWhitelisted != nil {
		t.Error()
	}

}

func TestJoinHeaders(t *testing.T) {
	requestBytes := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
	result := whitelisting.JoinHeaders(requestBytes, []byte("X-Test: example\r\n"))
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: example\r\n\r\n")) == false {
		t.Error("Concat headers failed", string(result))
	}
}

func TestJoinHeadersHeaderOverwriting(t *testing.T) {
	// Overlapping header in the end
	requestBytes := []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: do-not-change\r\n\r\n")
	result := whitelisting.JoinHeaders(requestBytes, []byte("X-Test: example\r\n"))
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: do-not-change\r\n\r\n")) == false {
		t.Error("Concat headers failed", string(result))
	}

	// Overlapping header inbetween
	requestBytes = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: do-not-change\r\nX-Other-Headers: test\r\n\r\n")
	result = whitelisting.JoinHeaders(requestBytes, []byte("X-Test: example\r\n"))
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: do-not-change\r\nX-Other-Headers: test\r\n\r\n")) == false {
		t.Error("Concat headers failed", string(result))
	}

	// Overlapping header occuring multiple times
	requestBytes = []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: do-not-change\r\nX-Other-Headers: test\r\n\r\n")
	result = whitelisting.JoinHeaders(requestBytes, []byte("X-Test: example\r\nX-Test: example\r\n"))
	if bytes.Equal(result, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nX-Test: do-not-change\r\nX-Other-Headers: test\r\n\r\n")) == false {
		t.Error("Concat headers failed", string(result))
	}
}
