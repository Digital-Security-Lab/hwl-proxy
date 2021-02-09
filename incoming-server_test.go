package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/digital-security-lab/hwl-proxy/whitelisting"
)

func ProcessIncomingRequestTest(t *testing.T, request string, testRegex string) {
	whitelist = []whitelisting.WhitelistItem{
		whitelisting.WhitelistItem{Key: "host"},
		whitelisting.WhitelistItem{Key: "connection", Val: `(?i)(close|keep-alive)`},
		whitelisting.WhitelistItem{Key: "content-length", Val: `\d+`},
		whitelisting.WhitelistItem{Key: "transfer-encoding", Val: `(?i)(chunked)`},
	}

	reqLog = log.New(os.Stdout, log.Prefix(), 0)

	buf := make([]byte, 1024)
	reqData := []byte(request)
	re, err := regexp.Compile(testRegex)
	if err != nil {
		t.Error(err)
	}
	connIn, connOut := net.Pipe()
	go processIncomingRequest(connIn, connOut)

	bw := bufio.NewWriter(connOut)
	_, err = bw.Write(reqData)
	if err != nil {
		t.Error(err)
	}
	bw.Flush()

	connIn.SetReadDeadline(time.Now().Add(time.Millisecond * 10))
	br := bufio.NewReader(connIn)
	length, err := br.Read(buf)
	if re.Match(buf[:length]) == false {
		t.Error("Forwarded request:", string(buf[:length]))

	}
}

func TestProcessIncomingRequest(t *testing.T) {
	proxyConfig.Whitelisting = true
	ProcessIncomingRequestTest(t, "GET /index HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n", `^GET /index HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nX-Message-ID: \d+\r\n\r\n$`)
	ProcessIncomingRequestTest(t, "POST /index HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n", `^POST /index HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\nX-Message-ID: \d+\r\n\r\n$`)
	ProcessIncomingRequestTest(t, "POST /index HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", `^POST /index HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nX-Message-ID: \d+\r\n\r\n0\r\n\r\n$`)
}
