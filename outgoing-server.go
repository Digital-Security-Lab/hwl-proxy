package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/digital-security-lab/hwl-proxy/session"
	"github.com/digital-security-lab/hwl-proxy/utils"
	"github.com/digital-security-lab/hwl-proxy/whitelisting"
)

func outgoingServer() {
	// listen for incoming connections from intermediary
	server, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", proxyConfig.PortInLocal))
	log.Println("Start Outgoing module server:", fmt.Sprintf("127.0.0.1:%d", proxyConfig.PortInLocal))
	if err != nil {
		log.Fatal(err.Error())
	}
	for {
		conn, err := server.Accept()
		if err != nil {
			log.Println(err.Error())
			break
		}
		go handleConnOutgoing(conn)
	}
}

func handleConnOutgoing(connIn net.Conn) {
	defer connIn.Close()
	connIn.SetDeadline(time.Now().Add(proxyConfig.ConnTimeout * time.Second))
	var connOut net.Conn
	processOutgoingRequest(connIn, connOut)
}

//Handle request to outgoing connection.
func processOutgoingRequest(connIn net.Conn, connOut net.Conn) {
	connInBr := bufio.NewReader(connIn)
	for {
		// 1 Read headers
		data, err := utils.ReadUntilBytes(connInBr, []byte("\r\n\r\n"))
		if err != nil {
			return
		}

		// 2 Check request format
		if !utils.IsRequest(data) {
			connIn.Write(utils.CreateResponse(400, "Bad Request", []byte("Bad Request")))
			return
		}

		// 3 Read body
		contentLength := utils.GetHeaderFieldValues(data, []byte("Content-Length"))
		transferEncoding := utils.GetHeaderFieldValues(data, []byte("Transfer-Encoding"))
		if len(transferEncoding) > 0 && bytes.Equal(transferEncoding[0], []byte("chunked")) {
			if proxyConfig.Whitelisting {
				data = utils.RemoveHeader(data, "Content-Length", 0)
			}
			body, err := utils.ReadChunks(connInBr)
			if err != nil {
				connIn.Write(utils.CreateResponse(400, "Bad Request", []byte("Bad Request")))
				return
			}
			data = append(data, body...)
		} else if len(contentLength) > 0 {
			clNum, err := strconv.Atoi(string(contentLength[0]))
			if err != nil {
				connIn.Write(utils.CreateResponse(400, "Bad Request", []byte("Bad Request")))
				return
			}
			body, err := utils.ReadByContentLength(connInBr, clNum)
			if err != nil {
				connIn.Write(utils.CreateResponse(400, "Bad Request", []byte("Bad Request")))
				return
			}
			data = append(data, body...)
		}

		// 4 Join headers
		if proxyConfig.Whitelisting {
			messageIDs := utils.GetHeaderFieldValues(data, []byte("X-Message-ID"))
			if len(messageIDs) == 1 {
				data = utils.RemoveHeader(data, "X-Message-ID", 0)
				currentSession := session.Get(string(messageIDs[0]))
				if currentSession == nil {
					return
				}
				data = whitelisting.JoinHeaders(data, currentSession.SplitData)
				session.Remove(string(messageIDs[0]))
			} else {
				// handle error no message id
				return
			}
		}
		// 5 Forward request
		if connOut == nil {
			// Open connection if first request
			connOut, err = net.Dial("tcp", proxyConfig.OutgoingAddress)
			if err != nil {
				return
			}
			defer connOut.Close()
			connOut.SetDeadline(time.Now().Add(proxyConfig.ConnTimeout * time.Second))
		}
		connOut.Write(data)

		// Receive response
		err = processOutgoingResponse(connOut, connIn)
		if err != nil {
			return
		}
	}
}

//Handle response from outgoing connection.
func processOutgoingResponse(connIn net.Conn, connOut net.Conn) error {
	connInBr := bufio.NewReader(connIn)
	// 1 Read headers
	data, err := utils.ReadUntilBytes(connInBr, []byte("\r\n\r\n"))
	if err != nil {
		return err
	}

	// 2 Check request format
	if !utils.IsResponse(data) {
		return err
	}

	// 3 Read body
	data, err = utils.ReadHTTPBody(connInBr, data, proxyConfig.Whitelisting)
	if err != nil {
		return err
	}
	_, err = connOut.Write(data)
	return err
}
