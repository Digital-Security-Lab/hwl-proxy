package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/digital-security-lab/hwl-proxy/session"
	"github.com/digital-security-lab/hwl-proxy/utils"
)

func incomingServer() {
	server, err := net.Listen("tcp", proxyConfig.IncomingAddress)
	log.Println("Start Incoming module server:", proxyConfig.IncomingAddress)
	if err != nil {
		log.Fatal(err.Error())
	}
	for {
		conn, err := server.Accept()
		if err != nil {
			log.Println(err.Error())
			break
		}
		go handleConnIncoming(conn)
	}
}

func handleConnIncoming(connIn net.Conn) {
	defer connIn.Close()
	connIn.SetDeadline(time.Now().Add(proxyConfig.ConnTimeout * time.Second))
	var connOut net.Conn
	processIncomingRequest(connIn, connOut)
}

//Handle request from incoming connection.
func processIncomingRequest(connIn net.Conn, connOut net.Conn) {
	var currentSession *session.Session
	connInBr := bufio.NewReader(connIn)
	var ok bool
	for {
		if !proxyConfig.Origin {
			currentSession = session.Create()
			defer session.Remove(currentSession.ID)
		}
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

		// 3 Header whitelisting
		if proxyConfig.Whitelisting {
			if proxyConfig.Origin {
				data, _, ok = whitelist.Apply(data)
				if !ok {
					connIn.Write(utils.CreateResponse(400, "Bad Request", []byte("Bad Request")))
					return
				}
			} else {
				data, currentSession.SplitData, ok = whitelist.Apply(data)
				if !ok {
					connIn.Write(utils.CreateResponse(400, "Bad Request", []byte("Bad Request")))
					return
				}
				data = utils.AddHeader(data, "X-Message-ID", currentSession.ID)
			}
		}

		// 4 Read body
		data, err = utils.ReadHTTPBody(connInBr, data, proxyConfig.Whitelisting)
		if err != nil {
			connIn.Write(utils.CreateResponse(400, "Bad Request", []byte("Bad Request")))
			return
		}

		// 5 Forward request
		if connOut == nil {
			// Open connection if first request
			connOut, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyConfig.PortOutLocal))
			if err != nil {
				return
			}
			defer connOut.Close()
			connOut.SetDeadline(time.Now().Add(proxyConfig.ConnTimeout * time.Second))
		}
		connOut.Write(data)

		// Receive response
		err = processIncomingResponse(connOut, connIn)
		if err != nil {
			return
		}
	}
}

//Handle response from outgoing connection.
func processIncomingResponse(connIn net.Conn, connOut net.Conn) error {
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
