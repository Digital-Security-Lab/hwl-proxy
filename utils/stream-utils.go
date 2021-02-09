package utils

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

//ReadUntilBytes reads from a stream until the occurance of the delimiter.
func ReadUntilBytes(br *bufio.Reader, delim []byte) ([]byte, error) {
	var data []byte
	for {
		buf, err := br.ReadBytes(byte(delim[len(delim)-1]))
		if err != nil {
			return nil, err
		}
		data = append(data, buf...)
		if bytes.Index(data, delim) == len(data)-len(delim) {
			return data, nil
		}
	}
}

//ReadChunks reads from a stream expecting a chunked encoded http body.
func ReadChunks(reader *bufio.Reader) ([]byte, error) {
	var data []byte

	line, err := ReadUntilBytes(reader, []byte("\r\n"))
	if err == nil {
		num, err := strconv.Atoi(strings.TrimSpace(string(line)))
		if err == nil {
			data = append(data, line...)
			for num != 0 {
				// read chunk
				buf := make([]byte, num)
				_, err := io.ReadFull(reader, buf)
				if err != nil {
					return nil, err
				}
				data = append(data, buf...)
				line, err := ReadUntilBytes(reader, []byte("\r\n"))
				data = append(data, line...)
				// check next chunk size
				line, err = ReadUntilBytes(reader, []byte("\r\n"))
				if err == nil {
					num, err = strconv.Atoi(strings.TrimSpace(string(line)))
					if err != nil {
						return nil, err
					}
					data = append(data, line...)
				}
			}
			line, err = ReadUntilBytes(reader, []byte("\r\n"))
			if err != nil {
				return nil, err
			}
			data = append(data, line...)
			return data, nil
		}
		return data, err
	}
	return data, err
}

//ReadByContentLength reads from a stream expecting a fixed size.
func ReadByContentLength(reader *bufio.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(reader, buf)
	if err != nil {
		return buf, err
	}
	return buf, nil
}

//Tunnel reads incoming data from one connection and forwards to another connection
func Tunnel(connIn net.Conn, connOut net.Conn) {
	buf := make([]byte, 4096)
	for {
		length, err := connIn.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}
		connOut.Write(buf[:length])
	}
}
