package utils_test

import (
	"bufio"
	"bytes"
	"net"
	"strconv"
	"testing"

	"github.com/digital-security-lab/hwl-proxy/utils"
)

func TestReadUntilBytes(t *testing.T) {
	buf := bytes.NewBufferString("abcdefghijklmnopqrstuvw")
	br := bufio.NewReader(buf)
	data, err := utils.ReadUntilBytes(br, []byte("kl"))
	if err != nil {
		t.Error("Error returned")
	}
	if bytes.Equal(data, []byte("abcdefghijkl")) == false {
		t.Error("Read:", string(data), "Expected:", "abcdefghijkl")
	}

	buf = bytes.NewBufferString("abcdefghijklmnopqrstuvw")
	br = bufio.NewReader(buf)
	data, err = utils.ReadUntilBytes(br, []byte("lk"))
	if err == nil {
		t.Error("No error returned")
	}
}

func TestReadChunks(t *testing.T) {
	chunk_a := []byte("0\r\n\r\n")
	chunk_b := []byte("1\r\na\r\n")
	chunk_c := []byte("10\r\nabcdefghij\r\n")

	buf := bytes.NewBuffer(chunk_a)
	br := bufio.NewReader(buf)
	data, err := utils.ReadChunks(br)
	if err != nil {
		t.Error("Error returned")
	}
	if bytes.Equal(data, chunk_a) == false {
		t.Error("Read:", string(data), "Expected:", string(chunk_a))
	}

	buf = bytes.NewBuffer(append(chunk_b, chunk_a...))
	br = bufio.NewReader(buf)
	data, err = utils.ReadChunks(br)
	if err != nil {
		t.Error("Error returned")
	}
	if bytes.Equal(data, append(chunk_b, chunk_a...)) == false {
		t.Error("Read:", string(data), "Expected:", string(append(chunk_b, chunk_a...)))
	}

	buf = bytes.NewBuffer(append(chunk_c, append(chunk_b, chunk_a...)...))
	br = bufio.NewReader(buf)
	data, err = utils.ReadChunks(br)
	if err != nil {
		t.Error("Error returned")
	}
	if bytes.Equal(data, append(chunk_c, append(chunk_b, chunk_a...)...)) == false {
		t.Error("Read:", string(data), "Expected:", string(append(chunk_c, append(chunk_b, chunk_a...)...)))
	}
}

func TestReadByContentLength(t *testing.T) {
	buf := bytes.NewBufferString("abcdefghijklmnopqrstuvw")
	br := bufio.NewReader(buf)
	data, err := utils.ReadByContentLength(br, 3)
	if err != nil {
		t.Error("Error returned")
	}
	if bytes.Equal(data, []byte("abc")) == false {
		t.Error("Incorrect data")
	}

	br = bufio.NewReader(buf)
	data, err = utils.ReadByContentLength(br, 3)
	if err == nil {
		t.Error("Error not returned")
	}
}

func TestTunnel(t *testing.T) {
	connIn, connOut := net.Pipe()
	data := []byte("Sample message")
	buf := make([]byte, 256)

	go utils.Tunnel(connOut, connIn)
	bw := bufio.NewWriter(connIn)
	length, err := bw.Write(data)
	bw.Flush()
	if err != nil || length != len(data) {
		t.Fail()
	}

	br := bufio.NewReader(connOut)
	length, err = br.Read(buf)
	if err != nil || length != len(data) {
		t.Error(string(buf), strconv.Itoa(length))
	}
	connOut.Close()
	connIn.Close()
}
