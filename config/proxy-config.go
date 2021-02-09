package config

import (
	"encoding/json"
	"io/ioutil"
	"time"
)

type ProxyConfig struct {
	IncomingAddress string        // incoming connection from the internet
	PortOutLocal    int           // outgoing connection to local intermediary or origin server
	PortInLocal     int           // incoming connection from local intermediary
	OutgoingAddress string        // outgoing connection to next intermediary
	Whitelisting    bool          // apply whitelisting
	ConnTimeout     time.Duration // connection read and write timeout
	Origin          bool          // true, if target is origin server, false if target is intermediary with two endpoints
}

func (proxyConfig *ProxyConfig) Load(file string) error {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, proxyConfig)
	return err
}
