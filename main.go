package main

import (
	"flag"
	"log"
	"os"

	"github.com/digital-security-lab/hwl-proxy/config"
	"github.com/digital-security-lab/hwl-proxy/whitelisting"
)

var reqLog *log.Logger
var proxyConfig config.ProxyConfig
var whitelist whitelisting.Whitelist

func main() {
	// Flags
	var configFile, whitelistFile string
	flag.StringVar(&configFile, "c", "config.json", "config file path")
	flag.StringVar(&whitelistFile, "wl", "whitelist.json", "whitelist file path")
	flag.Parse()

	// Load config
	err := proxyConfig.Load(configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = whitelist.Load(whitelistFile)
	if err != nil {
		log.Fatal(err)
	}

	// Configure logger
	reqLog = log.New(os.Stdout, log.Prefix(), 0)

	// Start servers
	if !proxyConfig.Origin {
		go outgoingServer()
	}
	incomingServer()
}
