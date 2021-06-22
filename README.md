# HWL Proxy

## Description
This repository contains the proof-of-concept implementation of a Header Whitelisting (HWL) Proxy. It can be deployed on HTTP intermediaries or web servers to sanitize HTTP requests from unknown or invalid header fields. 

**Please note:** This application does not support HTTPS and is only meant for research and testing purposes.

## Requirements
- Go v1.13.3 or higher

## Download project
```
go get github.com/Digital-Security-Lab/hwl-proxy
```

## Build 
```
go build -o hwl-proxy
```

## Testing
```
go test ./...
```

## Run 
```
./hwl-proxy
```

### Optional flags
```
  -c string
        config file path (default "config.json")
  -wl string
        whitelist file path (default "whitelist.json")
```

## Proxy configuration

The proxy configuration must be defined in a JSON file (default: config.json). 

If deployed on an intermediary, the file may look as follows:
```json
{
    "incomingAddress": "<host-address>:80",
    "portOutLocal": 81,
    "portInLocal": 80,
    "outgoingAddress": "<host-address>:80",
    "whitelisting": true,
    "origin": false,
    "connTimeout": 30
}
```
If deployed on an web server, the file may look as follows:
```json
{
    "incomingAddress": "<host-address>:80",
    "portOutLocal": 81,
    "whitelisting": true,
    "origin": true,
    "connTimeout": 30
}
```

## Whitelist configuration
The request header whitelist is used to define which header fields should be forwarded to the intermediary or web server. It must be specified in a JSON file (default: whitelist.json), which contains an array of `{"key": "", "val": ""}` objects. The value of `key` represents the HTTP request header field name. The `val` parameter is optional and can be used to limit the corresponding HTTP request header field value by a regular expression. If left out, the value can be any value that is compliant with the syntax specified in [`RFC 2730`](https://tools.ietf.org/html/rfc7230). The following is an example for a valid whitelist configuration:
```json
[
    {
        "key": "host"
    },{
        "key": "content-length",
        "val": "\\d+",
    },{
        "key": "connection",
        "val": "(keep-alive|close)",
    }
]
```
## References
- Büttner, A., Nguyen, H. V., Gruschka, N., & Lo Iacono, L. (2021). Less is Often More: Header Whitelisting as Semantic Gap Mitigation in HTTP-Based Software Systems. In IFIP International Conference on ICT Systems Security and Privacy Protection (pp. 332-347). Springer, Cham. [Link](https://link.springer.com/chapter/10.1007/978-3-030-78120-0_22)

## License
[`MIT License`](https://github.com/Digital-Security-Lab/hwl-proxy/blob/master/LICENSE)
