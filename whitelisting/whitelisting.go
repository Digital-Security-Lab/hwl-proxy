package whitelisting

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"regexp"

	"github.com/digital-security-lab/hwl-proxy/utils"
)

type WhitelistItem struct {
	Key string // header key
	Val string // value as regex
}

type Whitelist []WhitelistItem

//Load reads the whitelist from an according JSON file.
func (wl *Whitelist) Load(file string) error {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, wl)
	return err
}

//Apply modifies the request data, so only whitelisted headers are preserved.
//It is assumed that the first line is the request line and is therefore ignored.
//The first byte array returned is the request line and all whitelisted headers. The second array contains the headers that are not whitelisted.
func (wl *Whitelist) Apply(data []byte) ([]byte, []byte, bool) {
	var err error
	var re *regexp.Regexp
	var whitelisted, nonWhitelisted []byte
	lines := bytes.Split(data, []byte("\r\n"))

	// append request line
	whitelisted = append(whitelisted, lines[0]...)
	whitelisted = append(whitelisted, []byte("\r\n")...)

	//whitelisting
	wlHeaderOccurance := make([]bool, len(*wl))

	for i, line := range lines {
		if i != 0 && len(line) > 0 {
			// return without results if invalid syntax is detected
			if !utils.IsValidHeader(line) && len(line) > 0 {
				return nil, nil, false
			}
			match := false
			for j, wlItem := range *wl {
				if len(wlItem.Val) > 0 {
					re, err = regexp.Compile(`^((((?i)` + wlItem.Key + `):(\x09|\x20)?` + wlItem.Val + `(\x09|\x20)?){1})$`)
				} else {
					re, err = regexp.Compile(`^(((((?i)` + wlItem.Key + `):((\x09|\x20)?([\x21-\xFF]))*(\x09|\x20)?)){1})$`)
				}

				if wlHeaderOccurance[j] == false && (err == nil && re.Match(line)) {
					match = true
					wlHeaderOccurance[j] = true
					break
				}
			}

			if match {
				whitelisted = append(whitelisted, line...)
				whitelisted = append(whitelisted, []byte("\r\n")...)
			} else {
				nonWhitelisted = append(nonWhitelisted, line...)
				nonWhitelisted = append(nonWhitelisted, []byte("\r\n")...)
			}
		}
	}
	whitelisted = append(whitelisted, []byte("\r\n")...)
	return whitelisted, nonWhitelisted, true
}

//JoinHeaders adds headers to the original message,
//if their field name is not already included.
func JoinHeaders(message []byte, headers []byte) []byte {
	var data []byte
	tmp := bytes.SplitN(message, []byte("\r\n\r\n"), 2)
	if len(tmp) > 0 && len(tmp) < 3 {
		// check for header field name overlapping
		headerLines := bytes.Split(headers, []byte("\r\n"))
		messageLines := bytes.Split(tmp[0], []byte("\r\n"))
		for _, messageLine := range messageLines {
			if utils.IsValidHeader(messageLine) {
				headerFieldName := utils.GetHeaderFieldName(messageLine)
				for i := 0; i < len(headerLines); i++ {
					refFieldName := utils.GetHeaderFieldName(headerLines[i])
					if bytes.Compare(bytes.ToLower(headerFieldName), bytes.ToLower(refFieldName)) == 0 {
						// remove original header if field name matches with a field name
						// of the request modified by the intermediary
						headerLines = append(headerLines[:i], headerLines[i+1:]...)
						i--
					}
				}
			}
		}
		headers = bytes.Join(headerLines, []byte("\r\n"))
		data = append(append(data, append(tmp[0], append([]byte("\r\n"), headers...)...)...), []byte("\r\n")...)
		if len(tmp) == 2 {
			data = append(data, tmp[1]...)
		}
	}

	return data
}
