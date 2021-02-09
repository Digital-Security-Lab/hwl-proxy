package session

import (
	"strconv"
	"sync"

	"github.com/digital-security-lab/hwl-proxy/utils"
)

//Session is a container for each request/response session.
type Session struct {
	ID        string
	SplitData []byte
}

var sessionMap = make(map[string]*Session)
var sessionMutex sync.Mutex

//Create creates a new session object with a unique id.
func Create() *Session {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	id := strconv.Itoa(utils.GenerateRandomInt())
	// TODO: check whether ID exists
	sessionMap[id] = &Session{ID: id}
	return sessionMap[id]
}

//Get returns the session object for the matching id. If the id does not exist, nil is returned.
func Get(id string) *Session {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if val, ok := sessionMap[id]; ok {
		return val
	}
	return nil
}

//Remove removes an existing session and returns a boolean value indicating whether a session with id existed.
func Remove(id string) bool {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	if _, ok := sessionMap[id]; ok {
		delete(sessionMap, id)
		return true
	}
	return false
}
