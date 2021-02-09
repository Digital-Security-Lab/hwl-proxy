package session_test

import (
	"testing"

	"github.com/digital-security-lab/hwl-proxy/session"
)

func TestSession(t *testing.T) {
	// Session create
	createSession := session.Create()
	if createSession == nil {
		t.Fatal("Session create returns nil")
	}
	id := createSession.ID

	// Session get valid id
	getSession := session.Get(id)
	if getSession == nil {
		t.Error("Session get returns nil for a valid key")
	}

	// Session get invalid id
	getSession = session.Get("abc")
	if getSession != nil {
		t.Error("Session get does not return nil for an invalid key")
	}

	// Session remove
	rmState := session.Remove("abc")
	if rmState == true {
		t.Error("Session remove returns true for an invalid key")
	}
	rmState = session.Remove(id)
	if rmState == false {
		t.Error("Session remove returns false for a valid key")
	}
	getSession = session.Get(id)
	if getSession != nil {
		t.Error("Session not deleted properly")
	}
}
