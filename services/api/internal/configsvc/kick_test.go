package configsvc

import (
	"testing"

	"github.com/google/uuid"
)

func TestKickInvokesCancel(t *testing.T) {
	s := New(nil, nil, nil)
	called := false
	id := uuid.New()
	s.mu.Lock()
	s.kicks[id] = func() { called = true }
	s.mu.Unlock()
	s.Kick(id)
	if !called {
		t.Fatal("Kick did not cancel the watch")
	}
	s.Kick(uuid.Nil)
}
