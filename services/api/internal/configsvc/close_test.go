package configsvc

import "testing"

func TestCloseIsIdempotentAndSignals(t *testing.T) {
	s := New(nil, nil, nil)
	select {
	case <-s.closingCh():
		t.Fatal("closing before Close")
	default:
	}
	s.Close()
	s.Close()
	select {
	case <-s.closingCh():
	default:
		t.Fatal("Close must close the channel every Watch selects on")
	}
}
