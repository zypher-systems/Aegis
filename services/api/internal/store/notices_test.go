package store

import "testing"

func TestMergeNoticeReplacesSameResource(t *testing.T) {
	cur := []Notice{{Kind: "acme_renew", ResourceID: "a", Title: "old"}}
	out := MergeNotice(cur, Notice{Kind: "acme_renew", ResourceID: "a", Title: "new"})
	if len(out) != 1 || out[0].Title != "new" {
		t.Fatalf("%+v", out)
	}
	out = MergeNotice(out, Notice{Kind: "acme_renew", ResourceID: "b", Title: "other"})
	if len(out) != 2 {
		t.Fatalf("len=%d", len(out))
	}
	dropped := dropNotice(out, "acme_renew", "a")
	if len(dropped) != 1 || dropped[0].ResourceID != "b" {
		t.Fatalf("%+v", dropped)
	}
}
