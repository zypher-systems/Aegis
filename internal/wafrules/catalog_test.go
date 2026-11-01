package wafrules

import "testing"

func TestNormalizeAndValidate(t *testing.T) {
	if NormalizeMode("DETECT") != "detect" {
		t.Fatal("detect")
	}
	if NormalizeMode("") != "block" {
		t.Fatal("default block")
	}
	if NormalizeParanoia(0) != 1 || NormalizeParanoia(9) != 4 {
		t.Fatal("paranoia clamp")
	}
	if NormalizeThreshold(0) != 5 || NormalizeThreshold(200) != 100 {
		t.Fatal("threshold clamp")
	}
	tags := NormalizeDisabledTags([]string{"attack-sqli", "nope", "attack-sqli"})
	if len(tags) != 1 || tags[0] != "attack-sqli" {
		t.Fatalf("normalize tags: %v", tags)
	}
	if err := ValidateDisabledTags([]string{"not-a-tag"}); err == nil {
		t.Fatal("expected unknown tag")
	}
	all := make([]string, 0, len(Packages()))
	for _, p := range Packages() {
		all = append(all, p.Tag)
	}
	if err := ValidateDisabledTags(all); err == nil {
		t.Fatal("expected at least one package")
	}
}
