package vaults

import (
	"encoding/json"
	"testing"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

func TestDeriveFederationInfo(t *testing.T) {
	enc := func(i FederationInfo) string { b, _ := json.Marshal(i); return string(b) }
	cases := []struct {
		name string
		rows []domain.Federation
		want string
	}{
		{"not federated", nil, `{"role":null,"home_url":null,"status":null}`},
		{"home", []domain.Federation{{Role: "home", PeerURL: "https://f.org", Status: "revoked"}, {Role: "home", PeerURL: "https://g.org", Status: "active"}},
			`{"role":"home","home_url":"https://lumi.work.com","status":"active"}`},
		{"follower prefers active link", []domain.Federation{{Role: "follower", PeerURL: "https://old.org", Status: "revoked"}, {Role: "follower", PeerURL: "https://home.org", Status: "active"}},
			`{"role":"follower","home_url":"https://home.org","status":"active"}`},
		{"severed follower", []domain.Federation{{Role: "follower", PeerURL: "https://home.org", Status: "severed"}},
			`{"role":"follower","home_url":"https://home.org","status":"severed"}`},
	}
	for _, c := range cases {
		if got := enc(deriveFederationInfo(c.rows, "https://lumi.work.com")); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if got := enc(deriveFederationInfo([]domain.Federation{{Role: "home", Status: "active"}}, "")); got != `{"role":"home","home_url":null,"status":"active"}` {
		t.Errorf("home without base url: %s", got)
	}
}
