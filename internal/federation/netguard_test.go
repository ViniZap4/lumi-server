package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

func TestValidateServerURL(t *testing.T) {
	cases := []struct {
		raw string
		ok  bool
	}{
		{"https://home.example", true},
		{"https://home.example:8443", true},
		{"http://home.example", true}, // syntax only; policy decides http
		{"https://[2001:4860::1]:443", true},
		{"", false},
		{"not a url", false},
		{"ftp://home.example", false},
		{"https://", false},
		{"https://home.example/api", false},
		{"https://home.example/", false},
		{"https://home.example?x=1", false},
		{"https://home.example?", false},
		{"https://home.example#frag", false},
		{"https://user:pass@home.example", false},
		{"https://user@home.example", false},
		{"https://home.example:0", false},
		{"https://home.example:99999", false},
		{"https://home.example:", false},
		{"https://home.example\\@evil", false},
		{"//home.example", false},
		{"https:home.example", false},
	}
	for _, tc := range cases {
		err := validateServerURL(tc.raw)
		if tc.ok && err != nil {
			t.Errorf("validateServerURL(%q) = %v, want ok", tc.raw, err)
		}
		if !tc.ok && !errors.Is(err, domain.ErrValidation) {
			t.Errorf("validateServerURL(%q) = %v, want ErrValidation", tc.raw, err)
		}
	}
}

func TestNetPolicy_CheckPeerURL_HTTPS(t *testing.T) {
	strict := NetPolicy{}
	if err := strict.CheckPeerURL("http://home.example"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("strict policy must reject http, got %v", err)
	}
	if err := strict.CheckPeerURL("https://home.example"); err != nil {
		t.Fatalf("strict policy must accept https: %v", err)
	}
	dev := NetPolicy{AllowInsecureHTTP: true}
	if err := dev.CheckPeerURL("http://localhost:8080"); err != nil {
		t.Fatalf("dev policy must accept http: %v", err)
	}
}

func TestIsPublicAddr(t *testing.T) {
	cases := []struct {
		ip     string
		public bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"127.10.0.1", false},
		{"::1", false},
		{"10.0.0.1", false},
		{"172.16.5.4", false},
		{"192.168.1.1", false},
		{"169.254.169.254", false}, // cloud metadata
		{"fe80::1", false},
		{"fc00::1", false},
		{"fd12:3456::1", false},
		{"100.64.0.1", false},
		{"0.0.0.0", false},
		{"0.1.2.3", false},
		{"::", false},
		{"224.0.0.1", false},
		{"ff02::1", false},
		{"255.255.255.255", false},
		{"198.18.0.1", false},
		{"::ffff:127.0.0.1", false}, // v4-mapped loopback
		{"::ffff:10.0.0.1", false},
		{"64:ff9b::a00:1", false},  // NAT64 -> 10.0.0.1
		{"64:ff9b::808:808", true}, // NAT64 -> 8.8.8.8
		{"2001:db8::1", false},
	}
	for _, tc := range cases {
		if got := isPublicAddr(netip.MustParseAddr(tc.ip)); got != tc.public {
			t.Errorf("isPublicAddr(%s) = %v, want %v", tc.ip, got, tc.public)
		}
	}
}

func TestNetPolicy_AllowedCIDRs(t *testing.T) {
	cidrs, err := ParseCIDRList("127.0.0.1, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	p := NetPolicy{AllowedCIDRs: cidrs}
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "::ffff:10.1.2.3"} {
		if err := p.checkAddr(netip.MustParseAddr(ip)); err != nil {
			t.Errorf("allowlisted %s rejected: %v", ip, err)
		}
	}
	for _, ip := range []string{"127.0.0.2", "192.168.0.1", "169.254.169.254"} {
		if err := p.checkAddr(netip.MustParseAddr(ip)); !errors.Is(err, errBlockedAddress) {
			t.Errorf("non-allowlisted %s accepted: %v", ip, err)
		}
	}
	if _, err := ParseCIDRList("10.0.0.0/33"); err == nil {
		t.Fatal("bad CIDR must fail")
	}
}

// The guarded client must refuse to connect to loopback after DNS
// resolution (here: a literal 127.0.0.1 httptest server), and must not
// follow redirects even when the target is allowed.
func TestNetPolicy_HTTPClientBlocksInternalAndRedirects(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	strict := NetPolicy{AllowInsecureHTTP: true}
	resp, err := strict.HTTPClient().Get(srv.URL + "/x")
	if err == nil {
		resp.Body.Close()
		t.Fatal("strict policy connected to loopback")
	}
	if !errors.Is(err, errBlockedAddress) {
		t.Fatalf("want errBlockedAddress, got %v", err)
	}
	if hits != 0 {
		t.Fatalf("request reached loopback server")
	}

	// localhost hostname resolves to loopback: still blocked post-DNS.
	localURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	if resp, err := strict.HTTPClient().Get(localURL); err == nil {
		resp.Body.Close()
		t.Fatal("strict policy connected to localhost")
	}

	allowed := NetPolicy{AllowInsecureHTTP: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	resp, err = allowed.HTTPClient().Get(srv.URL + "/redirect")
	if err != nil {
		t.Fatalf("allowlisted loopback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect was followed: status %d", resp.StatusCode)
	}
	if hits != 1 {
		t.Fatalf("redirect target fetched: hits=%d", hits)
	}
}

func TestNetPolicy_WSDialerBlocksInternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	if _, err := (NetPolicy{}).WSDialer()(context.Background(), wsURL); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("strict policy must refuse ws://, got %v", err)
	}
	_, err := (NetPolicy{AllowInsecureHTTP: true}).WSDialer()(context.Background(), wsURL)
	if !errors.Is(err, errBlockedAddress) {
		t.Fatalf("want errBlockedAddress for loopback relay, got %v", err)
	}
}

type fixedOperators map[uuid.UUID]bool

func (f fixedOperators) IsOperator(_ context.Context, id uuid.UUID) (bool, error) { return f[id], nil }

// TestJoin_RequiresOperator is the regression test for any authenticated
// user being able to make the server join (and dial) an arbitrary home.
func TestJoin_RequiresOperator(t *testing.T) {
	op, user := uuid.New(), uuid.New()
	fx := newFedFixture(t, "https://follower.example")
	called := false
	fx.svc.client = &fakeHome{accept: func(AcceptRequest) (AcceptResponse, error) {
		called = true
		return AcceptResponse{}, errors.New("unreachable")
	}}

	fx.svc.operators = nil
	if _, _, err := fx.svc.Join(context.Background(), JoinInput{HomeURL: "https://home.example", Token: "t", Actor: op}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("nil operator checker must deny, got %v", err)
	}
	fx.svc.operators = fixedOperators{op: true}
	if _, _, err := fx.svc.Join(context.Background(), JoinInput{HomeURL: "https://home.example", Token: "t", Actor: user}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-operator must be denied, got %v", err)
	}
	if called {
		t.Fatal("home was contacted for a non-operator join")
	}
	// Operator passes the gate but strict policy still rejects SSRF-shaped URLs.
	for _, bad := range []string{"http://home.example", "https://home.example/x", "https://u:p@home.example"} {
		if _, _, err := fx.svc.Join(context.Background(), JoinInput{HomeURL: bad, Token: "t", Actor: op}); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("join %q: want ErrValidation, got %v", bad, err)
		}
	}
}

type fakeUserLookup map[uuid.UUID]domain.User

func (f fakeUserLookup) GetByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	u, ok := f[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

func TestUsernameOperators(t *testing.T) {
	admin, bob := uuid.New(), uuid.New()
	users := fakeUserLookup{admin: {ID: admin, Username: "admin"}, bob: {ID: bob, Username: "bob"}}
	ops := NewUsernameOperators(users, []string{" Admin ", ""})
	cases := []struct {
		id   uuid.UUID
		want bool
	}{{admin, true}, {bob, false}, {uuid.New(), false}, {uuid.Nil, false}}
	for _, tc := range cases {
		got, err := ops.IsOperator(context.Background(), tc.id)
		if err != nil || got != tc.want {
			t.Errorf("IsOperator(%s) = %v, %v; want %v", tc.id, got, err, tc.want)
		}
	}
	empty := NewUsernameOperators(users, nil)
	if ok, _ := empty.IsOperator(context.Background(), admin); ok {
		t.Fatal("empty operator list must deny everyone")
	}
}
