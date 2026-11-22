package federation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"testing"

	fws "github.com/fasthttp/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

func TestDecodeFrame_ManifestCaps(t *testing.T) {
	// A claimed count far above what the body can hold must be rejected
	// before any allocation proportional to the claim.
	lying := writeVarUint(nil, frameManifest)
	lying = writeVarUint(lying, maxManifestEntries) // within cap, body empty
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := DecodeFrame(lying); err == nil {
		t.Fatal("lying manifest accepted")
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<10 {
		t.Fatalf("lying 7-byte manifest allocated %d bytes; must reject before allocating", grew)
	}

	over := writeVarUint(nil, frameManifest)
	over = writeVarUint(over, maxManifestEntries+1)
	if _, err := DecodeFrame(over); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("over-cap manifest: want errFrameTooLarge, got %v", err)
	}

	ok := EncodeManifest([]NoteMeta{{ID: "a", Path: "a.md", Title: "A"}, {ID: "b", Path: "b.md"}})
	f, err := DecodeFrame(ok)
	if err != nil || len(f.Manifest) != 2 {
		t.Fatalf("valid manifest: %v %+v", err, f)
	}
}

func TestDecodeFrame_FieldAndFrameCaps(t *testing.T) {
	cases := []struct {
		name string
		meta NoteMeta
	}{
		{"long id", NoteMeta{ID: strings.Repeat("i", maxNoteIDBytes+1), Path: "a.md"}},
		{"long path", NoteMeta{ID: "a", Path: strings.Repeat("p", maxNotePathBytes+1)}},
		{"long title", NoteMeta{ID: "a", Path: "a.md", Title: strings.Repeat("t", maxNoteTitleBytes+1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeFrame(EncodeNoteAnnounce(tc.meta)); !errors.Is(err, errFrameTooLarge) {
				t.Fatalf("want errFrameTooLarge, got %v", err)
			}
		})
	}
	huge := make([]byte, maxRelayMessageBytes+1)
	huge[0] = byte(frameNoteSync)
	if _, err := DecodeFrame(huge); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("oversized frame: want errFrameTooLarge, got %v", err)
	}
}

type limitRecordingConn struct {
	nopRelayConn
	limit int64
}

type nopRelayConn struct{}

func (nopRelayConn) ReadMessage() (int, []byte, error) { return 0, nil, errors.New("closed") }
func (nopRelayConn) WriteMessage(int, []byte) error    { return nil }
func (nopRelayConn) Close() error                      { return nil }

func (c *limitRecordingConn) SetReadLimit(n int64) { c.limit = n }

func TestNewSession_SetsReadLimit(t *testing.T) {
	links := &Links{byVault: map[uuid.UUID][]*Session{}, deps: RelayDeps{Log: zerolog.Nop()}, rootCtx: context.Background()}
	conn := &limitRecordingConn{}
	links.NewSession(context.Background(), conn, uuid.New(), "https://peer.example", "home")
	if conn.limit != maxRelayMessageBytes {
		t.Fatalf("read limit = %d, want %d", conn.limit, maxRelayMessageBytes)
	}
}

// The follower's guarded dialer must return a connection that refuses an
// oversized message from a hostile home.
func TestWSDialer_EnforcesReadLimit(t *testing.T) {
	up := fws.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(fws.BinaryMessage, make([]byte, maxRelayMessageBytes+1))
	}))
	defer srv.Close()

	p := NetPolicy{AllowInsecureHTTP: true, AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	conn, err := p.WSDialer()(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, _, err := conn.ReadMessage(); !errors.Is(err, fws.ErrReadLimit) {
		t.Fatalf("want ErrReadLimit, got %v", err)
	}
}
