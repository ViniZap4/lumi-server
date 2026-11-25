// Publish mirrors, phase M3 (docs/SPEC-ESPELHO-SELADO.md §A15).
//
// A publish mirror is a mirror link whose invite carried a publish policy
// (owner consent: vault.federate + vault.manage). Home filters, not the
// mirror: on such a link home relays only the notes in scope, and the
// mirror never learns that anything else exists. Every outbound frame goes
// through the session's published set:
//
//   - opening: the manifest lists in-scope notes only (no incremental
//     resume: the change log would name out-of-scope ids in tombstones);
//   - Step1 for an id outside the set gets no answer;
//   - live updates, moves and deletes go out only for ids in the set;
//   - a note entering the scope (frontmatter flag set, moved into the
//     folder, created in scope) gets announce + noteMeta2 + full state;
//     one leaving it gets a delete;
//   - the control state is a minimised copy re-signed by home: the vault
//     name, the roles and only the members of the publish server itself.
package federation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// Publish scopes.
const (
	PublishScopeFlagged = "flagged"
	PublishScopeAll     = "all"
	publishFolderPrefix = "folder:"
)

// PublishPolicy is the owner's consent to publish a subset of the book
// anonymously from a mirror (invite body "publish", stored on the invite
// and on both link rows).
type PublishPolicy struct {
	Allowed bool `json:"allowed"`
	// Scope: "flagged" (notes whose frontmatter has publish: true; the
	// default), "folder:<prefix>" or "all".
	Scope string `json:"scope"`
	// Index lets search engines index the published pages (the mirror
	// sends X-Robots-Tag: noindex otherwise).
	Index bool `json:"index,omitempty"`
}

// Normalize validates the policy and fills the default scope. A policy
// with allowed=false is refused: absent means "not a publish mirror".
func (p PublishPolicy) Normalize() (PublishPolicy, error) {
	if !p.Allowed {
		return PublishPolicy{}, fmt.Errorf("%w: publish.allowed must be true (omit publish for a private mirror)", domain.ErrValidation)
	}
	switch {
	case p.Scope == "":
		p.Scope = PublishScopeFlagged
	case p.Scope == PublishScopeFlagged, p.Scope == PublishScopeAll:
	case strings.HasPrefix(p.Scope, publishFolderPrefix):
		prefix := strings.Trim(strings.TrimPrefix(p.Scope, publishFolderPrefix), "/")
		if prefix == "" || len(prefix) > 1024 || strings.ContainsAny(prefix, "\\\x00") {
			return PublishPolicy{}, fmt.Errorf("%w: invalid publish folder", domain.ErrValidation)
		}
		for _, seg := range strings.Split(prefix, "/") {
			if seg == "" || seg == "." || seg == ".." || strings.HasPrefix(seg, ".") {
				return PublishPolicy{}, fmt.Errorf("%w: invalid publish folder", domain.ErrValidation)
			}
		}
		p.Scope = publishFolderPrefix + prefix
	default:
		return PublishPolicy{}, fmt.Errorf("%w: publish.scope must be flagged, all or folder:<prefix>", domain.ErrValidation)
	}
	return p, nil
}

// NeedsFrontmatter reports whether Match reads the frontmatter.
func (p PublishPolicy) NeedsFrontmatter() bool { return p.Scope == PublishScopeFlagged }

// Match reports whether a note is in scope. frontmatterJSON is the note's
// replicated frontmatter (only read for the flagged scope; canvas notes
// have none, so they are never flagged).
func (p PublishPolicy) Match(path string, frontmatterJSON []byte) bool {
	if !p.Allowed {
		return false
	}
	switch {
	case p.Scope == PublishScopeAll:
		return true
	case strings.HasPrefix(p.Scope, publishFolderPrefix):
		return strings.HasPrefix(path, strings.TrimPrefix(p.Scope, publishFolderPrefix)+"/")
	case p.Scope == PublishScopeFlagged:
		return FlaggedForPublish(frontmatterJSON)
	}
	return false
}

// FlaggedForPublish reports whether a frontmatter JSON object carries
// publish: true (a YAML boolean; strings do not count).
func FlaggedForPublish(frontmatterJSON []byte) bool {
	if len(frontmatterJSON) == 0 {
		return false
	}
	var fm map[string]json.RawMessage
	if err := json.Unmarshal(frontmatterJSON, &fm); err != nil {
		return false
	}
	return bytes.Equal(bytes.TrimSpace(fm["publish"]), []byte("true"))
}

// MarshalPublish encodes a policy for a JSONB column (nil → NULL).
func MarshalPublish(p *PublishPolicy) []byte {
	if p == nil {
		return nil
	}
	b, _ := json.Marshal(p)
	return b
}

// UnmarshalPublish decodes a JSONB column (NULL or invalid → nil).
func UnmarshalPublish(b []byte) *PublishPolicy {
	if len(b) == 0 {
		return nil
	}
	var p PublishPolicy
	if err := json.Unmarshal(b, &p); err != nil || !p.Allowed {
		return nil
	}
	return &p
}

// ---- session side (home) -------------------------------------------------------

// noteInScope evaluates the policy against the note's current row and
// frontmatter. Errors count as out of scope (fail closed).
func (s *Session) noteInScope(noteID string) (NoteMeta, bool) {
	n, err := s.deps.Notes.Get(s.ctx, s.vaultID, noteID)
	if err != nil {
		return NoteMeta{}, false
	}
	m := NoteMeta{ID: n.ID, Path: n.Path, Title: n.Title, Epoch: n.CRDTEpoch}
	var fm []byte
	if s.publish.NeedsFrontmatter() {
		if s.deps.Frontmatter == nil {
			return m, false
		}
		if fm, err = s.deps.Frontmatter(s.ctx, s.vaultID, noteID); err != nil {
			return m, false
		}
	}
	return m, s.publish.Match(n.Path, fm)
}

// publishScope keeps the in-scope notes of a listing and records them as
// the mirror's set.
func (s *Session) publishScope(metas []NoteMeta) []NoteMeta {
	out := metas[:0:0]
	for _, m := range metas {
		if _, ok := s.noteInScope(m.ID); ok {
			out = append(out, m)
		}
	}
	s.pubMu.Lock()
	s.published = make(map[string]bool, len(out))
	for _, m := range out {
		s.published[m.ID] = true
	}
	s.pubMu.Unlock()
	return out
}

func (s *Session) isPublished(noteID string) bool {
	s.pubMu.Lock()
	defer s.pubMu.Unlock()
	return s.published[noteID]
}

func (s *Session) setPublished(noteID string, on bool) (was bool) {
	s.pubMu.Lock()
	defer s.pubMu.Unlock()
	was = s.published[noteID]
	if on {
		s.published[noteID] = true
	} else {
		delete(s.published, noteID)
	}
	return was
}

// publishSync re-evaluates one note after a create, move or metadata
// change and sends what the publish mirror needs: enter (announce +
// meta2 + full state), leave (delete), or the change itself (move /
// meta2) for a note that stays in scope.
func (s *Session) publishSync(noteID string, moved bool) {
	m, in := s.noteInScope(noteID)
	was := s.setPublished(noteID, in)
	switch {
	case in && !was:
		s.publishEnter(m)
	case !in && was:
		s.send(EncodeNoteDelete(noteID))
	case in && was:
		if moved {
			s.send(EncodeNoteMove(NoteMeta{ID: m.ID, Path: m.Path, Title: m.Title}))
		}
		if s.speaksV2() {
			if frame := s.links.meta2Frame(s.vaultID, m); frame != nil {
				s.send(frame)
			}
		}
	}
}

func (s *Session) publishEnter(m NoteMeta) {
	state, err := s.withDoc(m.ID, func(doc *crdt.Doc) ([]byte, error) { return doc.EncodeStateAsUpdate() })
	if err != nil {
		s.setPublished(m.ID, false)
		return
	}
	s.send(EncodeNoteAnnounce(m))
	if s.speaksV2() {
		if frame := s.links.meta2Frame(s.vaultID, m); frame != nil {
			s.send(frame)
		}
	}
	s.send(EncodeNoteSync(m.ID, wsync.EncodeSyncUpdate(state)))
}

// publishDelete forwards a deletion only for a note the mirror holds.
func (s *Session) publishDelete(noteID string) {
	if s.setPublished(noteID, false) {
		s.send(EncodeNoteDelete(noteID))
	}
}

// ---- control state for a publish link ------------------------------------------

// ControlStateFor returns the control document for one link. A publish
// mirror gets a minimised copy, re-signed by home with the same seq: the
// name, the roles and only the members of that server (the mirror
// resolves nothing else, and a public-facing server has no business
// holding the member list).
func (s *Service) ControlStateFor(ctx context.Context, vaultID uuid.UUID, peerURL string) (state, sig []byte, ok bool) {
	full, _, ok := s.CurrentControlState(ctx, vaultID)
	if !ok {
		return nil, nil, false
	}
	out, err := MinimizeControl(full, peerURL)
	if err != nil {
		return nil, nil, false
	}
	return out, s.signControl(vaultID, out), true
}

// MinimizeControl keeps the name, seq and roles of a control document and
// only the members keyed "<user>@<peerURL>".
func MinimizeControl(stateJSON []byte, peerURL string) ([]byte, error) {
	var doc ControlState
	if err := json.Unmarshal(stateJSON, &doc); err != nil {
		return nil, err
	}
	peer := normalizeServerURL(peerURL)
	kept := []ControlMember{}
	for _, m := range doc.Members {
		at := strings.LastIndex(m.Key, "@")
		if at > 0 && peer != "" && normalizeServerURL(m.Key[at+1:]) == peer {
			kept = append(kept, m)
		}
	}
	doc.Members = kept
	return json.Marshal(doc)
}

func (s *Service) signControl(vaultID uuid.UUID, stateJSON []byte) []byte {
	return ed25519.Sign(s.priv, controlSigMessage(vaultID, stateJSON))
}
