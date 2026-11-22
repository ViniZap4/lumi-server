package wsync

import (
	"encoding/json"

	"github.com/google/uuid"
)

// awarenessTracker records what a subscriber announced over awareness so
// its entries can be retired when it leaves.
type awarenessTracker struct{}

// broadcastPresenceLeave emits a synthetic awareness frame signalling
// that the subscriber's legacy presence identity has departed.
func (r *Room) broadcastPresenceLeave(sub *Subscriber) {
	if sub.ClientID == uuid.Nil {
		return
	}
	payload, err := json.Marshal(struct {
		ClientID    string `json:"client_id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Color       string `json:"color"`
		Left        bool   `json:"left"`
	}{ClientID: sub.ClientID.String(), Left: true})
	if err != nil {
		return
	}
	r.broadcast(EncodeAwareness(payload), nil)
}
