package federation

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// OperatorUserLookup resolves a local user by id. Implemented by
// *pg.UserStore.
type OperatorUserLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (domain.User, error)
}

// UsernameOperators is the OperatorChecker backed by a configured list of
// local usernames (LUMI_FEDERATION_OPERATORS, defaulting to the bootstrap
// admin). Usernames are immutable and stored lower-case.
type UsernameOperators struct {
	users OperatorUserLookup
	names map[string]struct{}
}

// NewUsernameOperators builds the checker; blank names are ignored. With no
// names every IsOperator call answers false (join disabled).
func NewUsernameOperators(users OperatorUserLookup, names []string) *UsernameOperators {
	set := map[string]struct{}{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" {
			set[n] = struct{}{}
		}
	}
	return &UsernameOperators{users: users, names: set}
}

func (o *UsernameOperators) IsOperator(ctx context.Context, userID uuid.UUID) (bool, error) {
	if o == nil || len(o.names) == 0 || o.users == nil || userID == uuid.Nil {
		return false, nil
	}
	u, err := o.users.GetByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	_, ok := o.names[strings.ToLower(u.Username)]
	return ok, nil
}
