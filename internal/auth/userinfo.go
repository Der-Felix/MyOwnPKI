package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// UserInfo is a user as an instance admin sees it (step 18): no secrets.
type UserInfo struct {
	ID, Username  string
	InstanceAdmin bool
	Disabled      bool
	LockedUntil   time.Time // zero = not locked
	TOTPConfirmed bool
	Passkeys      int
	Roles         []authz.Binding
	CreatedAt     time.Time
}

// ErrNoUser: no user with this ID.
var ErrNoUser = errors.New("no such user")

// canSeeUsers: reading users needs an instance admin (no step-up – it
// changes nothing) or the console.
func canSeeUsers(who keys.Who) error {
	p := who.Principal
	switch {
	case p == nil:
		return authz.ErrDenied
	case p.Kind == authz.KindConsole || p.Kind == authz.KindSystem || p.InstanceAdmin:
		return nil
	}
	return errors.Join(authz.ErrDenied, errors.New("only instance admins see the users"))
}

// ListUsers lists every user.
func (s *Service) ListUsers(ctx context.Context, who keys.Who) ([]UserInfo, error) {
	if err := canSeeUsers(who); err != nil {
		return nil, err
	}
	q := systemdb.New(s.System)
	rows, err := q.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]UserInfo, 0, len(rows))
	for _, u := range rows {
		info, ierr := s.userInfo(ctx, q, u)
		if ierr != nil {
			return nil, ierr
		}
		out = append(out, *info)
	}
	return out, nil
}

// UserByID returns one user.
func (s *Service) UserByID(ctx context.Context, who keys.Who, id string) (*UserInfo, error) {
	if err := canSeeUsers(who); err != nil {
		return nil, err
	}
	q := systemdb.New(s.System)
	u, err := q.GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoUser
	}
	if err != nil {
		return nil, err
	}
	return s.userInfo(ctx, q, u)
}

func (s *Service) userInfo(ctx context.Context, q *systemdb.Queries, u systemdb.User) (*UserInfo, error) {
	info := &UserInfo{ID: u.ID, Username: u.Username, InstanceAdmin: u.InstanceAdmin == 1, Disabled: u.DisabledAt.Valid,
		TOTPConfirmed: u.TotpConfirmedAt.Valid, CreatedAt: parseTime(u.CreatedAt), Roles: []authz.Binding{}}
	if wait := lockedFor(u, s.now()); wait > 0 {
		info.LockedUntil = parseTime(u.LockedUntil.String)
	}
	n, err := q.CountPasskeys(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	info.Passkeys = int(n)
	bs, err := q.ListRoleBindings(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	for _, b := range bs {
		info.Roles = append(info.Roles, authz.Binding{Tenant: b.TenantID, CA: b.Ca, Role: authz.Role(b.Role)})
	}
	return info, nil
}

// EnableUser lets a disabled user sign in again.
func (s *Service) EnableUser(ctx context.Context, userID string, who keys.Who) error {
	now := s.now()
	if err := s.authorize(ctx, who, "user.enable", userID); err != nil {
		return err
	}
	return s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		u, err := s.user(ctx, q, userID)
		if err != nil {
			return err
		}
		if !u.DisabledAt.Valid {
			return refused("user %q is not disabled", u.Username)
		}
		if serr := q.SetDisabled(ctx, systemdb.SetDisabledParams{DisabledAt: sql.NullString{}, UpdatedAt: formatTime(now), ID: userID}); serr != nil {
			return serr
		}
		return s.enqueueTarget(ctx, tx, who, "user.enable", userID, map[string]any{"username": u.Username})
	})
}

// UnlockByID ends a lockout early, like `myownpki user unlock`.
func (s *Service) UnlockByID(ctx context.Context, userID string, who keys.Who) error {
	u, err := systemdb.New(s.System).GetUser(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoUser
	}
	if err != nil {
		return err
	}
	return s.Unlock(ctx, u.Username, who)
}

// SetRoles replaces the roles of a user in one tenant: missing ones are
// added, others removed. The user's sessions end (by SetRole/RemoveRole).
func (s *Service) SetRoles(ctx context.Context, userID, tenant string, want []authz.Binding, who keys.Who) error {
	if err := s.authorize(ctx, who, "user.role_set", userID); err != nil {
		return err
	}
	q := systemdb.New(s.System)
	if _, err := s.user(ctx, q, userID); err != nil {
		return err
	}
	have, err := q.ListRoleBindings(ctx, userID)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, b := range want {
		b.Tenant = tenant
		keep[b.CA] = true
		if err := s.SetRole(ctx, userID, b, who); err != nil {
			return err
		}
	}
	for _, h := range have {
		if h.TenantID == tenant && !keep[h.Ca] {
			if err := s.RemoveRole(ctx, userID, tenant, h.Ca, who); err != nil {
				return err
			}
		}
	}
	return nil
}
