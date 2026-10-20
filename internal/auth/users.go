package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ids"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

// ErrRefused is wrapped by *RefusedError: a request the caller can fix.
var ErrRefused = errors.New("request refused")

// RefusedError lists every problem of a user management request at once.
type RefusedError struct{ Reasons []string }

func (e *RefusedError) Error() string { return "request refused: " + strings.Join(e.Reasons, "; ") }

func (e *RefusedError) Unwrap() error { return ErrRefused }

func refused(format string, args ...any) error {
	return &RefusedError{Reasons: []string{fmt.Sprintf(format, args...)}}
}

// NewUserRequest creates a user with password, TOTP secret and recovery
// codes. Who needs user.manage (init runs as the console).
type NewUserRequest struct {
	Username      string
	Password      string
	InstanceAdmin bool
	Roles         []authz.Binding
	// Draft, if set, is the second factor made beforehand (init); nil = a
	// new secret and new recovery codes.
	Draft *Draft
	Who   keys.Who
}

// CreateUser stores the user and returns the enrollment to show once: the
// TOTP secret is fixed now, so the first code – at init on the console, or
// at the first login – only confirms it (no window in which somebody else
// could set up their own authenticator).
func (s *Service) CreateUser(ctx context.Context, req NewUserRequest) (*Enrollment, error) {
	now := s.now()
	if err := s.authorize(ctx, req.Who, "user.create", ""); err != nil {
		return nil, err
	}
	q := systemdb.New(s.System)
	var reasons []string
	if err := CheckUsername(req.Username); err != nil {
		reasons = append(reasons, err.Error())
	} else if _, found, err := s.userByName(ctx, q, req.Username); err != nil {
		return nil, err
	} else if found {
		reasons = append(reasons, fmt.Sprintf("the user name %q is taken", req.Username))
	}
	var pe *PolicyError
	if err := CheckPassword(req.Username, req.Password); errors.As(err, &pe) {
		reasons = append(reasons, pe.Reasons...)
	}
	rp, err := s.checkBindings(ctx, q, req.Roles)
	if err != nil {
		return nil, err
	}
	reasons = append(reasons, rp...)
	if len(reasons) > 0 {
		return nil, &RefusedError{Reasons: reasons}
	}

	hash, err := s.Hasher.Hash(ctx, req.Password)
	if err != nil {
		return nil, err
	}
	id, err := ids.New("usr", now, s.Rand)
	if err != nil {
		return nil, err
	}
	draft := req.Draft
	if draft == nil {
		if draft, err = s.NewDraft(req.Username); err != nil {
			return nil, err
		}
		defer draft.Clear()
	}
	sealed, err := s.Key.sealTOTP(s.Rand, id, draft.secret)
	if err != nil {
		return nil, err
	}
	enr := *draft.Enrollment
	enr.UserID = id
	admin := int64(0)
	if req.InstanceAdmin {
		admin = 1
	}
	err = s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		if terr := q.InsertUser(ctx, systemdb.InsertUserParams{
			ID: id, Username: req.Username, PasswordHash: hash, PasswordChangedAt: formatTime(now), TotpSecret: sealed,
			InstanceAdmin: admin, CreatedAt: formatTime(now), UpdatedAt: formatTime(now),
		}); terr != nil {
			return terr
		}
		for _, b := range req.Roles {
			if terr := q.SetRoleBinding(ctx, bindingParams(id, b, req.Who, now)); terr != nil {
				return terr
			}
		}
		if terr := s.storeRecoveryCodes(ctx, q, id, enr.RecoveryCodes, now); terr != nil {
			return terr
		}
		if draft.confirmedStep > 0 {
			n, terr := q.UseTOTPStep(ctx, systemdb.UseTOTPStepParams{
				TotpLastStep: draft.confirmedStep, TotpConfirmedAt: sql.NullString{String: formatTime(now), Valid: true},
				UpdatedAt: formatTime(now), ID: id, TotpLastStep_2: draft.confirmedStep,
			})
			if terr != nil || n != 1 {
				return errors.Join(errors.New("confirm the authenticator"), terr)
			}
		}
		return s.enqueueTarget(ctx, tx, req.Who, "user.create", id, map[string]any{
			"username": req.Username, "instance_admin": req.InstanceAdmin, "roles": bindingNames(req.Roles),
			"totp_confirmed": draft.confirmedStep > 0,
		})
	})
	if err != nil {
		return nil, err
	}
	return &enr, nil
}

// ConfirmTOTP confirms the authenticator of a new user right away (init on
// the console asks for the first code).
func (s *Service) ConfirmTOTP(ctx context.Context, userID, code string, who keys.Who) error {
	now := s.now()
	if err := s.authorize(ctx, who, "user.totp_confirm", userID); err != nil {
		return err
	}
	return s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		u, err := q.GetUser(ctx, userID)
		if err != nil {
			return err
		}
		ok, _, err := s.useTOTP(ctx, q, u, code, now)
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalidCode
		}
		return s.enqueueTarget(ctx, tx, who, "user.totp_confirm", u.ID, map[string]any{"username": u.Username})
	})
}

// SetRole gives a user a role in a tenant (optionally one CA). The user's
// sessions end: new rights only with a new session (security.md).
func (s *Service) SetRole(ctx context.Context, userID string, b authz.Binding, who keys.Who) error {
	now := s.now()
	if err := s.authorize(ctx, who, "user.role_set", userID); err != nil {
		return err
	}
	q := systemdb.New(s.System)
	if _, err := s.user(ctx, q, userID); err != nil {
		return err
	}
	reasons, err := s.checkBindings(ctx, q, []authz.Binding{b})
	if err != nil {
		return err
	}
	if len(reasons) > 0 {
		return &RefusedError{Reasons: reasons}
	}
	return s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		if b.CA == "" && b.Role != authz.Admin {
			if err := s.keepLastAdmins(ctx, q, userID, false, b.Tenant); err != nil {
				return err
			}
		}
		if err := q.SetRoleBinding(ctx, bindingParams(userID, b, who, now)); err != nil {
			return err
		}
		n, err := q.DeleteUserSessions(ctx, userID)
		if err != nil {
			return err
		}
		return s.enqueueTarget(ctx, tx, who, "user.role_set", userID, map[string]any{"role": bindingNames([]authz.Binding{b})[0], "sessions_ended": n})
	})
}

// RemoveRole takes a role away; the user's sessions end.
func (s *Service) RemoveRole(ctx context.Context, userID, tenant, ca string, who keys.Who) error {
	if err := s.authorize(ctx, who, "user.role_remove", userID); err != nil {
		return err
	}
	return s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		if ca == "" {
			if err := s.keepLastAdmins(ctx, q, userID, false, tenant); err != nil {
				return err
			}
		}
		n, err := q.DeleteRoleBinding(ctx, systemdb.DeleteRoleBindingParams{UserID: userID, TenantID: tenant, Ca: ca})
		if err != nil {
			return err
		}
		if n == 0 {
			return refused("the user has no role in tenant %q for CA %q", tenant, ca)
		}
		ended, err := q.DeleteUserSessions(ctx, userID)
		if err != nil {
			return err
		}
		return s.enqueueTarget(ctx, tx, who, "user.role_remove", userID, map[string]any{"tenant": tenant, "ca": ca, "sessions_ended": ended})
	})
}

// DisableUser disables a user for good (users are never deleted: their ID is
// in the audit log) and ends their sessions. Nobody disables themselves.
func (s *Service) DisableUser(ctx context.Context, userID string, who keys.Who) error {
	now := s.now()
	if err := s.authorize(ctx, who, "user.disable", userID); err != nil {
		return err
	}
	if who.Principal != nil && who.Principal.UserID == userID {
		return refused("you can't disable your own account")
	}
	return s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		u, err := s.user(ctx, q, userID)
		if err != nil {
			return err
		}
		if u.DisabledAt.Valid {
			return refused("user %q is disabled already", u.Username)
		}
		if kerr := s.keepLastAdmins(ctx, q, userID, true, ""); kerr != nil {
			return kerr
		}
		if serr := q.SetDisabled(ctx, systemdb.SetDisabledParams{DisabledAt: sql.NullString{String: formatTime(now), Valid: true}, UpdatedAt: formatTime(now), ID: userID}); serr != nil {
			return serr
		}
		n, err := q.DeleteUserSessions(ctx, userID)
		if err != nil {
			return err
		}
		return s.enqueueTarget(ctx, tx, who, "user.disable", userID, map[string]any{"username": u.Username, "sessions_ended": n})
	})
}

// ResetTOTP gives a user a new TOTP secret and new recovery codes and ends
// their sessions. The user confirms the secret at the next login – only this
// secret works, so there is no window for anybody else. Used by admins and
// by myownpki user reset-2fa (lost phone, lost auth key).
func (s *Service) ResetTOTP(ctx context.Context, username string, who keys.Who) (*Enrollment, error) {
	now := s.now()
	if err := s.authorize(ctx, who, "user.totp_reset", username); err != nil {
		return nil, err
	}
	q := systemdb.New(s.System)
	u, found, err := s.userByName(ctx, q, username)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, refused("there is no user %q", username)
	}
	secret, err := newTOTPSecret(s.Rand)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	sealed, err := s.Key.sealTOTP(s.Rand, u.ID, secret)
	if err != nil {
		return nil, err
	}
	enr := newEnrollment(s.issuer(), u.ID, u.Username, secret)
	err = s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		if terr := q.ResetTOTP(ctx, systemdb.ResetTOTPParams{TotpSecret: sealed, UpdatedAt: formatTime(now), ID: u.ID}); terr != nil {
			return terr
		}
		var terr error
		if enr.RecoveryCodes, terr = s.replaceRecoveryCodes(ctx, q, u.ID, now); terr != nil {
			return terr
		}
		n, terr := q.DeleteUserSessions(ctx, u.ID)
		if terr != nil {
			return terr
		}
		// The lost device may be a security key: only the new secret works.
		passkeys, terr := q.DeleteUserPasskeys(ctx, u.ID)
		if terr != nil {
			return terr
		}
		return s.enqueueTarget(ctx, tx, who, "user.totp_reset", u.ID, map[string]any{"username": u.Username, "sessions_ended": n, "passkeys_removed": passkeys})
	})
	if err != nil {
		return nil, err
	}
	return enr, nil
}

// Unlock ends a lockout early (myownpki user unlock on the console).
func (s *Service) Unlock(ctx context.Context, username string, who keys.Who) error {
	now := s.now()
	if err := s.authorize(ctx, who, "user.unlock", username); err != nil {
		return err
	}
	err := s.inTx(ctx, func(q *systemdb.Queries, tx *sql.Tx) error {
		u, found, err := s.userByName(ctx, q, username)
		if err != nil {
			return err
		}
		if !found {
			return refused("there is no user %q", username)
		}
		if err := q.SetLoginFailures(ctx, systemdb.SetLoginFailuresParams{FailedLogins: 0, UpdatedAt: formatTime(now), ID: u.ID}); err != nil {
			return err
		}
		// An unlock often follows a compromise: devices signed in before
		// lose their trust (device cookies, owner 2026-10-17).
		if err := q.BumpCredentialsEpoch(ctx, systemdb.BumpCredentialsEpochParams{UpdatedAt: formatTime(now), ID: u.ID}); err != nil {
			return err
		}
		return s.enqueueTarget(ctx, tx, who, "user.unlock", u.ID, map[string]any{
			"username": u.Username, "was_locked": lockedFor(u, now) > 0, "failures": u.FailedLogins,
		})
	})
	if err != nil {
		return err
	}
	s.Throttle.Forget(username)
	return nil
}

// keepLastAdmins refuses a change that would leave the instance without an
// active instance admin or a tenant without an active tenant-wide admin –
// also when another admin asks (owner 2026-10-15). disabling: the user is
// about to be disabled (all their admin roles count); otherwise only the
// tenant-wide admin role in tenant is about to go. It runs in the
// transaction of the change, so two admins can't remove each other at once.
func (s *Service) keepLastAdmins(ctx context.Context, q *systemdb.Queries, userID string, disabling bool, tenant string) error {
	u, err := s.user(ctx, q, userID)
	if err != nil || u.DisabledAt.Valid {
		return err // a disabled user is nobody's last admin
	}
	if disabling && u.InstanceAdmin == 1 {
		n, cerr := q.CountOtherActiveInstanceAdmins(ctx, u.ID)
		if cerr != nil {
			return cerr
		}
		if n == 0 {
			return refused("%q is the last active instance admin – make another user instance admin first", u.Username)
		}
	}
	bindings, err := q.ListRoleBindings(ctx, u.ID)
	if err != nil {
		return err
	}
	for _, b := range bindings {
		if b.Ca != "" || b.Role != string(authz.Admin) || (!disabling && b.TenantID != tenant) {
			continue
		}
		n, cerr := q.CountOtherActiveTenantAdmins(ctx, systemdb.CountOtherActiveTenantAdminsParams{TenantID: b.TenantID, UserID: u.ID})
		if cerr != nil {
			return cerr
		}
		if n == 0 {
			return refused("%q is the last active admin of tenant %q – give another user the admin role there first", u.Username, b.TenantID)
		}
	}
	return nil
}

// authorize: user management needs user.manage with a fresh second factor
// (the console passes). A refusal is audited as denied.
func (s *Service) authorize(ctx context.Context, who keys.Who, action, target string) error {
	err := who.Principal.Check(authz.ManageUsers, authz.Resource{}, s.now())
	if err == nil {
		return nil
	}
	if aerr := s.directWho(ctx, who, action, target, audit.ResultDenied, map[string]any{"reason": err.Error()}); aerr != nil {
		return errors.Join(err, aerr)
	}
	return err
}

func (s *Service) user(ctx context.Context, q *systemdb.Queries, id string) (systemdb.User, error) {
	u, err := q.GetUser(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return u, refused("there is no user with the ID %q", id)
	}
	return u, err
}

// checkBindings: valid roles in existing tenants.
func (s *Service) checkBindings(ctx context.Context, q *systemdb.Queries, bs []authz.Binding) ([]string, error) {
	var reasons []string
	for _, b := range bs {
		if !authz.ValidRole(b.Role) {
			reasons = append(reasons, fmt.Sprintf("unknown role %q (viewer, operator or admin)", b.Role))
		}
		if _, err := q.GetTenant(ctx, b.Tenant); errors.Is(err, sql.ErrNoRows) {
			reasons = append(reasons, fmt.Sprintf("there is no tenant %q", b.Tenant))
		} else if err != nil {
			return nil, err
		}
	}
	return reasons, nil
}

func bindingParams(userID string, b authz.Binding, who keys.Who, now time.Time) systemdb.SetRoleBindingParams {
	return systemdb.SetRoleBindingParams{UserID: userID, TenantID: b.Tenant, Ca: b.CA, Role: string(b.Role), CreatedAt: formatTime(now), CreatedBy: who.Actor.Name}
}

// bindingNames writes bindings as "tenant:role" or "tenant/ca:role".
func bindingNames(bs []authz.Binding) []string {
	out := make([]string, 0, len(bs))
	for _, b := range bs {
		scope := b.Tenant
		if b.CA != "" {
			scope += "/" + b.CA
		}
		out = append(out, scope+":"+string(b.Role))
	}
	return out
}

// selfWho is the user acting on their own account.
func selfWho(u systemdb.User, ip string) keys.Who {
	return keys.Who{Actor: audit.Actor{Type: audit.ActorUser, ID: u.ID, Name: u.Username}, SourceIP: ip}
}

// enqueue writes the audit event of a change to u into the outbox of the
// same transaction.
func (s *Service) enqueue(ctx context.Context, tx *sql.Tx, who keys.Who, action string, u systemdb.User, details map[string]any) error {
	return s.enqueueTarget(ctx, tx, who, action, u.ID, details)
}

func (s *Service) enqueueTarget(ctx context.Context, tx *sql.Tx, who keys.Who, action, userID string, details map[string]any) error {
	return audit.Enqueue(ctx, tx, s.now(), audit.Entry{
		Time: s.now(), Actor: who.Actor, Action: action, Target: audit.Target{Type: "user", ID: userID},
		Result: audit.ResultSuccess, SourceIP: who.SourceIP, Details: details,
	})
}

// directWho appends a refusal by an administrator.
func (s *Service) directWho(ctx context.Context, who keys.Who, action, target string, result audit.Result, details map[string]any) error {
	_, _, err := audit.Append(ctx, s.Audit, store.InstanceScope, audit.Entry{
		Time: s.now(), Actor: who.Actor, Action: action, Target: audit.Target{Type: "user", ID: short(target)},
		Result: result, SourceIP: who.SourceIP, Details: details,
	}, "")
	return err
}

// short caps a caller-supplied value for the audit log.
func short(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}
