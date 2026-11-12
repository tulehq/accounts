package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"tule.dev/accounts/internal/contracts"
)

// accountColumns are the columns scanAccount reads, from accounts joined to
// the OU that is its parent, if any. The one parameter is the root's path,
// for an account in the root.
const accountColumns = `a.rowid, a.id, a.name, a.email, a.state, a.joined_method,
	a.joined_at, COALESCE(p.path, ?)
	FROM accounts a LEFT JOIN organizational_units p ON p.id = a.parent_id`

func scanAccount(o *org) func(scanner) (cursored[contracts.Account], error) {
	return func(r scanner) (cursored[contracts.Account], error) {
		var (
			row        int64
			joined     int64
			parentPath string
			a          contracts.Account
		)
		err := r.Scan(&row, &a.ID, &a.Name, &a.Email, &a.State, &a.JoinedMethod, &joined,
			&parentPath)
		a.ARN = o.accountARN(a.ID)
		a.JoinedTimestamp = unstamp(joined)
		a.Paths = []string{parentPath + a.ID + "/"}
		return cursored[contracts.Account]{item: a, cursor: rowCursor(row)}, err
	}
}

// accountRow is what the account operations need to know of an account.
type accountRow struct {
	parentID string
	state    string
}

// loadAccount reads an account's parent and state, failing with
// contracts.ErrAccountNotFound when no member account has the ID.
func loadAccount(ctx context.Context, tx *sql.Tx, accountID string) (*accountRow, error) {
	var a accountRow
	err := tx.QueryRowContext(ctx,
		`SELECT parent_id, state FROM accounts WHERE id = ?`, accountID,
	).Scan(&a.parentID, &a.state)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, contracts.ErrAccountNotFound
	case err != nil:
		return nil, fmt.Errorf("read account: %w", err)
	}
	return &a, nil
}

// CreateAccount creates a member account in the root, at once. The request
// is recorded either way: SUCCEEDED with the new account's ID, or FAILED with
// EMAIL_ALREADY_EXISTS when a member account has the email already, compared
// without regard to case.
func (s *Service) CreateAccount(
	ctx context.Context,
	in contracts.CreateAccountInput,
) (*contracts.CreateAccountStatus, error) {
	// Too many tags fails the request outright, before any account or record
	// exists, as AWS does.
	if len(in.Tags) > contracts.MaxTagsPerResource {
		return nil, contracts.ErrTagLimitExceeded
	}
	roleName := in.RoleName
	if roleName == "" {
		roleName = contracts.DefaultRoleName
	}

	var out *contracts.CreateAccountStatus
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}

		id, err := newRequestID()
		if err != nil {
			return err
		}
		now := s.now()
		status := contracts.CreateAccountStatus{
			ID:                 id,
			AccountName:        in.AccountName,
			RequestedTimestamp: now,
			CompletedTimestamp: now,
			State:              contracts.CreateAccountStateSucceeded,
		}

		taken, err := exists(ctx, tx,
			`SELECT 1 FROM accounts WHERE email = ? COLLATE NOCASE LIMIT 1`, in.Email)
		if err != nil {
			return err
		}
		if taken {
			status.State = contracts.CreateAccountStateFailed
			status.FailureReason = contracts.FailureEmailAlreadyExists
		} else {
			if status.AccountID, err = s.insertAccount(ctx, tx, o, in, roleName); err != nil {
				return err
			}
		}

		if err = insertStatus(ctx, tx, &status); err != nil {
			return err
		}
		out = &status
		return nil
	})
	return out, err
}

// insertAccount stores a new account in the root, with its tags, and returns
// its ID.
func (s *Service) insertAccount(
	ctx context.Context,
	tx *sql.Tx,
	o *org,
	in contracts.CreateAccountInput,
	roleName string,
) (string, error) {
	id, err := s.unusedAccountID(ctx, tx)
	if err != nil {
		return "", err
	}
	if err = exec(ctx, tx,
		`INSERT INTO accounts
		 (id, name, email, parent_id, state, joined_method, joined_at, role_name)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, in.AccountName, in.Email, o.rootID, contracts.AccountStateActive,
		contracts.JoinedMethodCreated, stamp(s.now()), roleName,
	); err != nil {
		return "", err
	}
	if err = putTags(ctx, tx, id, in.Tags); err != nil {
		return "", err
	}
	return id, nil
}

// maxIDAttempts bounds the draws for an account ID no member account has. A
// collision among 10^12 IDs is already unlikely; several in a row mean
// something is wrong with the random source.
const maxIDAttempts = 5

func (s *Service) unusedAccountID(ctx context.Context, tx *sql.Tx) (string, error) {
	for range maxIDAttempts {
		id, err := newAccountID()
		if err != nil {
			return "", err
		}
		if id == s.settings.ManagementAccountID {
			continue
		}
		taken, err := exists(ctx, tx, `SELECT 1 FROM accounts WHERE id = ? LIMIT 1`, id)
		if err != nil {
			return "", err
		}
		if !taken {
			return id, nil
		}
	}
	return "", fmt.Errorf("no unused account ID after %d attempts", maxIDAttempts)
}

func insertStatus(ctx context.Context, tx *sql.Tx, st *contracts.CreateAccountStatus) error {
	return exec(ctx, tx,
		`INSERT INTO create_account_statuses
		 (id, account_name, state, failure_reason, account_id, requested_at, completed_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		st.ID, st.AccountName, st.State, nullable(st.FailureReason), nullable(st.AccountID),
		stamp(st.RequestedTimestamp), stamp(st.CompletedTimestamp))
}

// nullable stores an empty string as NULL, for the columns that are only set
// in one outcome.
func nullable(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

const statusColumns = `rowid, id, account_name, state, failure_reason, account_id,
	requested_at, completed_at FROM create_account_statuses`

func scanStatus(r scanner) (cursored[contracts.CreateAccountStatus], error) {
	var (
		row                  int64
		st                   contracts.CreateAccountStatus
		reason, accountID    sql.NullString
		requested, completed int64
	)
	err := r.Scan(&row, &st.ID, &st.AccountName, &st.State, &reason, &accountID,
		&requested, &completed)
	st.FailureReason = reason.String
	st.AccountID = accountID.String
	st.RequestedTimestamp = unstamp(requested)
	st.CompletedTimestamp = unstamp(completed)
	return cursored[contracts.CreateAccountStatus]{item: st, cursor: rowCursor(row)}, err
}

// DescribeCreateAccountStatus returns the record of one CreateAccount
// request.
func (s *Service) DescribeCreateAccountStatus(
	ctx context.Context,
	requestID string,
) (*contracts.CreateAccountStatus, error) {
	var out *contracts.CreateAccountStatus
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := loadOrg(ctx, tx); err != nil {
			return err
		}
		st, err := scanStatus(tx.QueryRowContext(ctx,
			`SELECT `+statusColumns+` WHERE id = ?`, requestID))
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return contracts.ErrCreateAccountStatusNotFound
		case err != nil:
			return fmt.Errorf("read create account status: %w", err)
		}
		out = &st.item
		return nil
	})
	return out, err
}

// ListCreateAccountStatus lists the CreateAccount records in the order the
// requests were made, keeping only those in in.States when it is not empty.
func (s *Service) ListCreateAccountStatus(
	ctx context.Context,
	in contracts.ListCreateAccountStatusInput,
) (*contracts.Page[contracts.CreateAccountStatus], error) {
	states := slices.Clone(in.States)
	slices.Sort(states)
	states = slices.Compact(states)
	scope := strings.Join(states, ",")

	var out *contracts.Page[contracts.CreateAccountStatus]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		after, err := decodeRowToken(in.Page.NextToken, o.id, listStatuses, scope)
		if err != nil {
			return err
		}

		size := pageSize(in.Page.MaxResults)
		query := `SELECT ` + statusColumns + ` WHERE rowid > ?`
		args := []any{after}
		if len(states) > 0 {
			query += ` AND state IN (?` + strings.Repeat(", ?", len(states)-1) + `)`
			for _, st := range states {
				args = append(args, st)
			}
		}
		query += ` ORDER BY rowid LIMIT ?`
		args = append(args, size+1)

		rows, err := queryAll(ctx, tx, scanStatus, query, args...)
		if err != nil {
			return err
		}
		out = paginate(rows, size, o.id, listStatuses, scope)
		return nil
	})
	return out, err
}

// DescribeAccount describes a member account.
func (s *Service) DescribeAccount(
	ctx context.Context,
	accountID string,
) (*contracts.Account, error) {
	var out *contracts.Account
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		rows, err := queryAll(ctx, tx, scanAccount(o),
			`SELECT `+accountColumns+` WHERE a.id = ?`, o.rootPath(), accountID)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return contracts.ErrAccountNotFound
		}
		out = &rows[0].item
		return nil
	})
	return out, err
}

// ListAccounts lists every member account, closed ones included, in the order
// they joined.
func (s *Service) ListAccounts(
	ctx context.Context,
	page contracts.PageInput,
) (*contracts.Page[contracts.Account], error) {
	var out *contracts.Page[contracts.Account]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		after, err := decodeRowToken(page.NextToken, o.id, listAccounts, "")
		if err != nil {
			return err
		}

		size := pageSize(page.MaxResults)
		rows, err := queryAll(ctx, tx, scanAccount(o),
			`SELECT `+accountColumns+` WHERE a.rowid > ? ORDER BY a.rowid LIMIT ?`,
			o.rootPath(), after, size+1)
		if err != nil {
			return err
		}
		out = paginate(rows, size, o.id, listAccounts, "")
		return nil
	})
	return out, err
}

// ListAccountsForParent lists the accounts directly under a root or OU, in
// the order they joined.
func (s *Service) ListAccountsForParent(
	ctx context.Context,
	parentID string,
	page contracts.PageInput,
) (*contracts.Page[contracts.Account], error) {
	var out *contracts.Page[contracts.Account]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		after, err := decodeRowToken(page.NextToken, o.id, listAccountsParent, parentID)
		if err != nil {
			return err
		}
		if _, err = requireParent(ctx, tx, o, parentID, contracts.ErrParentNotFound); err != nil {
			return err
		}

		size := pageSize(page.MaxResults)
		rows, err := queryAll(ctx, tx, scanAccount(o),
			`SELECT `+accountColumns+` WHERE a.parent_id = ? AND a.rowid > ?
			 ORDER BY a.rowid LIMIT ?`,
			o.rootPath(), parentID, after, size+1)
		if err != nil {
			return err
		}
		out = paginate(rows, size, o.id, listAccountsParent, parentID)
		return nil
	})
	return out, err
}

// CloseAccount closes a member account at once. A closed account stays in
// the organization: it is still listed and can still be moved, but not
// closed again.
func (s *Service) CloseAccount(ctx context.Context, accountID string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		if o.featureSet != contracts.FeatureSetAll {
			return contracts.ErrNotInAllFeaturesMode
		}
		a, err := loadAccount(ctx, tx, accountID)
		if err != nil {
			return err
		}
		switch {
		case accountID == o.managementAccountID:
			return contracts.ErrCannotCloseManagementAccount
		case a.state == contracts.AccountStateClosed:
			return contracts.ErrAccountAlreadyClosed
		}
		return exec(ctx, tx, `UPDATE accounts SET state = ? WHERE id = ?`,
			contracts.AccountStateClosed, accountID)
	})
}

// RemoveAccountFromOrganization removes a member account, and its tags, from
// the organization.
func (s *Service) RemoveAccountFromOrganization(ctx context.Context, accountID string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		if _, err = loadAccount(ctx, tx, accountID); err != nil {
			return err
		}
		if accountID == o.managementAccountID {
			return contracts.ErrManagementAccountCannotLeave
		}

		if err = exec(ctx, tx, `DELETE FROM tags WHERE resource_id = ?`, accountID); err != nil {
			return err
		}
		return exec(ctx, tx, `DELETE FROM accounts WHERE id = ?`, accountID)
	})
}

// MoveAccount moves an account from the parent that holds it to another.
func (s *Service) MoveAccount(ctx context.Context, in contracts.MoveAccountInput) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		if _, err = requireParent(ctx, tx, o, in.SourceParentID,
			contracts.ErrSourceParentNotFound); err != nil {
			return err
		}
		if _, err = requireParent(ctx, tx, o, in.DestinationParentID,
			contracts.ErrDestinationParentNotFound); err != nil {
			return err
		}
		a, err := loadAccount(ctx, tx, in.AccountID)
		if err != nil {
			return err
		}
		switch a.parentID {
		case in.DestinationParentID:
			return contracts.ErrDuplicateAccount
		case in.SourceParentID:
		default:
			return fmt.Errorf("account is not in the source parent: %w",
				contracts.ErrAccountNotFound)
		}

		return exec(ctx, tx, `UPDATE accounts SET parent_id = ? WHERE id = ?`,
			in.DestinationParentID, in.AccountID)
	})
}
