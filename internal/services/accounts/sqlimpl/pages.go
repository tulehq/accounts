package sqlimpl

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"tule.dev/accounts/internal/contracts"
)

// A pagination token names the organization it was issued in, the listing it
// belongs to, the scope of that listing (the parent, resource or filter it
// was asked for), and the cursor of the last item it returned. A token is
// only accepted back by the same listing with the same scope in the same
// organization, so a token from one listing, from an organization since
// deleted, or one this service did not issue, fails rather than resuming
// somewhere arbitrary: rowids start over in a new organization. It is encoded
// to keep it opaque to clients.
const tokenSeparator = "\x00"

// The listings a token can belong to.
const (
	listAccounts       = "accounts"
	listAccountsParent = "accounts-for-parent"
	listStatuses       = "create-account-statuses"
	listRoots          = "roots"
	listParents        = "parents"
	listChildren       = "children"
	listOUs            = "ous-for-parent"
	listTags           = "tags"
)

func encodeToken(orgID, list, scope, cursor string) string {
	raw := strings.Join([]string{orgID, list, scope, cursor}, tokenSeparator)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeToken returns the cursor a listing should resume after, or "" for an
// empty token.
func decodeToken(token, orgID, list, scope string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", contracts.ErrInvalidToken
	}
	parts := strings.SplitN(string(raw), tokenSeparator, 4)
	if len(parts) != 4 || parts[0] != orgID || parts[1] != list || parts[2] != scope ||
		parts[3] == "" {
		return "", contracts.ErrInvalidToken
	}
	return parts[3], nil
}

// decodeRowToken is decodeToken for the listings that page by rowid, which
// is creation order. It returns 0 for an empty token.
func decodeRowToken(token, orgID, list, scope string) (int64, error) {
	cursor, err := decodeToken(token, orgID, list, scope)
	if err != nil || cursor == "" {
		return 0, err
	}
	row, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil || row < 0 {
		return 0, contracts.ErrInvalidToken
	}
	return row, nil
}

func pageSize(requested int) int {
	if requested <= 0 {
		return contracts.DefaultPageSize
	}
	return requested
}

// cursored is one item of a listing with the cursor that resumes after it.
type cursored[T any] struct {
	item   T
	cursor string
}

// paginate makes a page of up to size items from rows, which the query
// fetched with one more than size: when that extra row is there, the page has
// a token for the next.
func paginate[T any](
	rows []cursored[T],
	size int,
	orgID, list, scope string,
) *contracts.Page[T] {
	page := &contracts.Page[T]{Items: make([]T, 0, min(len(rows), size))}
	for i, r := range rows {
		if i == size {
			page.NextToken = encodeToken(orgID, list, scope, rows[size-1].cursor)
			break
		}
		page.Items = append(page.Items, r.item)
	}
	return page
}

func rowCursor(row int64) string {
	return strconv.FormatInt(row, 10)
}

// scanner is a row to scan: an *sql.Rows positioned on a row, or an
// *sql.Row.
type scanner interface {
	Scan(dest ...any) error
}

// queryAll runs query in tx and scans every row with scan.
func queryAll[T any](
	ctx context.Context,
	tx *sql.Tx,
	scan func(scanner) (T, error),
	query string,
	args ...any,
) ([]T, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query: %w", err)
	}
	// Every error of the iteration is reported by rows.Err below; Close
	// after a full iteration has nothing left to report.
	defer func() { _ = rows.Close() }()

	var out []T
	for rows.Next() {
		v, sErr := scan(rows)
		if sErr != nil {
			return nil, fmt.Errorf("scan: %w", sErr)
		}
		out = append(out, v)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

// exists reports whether query, a SELECT 1 ... LIMIT 1, returns a row.
func exists(ctx context.Context, tx *sql.Tx, query string, args ...any) (bool, error) {
	var one int
	err := tx.QueryRowContext(ctx, query, args...).Scan(&one)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	default:
		return false, fmt.Errorf("query: %w", err)
	}
}

func exec(ctx context.Context, tx *sql.Tx, query string, args ...any) error {
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	return nil
}
