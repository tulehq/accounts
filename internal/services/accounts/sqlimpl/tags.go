package sqlimpl

import (
	"context"
	"database/sql"
	"slices"
	"strings"

	"tule.dev/accounts/internal/contracts"
)

// requireTarget fails with contracts.ErrTargetNotFound unless resourceID is
// the root, an OU or a member account: the resources that carry tags here.
func requireTarget(ctx context.Context, tx *sql.Tx, o *org, resourceID string) error {
	if resourceID == o.rootID {
		return nil
	}
	found, err := exists(ctx, tx,
		`SELECT 1 FROM accounts WHERE id = ?
		 UNION ALL SELECT 1 FROM organizational_units WHERE id = ? LIMIT 1`,
		resourceID, resourceID)
	if err != nil {
		return err
	}
	if !found {
		return contracts.ErrTargetNotFound
	}
	return nil
}

// putTags sets tags on a resource, replacing the value of a key it has.
func putTags(ctx context.Context, tx *sql.Tx, resourceID string, tags []contracts.Tag) error {
	for _, t := range tags {
		if err := exec(ctx, tx,
			`INSERT INTO tags (resource_id, key, value) VALUES (?, ?, ?)
			 ON CONFLICT (resource_id, key) DO UPDATE SET value = excluded.value`,
			resourceID, t.Key, t.Value,
		); err != nil {
			return err
		}
	}
	return nil
}

// TagResource adds tags to a resource, or changes the values of keys it has,
// as long as it ends up with at most contracts.MaxTagsPerResource tags.
func (s *Service) TagResource(ctx context.Context, resourceID string, tags []contracts.Tag) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		if err = requireTarget(ctx, tx, o, resourceID); err != nil {
			return err
		}

		keys, err := queryAll(ctx, tx, func(r scanner) (string, error) {
			var k string
			sErr := r.Scan(&k)
			return k, sErr
		}, `SELECT key FROM tags WHERE resource_id = ?`, resourceID)
		if err != nil {
			return err
		}
		count := len(keys)
		for _, t := range tags {
			if !slices.Contains(keys, t.Key) {
				count++
			}
		}
		if count > contracts.MaxTagsPerResource {
			return contracts.ErrTagLimitExceeded
		}

		return putTags(ctx, tx, resourceID, tags)
	})
}

// UntagResource removes the tags with the given keys from a resource. A key
// the resource does not have is not an error.
func (s *Service) UntagResource(ctx context.Context, resourceID string, keys []string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		if err = requireTarget(ctx, tx, o, resourceID); err != nil {
			return err
		}
		if len(keys) == 0 {
			return nil
		}

		args := make([]any, 0, len(keys)+1)
		args = append(args, resourceID)
		for _, k := range keys {
			args = append(args, k)
		}
		return exec(ctx, tx,
			`DELETE FROM tags WHERE resource_id = ? AND key IN (?`+
				strings.Repeat(", ?", len(keys)-1)+`)`,
			args...)
	})
}

// ListTagsForResource lists a resource's tags in key order.
func (s *Service) ListTagsForResource(
	ctx context.Context,
	resourceID string,
	page contracts.PageInput,
) (*contracts.Page[contracts.Tag], error) {
	var out *contracts.Page[contracts.Tag]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		after, err := decodeToken(page.NextToken, o.id, listTags, resourceID)
		if err != nil {
			return err
		}
		if err = requireTarget(ctx, tx, o, resourceID); err != nil {
			return err
		}

		size := pageSize(page.MaxResults)
		rows, err := queryAll(ctx, tx, func(r scanner) (cursored[contracts.Tag], error) {
			var t contracts.Tag
			sErr := r.Scan(&t.Key, &t.Value)
			return cursored[contracts.Tag]{item: t, cursor: t.Key}, sErr
		},
			`SELECT key, value FROM tags WHERE resource_id = ? AND key > ?
			 ORDER BY key LIMIT ?`,
			resourceID, after, size+1)
		if err != nil {
			return err
		}
		out = paginate(rows, size, o.id, listTags, resourceID)
		return nil
	})
	return out, err
}
