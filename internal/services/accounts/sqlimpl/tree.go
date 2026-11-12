package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tule.dev/accounts/internal/contracts"
)

// parent is a root or an OU, which can hold accounts and OUs. depth is 0 for
// the root and how many OUs deep an OU sits otherwise, itself included.
type parent struct {
	id    string
	kind  string
	path  string
	depth int
}

// findParent returns the root or OU whose ID is id, or nil when there is
// none.
func findParent(ctx context.Context, tx *sql.Tx, o *org, id string) (*parent, error) {
	if id == o.rootID {
		return &parent{id: id, kind: contracts.NodeRoot, path: o.rootPath()}, nil
	}

	p := parent{id: id, kind: contracts.NodeOrganizationalUnit}
	err := tx.QueryRowContext(ctx,
		`SELECT path, depth FROM organizational_units WHERE id = ?`, id,
	).Scan(&p.path, &p.depth)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read parent: %w", err)
	}
	return &p, nil
}

// requireParent is findParent for a parent that must exist: notFound is the
// error when it does not.
func requireParent(
	ctx context.Context,
	tx *sql.Tx,
	o *org,
	id string,
	notFound error,
) (*parent, error) {
	p, err := findParent(ctx, tx, o, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, notFound
	}
	return p, nil
}

// ListRoots lists the organization's one root.
func (s *Service) ListRoots(
	ctx context.Context,
	page contracts.PageInput,
) (*contracts.Page[contracts.Root], error) {
	var out *contracts.Page[contracts.Root]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		after, err := decodeToken(page.NextToken, o.id, listRoots, "")
		if err != nil {
			return err
		}

		var rows []cursored[contracts.Root]
		if after == "" {
			rows = append(rows, cursored[contracts.Root]{
				item: contracts.Root{
					ID:          o.rootID,
					ARN:         o.rootARN(),
					Name:        rootName,
					PolicyTypes: o.policyTypes(),
				},
				cursor: o.rootID,
			})
		}
		out = paginate(rows, pageSize(page.MaxResults), o.id, listRoots, "")
		return nil
	})
	return out, err
}

// ListParents lists the one parent of an account or OU.
func (s *Service) ListParents(
	ctx context.Context,
	childID string,
	page contracts.PageInput,
) (*contracts.Page[contracts.Node], error) {
	var out *contracts.Page[contracts.Node]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		after, err := decodeToken(page.NextToken, o.id, listParents, childID)
		if err != nil {
			return err
		}

		var parentID string
		err = tx.QueryRowContext(ctx,
			`SELECT parent_id FROM accounts WHERE id = ?
			 UNION ALL SELECT parent_id FROM organizational_units WHERE id = ?`,
			childID, childID,
		).Scan(&parentID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return contracts.ErrChildNotFound
		case err != nil:
			return fmt.Errorf("read child: %w", err)
		}

		node := contracts.Node{ID: parentID, Type: contracts.NodeOrganizationalUnit}
		if parentID == o.rootID {
			node.Type = contracts.NodeRoot
		}
		var rows []cursored[contracts.Node]
		if after == "" {
			rows = append(rows, cursored[contracts.Node]{item: node, cursor: parentID})
		}
		out = paginate(rows, pageSize(page.MaxResults), o.id, listParents, childID)
		return nil
	})
	return out, err
}

// ListChildren lists the accounts or the OUs directly under a parent, in
// creation order.
func (s *Service) ListChildren(
	ctx context.Context,
	in contracts.ListChildrenInput,
) (*contracts.Page[contracts.Node], error) {
	table := "accounts"
	if in.ChildType == contracts.NodeOrganizationalUnit {
		table = "organizational_units"
	}
	scope := in.ParentID + "/" + in.ChildType

	var out *contracts.Page[contracts.Node]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		after, err := decodeRowToken(in.Page.NextToken, o.id, listChildren, scope)
		if err != nil {
			return err
		}
		if _, err = requireParent(
			ctx,
			tx,
			o,
			in.ParentID,
			contracts.ErrParentNotFound,
		); err != nil {
			return err
		}

		size := pageSize(in.Page.MaxResults)
		rows, err := queryAll(ctx, tx, func(r scanner) (cursored[contracts.Node], error) {
			var row int64
			node := contracts.Node{Type: in.ChildType}
			sErr := r.Scan(&row, &node.ID)
			return cursored[contracts.Node]{item: node, cursor: rowCursor(row)}, sErr
		},
			// The table is one of the two constants above, never input.
			`SELECT rowid, id FROM `+table+` WHERE parent_id = ? AND rowid > ?
			 ORDER BY rowid LIMIT ?`,
			in.ParentID, after, size+1)
		if err != nil {
			return err
		}
		out = paginate(rows, size, o.id, listChildren, scope)
		return nil
	})
	return out, err
}

// CreateOrganizationalUnit creates an OU under a root or OU, with tags.
func (s *Service) CreateOrganizationalUnit(
	ctx context.Context,
	in contracts.CreateOrganizationalUnitInput,
) (*contracts.OrganizationalUnit, error) {
	if len(in.Tags) > contracts.MaxTagsPerResource {
		return nil, contracts.ErrTagLimitExceeded
	}

	var out *contracts.OrganizationalUnit
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		p, err := requireParent(ctx, tx, o, in.ParentID, contracts.ErrParentNotFound)
		if err != nil {
			return err
		}
		if err = checkNewOU(ctx, tx, p, in.Name); err != nil {
			return err
		}

		id, err := newOUID(o.rootID)
		if err != nil {
			return err
		}
		ou := contracts.OrganizationalUnit{
			ID:   id,
			ARN:  o.ouARN(id),
			Name: in.Name,
			Path: p.path + id + "/",
		}
		if err = exec(ctx, tx,
			`INSERT INTO organizational_units (id, name, parent_id, path, depth)
			 VALUES (?, ?, ?, ?, ?)`,
			ou.ID, ou.Name, p.id, ou.Path, p.depth+1,
		); err != nil {
			return err
		}
		if err = putTags(ctx, tx, id, in.Tags); err != nil {
			return err
		}
		out = &ou
		return nil
	})
	return out, err
}

// checkNewOU enforces the limits on adding an OU named name under p: the
// nesting depth, the number of OUs and a name unique under p.
func checkNewOU(ctx context.Context, tx *sql.Tx, p *parent, name string) error {
	if p.depth+1 > contracts.MaxOUDepth {
		return contracts.ErrOUDepthLimitExceeded
	}

	var count int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM organizational_units`).Scan(&count); err != nil {
		return fmt.Errorf("count OUs: %w", err)
	}
	if count >= contracts.MaxOrganizationalUnits {
		return contracts.ErrOUNumberLimitExceeded
	}

	return requireUniqueOUName(ctx, tx, p.id, name, "")
}

// requireUniqueOUName fails when an OU other than self is named name under
// parentID.
func requireUniqueOUName(ctx context.Context, tx *sql.Tx, parentID, name, self string) error {
	taken, err := exists(ctx, tx,
		`SELECT 1 FROM organizational_units WHERE parent_id = ? AND name = ? AND id <> ?
		 LIMIT 1`,
		parentID, name, self)
	if err != nil {
		return err
	}
	if taken {
		return contracts.ErrDuplicateOrganizationalUnit
	}
	return nil
}

// DescribeOrganizationalUnit describes an OU.
func (s *Service) DescribeOrganizationalUnit(
	ctx context.Context,
	ouID string,
) (*contracts.OrganizationalUnit, error) {
	var out *contracts.OrganizationalUnit
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		out, _, err = loadOU(ctx, tx, o, ouID)
		return err
	})
	return out, err
}

// loadOU reads an OU and the ID of its parent.
func loadOU(
	ctx context.Context,
	tx *sql.Tx,
	o *org,
	ouID string,
) (*contracts.OrganizationalUnit, string, error) {
	ou := contracts.OrganizationalUnit{ID: ouID, ARN: o.ouARN(ouID)}
	var parentID string
	err := tx.QueryRowContext(ctx,
		`SELECT name, path, parent_id FROM organizational_units WHERE id = ?`, ouID,
	).Scan(&ou.Name, &ou.Path, &parentID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, "", contracts.ErrOrganizationalUnitNotFound
	case err != nil:
		return nil, "", fmt.Errorf("read OU: %w", err)
	}
	return &ou, parentID, nil
}

// UpdateOrganizationalUnit renames an OU, keeping names unique under its
// parent.
func (s *Service) UpdateOrganizationalUnit(
	ctx context.Context,
	in contracts.UpdateOrganizationalUnitInput,
) (*contracts.OrganizationalUnit, error) {
	var out *contracts.OrganizationalUnit
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		ou, parentID, err := loadOU(ctx, tx, o, in.ID)
		if err != nil {
			return err
		}
		if in.Name == nil {
			out = ou
			return nil
		}

		if err = requireUniqueOUName(ctx, tx, parentID, *in.Name, ou.ID); err != nil {
			return err
		}
		if err = exec(ctx, tx,
			`UPDATE organizational_units SET name = ? WHERE id = ?`, *in.Name, ou.ID,
		); err != nil {
			return err
		}
		ou.Name = *in.Name
		out = ou
		return nil
	})
	return out, err
}

// DeleteOrganizationalUnit deletes an empty OU and its tags.
func (s *Service) DeleteOrganizationalUnit(ctx context.Context, ouID string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		if _, _, err = loadOU(ctx, tx, o, ouID); err != nil {
			return err
		}

		occupied, err := exists(ctx, tx,
			`SELECT 1 FROM accounts WHERE parent_id = ?
			 UNION ALL SELECT 1 FROM organizational_units WHERE parent_id = ? LIMIT 1`,
			ouID, ouID)
		if err != nil {
			return err
		}
		if occupied {
			return contracts.ErrOrganizationalUnitNotEmpty
		}

		if err = exec(ctx, tx, `DELETE FROM tags WHERE resource_id = ?`, ouID); err != nil {
			return err
		}
		return exec(ctx, tx, `DELETE FROM organizational_units WHERE id = ?`, ouID)
	})
}

// ListOrganizationalUnitsForParent lists the OUs directly under a parent, in
// creation order.
func (s *Service) ListOrganizationalUnitsForParent(
	ctx context.Context,
	parentID string,
	page contracts.PageInput,
) (*contracts.Page[contracts.OrganizationalUnit], error) {
	var out *contracts.Page[contracts.OrganizationalUnit]
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		after, err := decodeRowToken(page.NextToken, o.id, listOUs, parentID)
		if err != nil {
			return err
		}
		if _, err = requireParent(ctx, tx, o, parentID, contracts.ErrParentNotFound); err != nil {
			return err
		}

		size := pageSize(page.MaxResults)
		rows, err := queryAll(ctx, tx,
			func(r scanner) (cursored[contracts.OrganizationalUnit], error) {
				var row int64
				var ou contracts.OrganizationalUnit
				sErr := r.Scan(&row, &ou.ID, &ou.Name, &ou.Path)
				ou.ARN = o.ouARN(ou.ID)
				return cursored[contracts.OrganizationalUnit]{
					item:   ou,
					cursor: rowCursor(row),
				}, sErr
			},
			`SELECT rowid, id, name, path FROM organizational_units
			 WHERE parent_id = ? AND rowid > ? ORDER BY rowid LIMIT ?`,
			parentID, after, size+1)
		if err != nil {
			return err
		}
		out = paginate(rows, size, o.id, listOUs, parentID)
		return nil
	})
	return out, err
}
