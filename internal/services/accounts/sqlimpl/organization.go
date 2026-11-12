package sqlimpl

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"tule.dev/accounts/internal/contracts"
)

// rootName is the name CreateOrganization gives the root.
const rootName = "Root"

// arnPrefix starts every ARN Organizations mints. Organizations is global, so
// the region is empty, and the account is the management account's.
const arnPrefix = "arn:aws:organizations::"

// org is the organization row.
type org struct {
	id                  string
	featureSet          string
	managementAccountID string
	rootID              string
}

func (o *org) arn() string {
	return arnPrefix + o.managementAccountID + ":organization/" + o.id
}

func (o *org) accountARN(accountID string) string {
	return arnPrefix + o.managementAccountID + ":account/" + o.id + "/" + accountID
}

func (o *org) rootARN() string {
	return arnPrefix + o.managementAccountID + ":root/" + o.id + "/" + o.rootID
}

func (o *org) ouARN(ouID string) string {
	return arnPrefix + o.managementAccountID + ":ou/" + o.id + "/" + ouID
}

// rootPath is the path of the root, which every other path starts with.
func (o *org) rootPath() string {
	return o.id + "/" + o.rootID + "/"
}

// policyTypes is what the root reports enabled: CreateOrganization enables
// service control policies in the root of an organization with all features,
// and none in one with consolidated billing only.
func (o *org) policyTypes() []contracts.PolicyTypeSummary {
	if o.featureSet != contracts.FeatureSetAll {
		return []contracts.PolicyTypeSummary{}
	}
	return []contracts.PolicyTypeSummary{{
		Type:   contracts.PolicyTypeServiceControl,
		Status: contracts.PolicyTypeStatusEnabled,
	}}
}

// loadOrg reads the organization, or fails with contracts.ErrNotInUse when
// there is none.
func loadOrg(ctx context.Context, tx *sql.Tx) (*org, error) {
	var o org
	err := tx.QueryRowContext(ctx,
		`SELECT id, feature_set, management_account_id, root_id FROM organization`,
	).Scan(&o.id, &o.featureSet, &o.managementAccountID, &o.rootID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, contracts.ErrNotInUse
	case err != nil:
		return nil, fmt.Errorf("read organization: %w", err)
	}
	return &o, nil
}

// CreateOrganization creates the organization, with its root, and makes the
// configured management account its first member.
func (s *Service) CreateOrganization(
	ctx context.Context,
	featureSet string,
) (*contracts.Organization, error) {
	if featureSet == "" {
		featureSet = contracts.FeatureSetAll
	}

	var out *contracts.Organization
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		_, err := loadOrg(ctx, tx)
		switch {
		case err == nil:
			return contracts.ErrAlreadyInOrganization
		case !errors.Is(err, contracts.ErrNotInUse):
			return err
		}

		o, err := newOrg(featureSet, s.settings.ManagementAccountID)
		if err != nil {
			return err
		}
		now := stamp(s.now())
		if err = exec(ctx, tx,
			`INSERT INTO organization (id, feature_set, management_account_id, root_id, created_at)
			 VALUES (?, ?, ?, ?, ?)`,
			o.id, o.featureSet, o.managementAccountID, o.rootID, now,
		); err != nil {
			return err
		}
		if err = exec(ctx, tx,
			`INSERT INTO accounts (id, name, email, parent_id, state, joined_method, joined_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			o.managementAccountID, s.settings.ManagementAccountName,
			s.settings.ManagementAccountEmail, o.rootID, contracts.AccountStateActive,
			contracts.JoinedMethodInvited, now,
		); err != nil {
			return err
		}

		out = describe(o, s.settings.ManagementAccountEmail)
		return nil
	})
	return out, err
}

func newOrg(featureSet, managementAccountID string) (*org, error) {
	id, err := newOrganizationID()
	if err != nil {
		return nil, err
	}
	rootID, err := newRootID()
	if err != nil {
		return nil, err
	}
	return &org{
		id:                  id,
		featureSet:          featureSet,
		managementAccountID: managementAccountID,
		rootID:              rootID,
	}, nil
}

// DescribeOrganization describes the organization.
func (s *Service) DescribeOrganization(ctx context.Context) (*contracts.Organization, error) {
	var out *contracts.Organization
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}
		// The management account's email is the one it was created with,
		// which the configuration may have changed since.
		var email string
		if err = tx.QueryRowContext(ctx, `SELECT email FROM accounts WHERE id = ?`,
			o.managementAccountID).Scan(&email); err != nil {
			return fmt.Errorf("read management account: %w", err)
		}
		out = describe(o, email)
		return nil
	})
	return out, err
}

// describe describes o, whose management account has the given email.
func describe(o *org, managementEmail string) *contracts.Organization {
	return &contracts.Organization{
		ID:                     o.id,
		ARN:                    o.arn(),
		FeatureSet:             o.featureSet,
		ManagementAccountID:    o.managementAccountID,
		ManagementAccountARN:   o.accountARN(o.managementAccountID),
		ManagementAccountEmail: managementEmail,
		AvailablePolicyTypes:   o.policyTypes(),
	}
}

// DeleteOrganization deletes the organization once the management account is
// its only member, and everything it held: the root, the OUs, the tags and
// the create-account records. A later CreateOrganization starts empty.
func (s *Service) DeleteOrganization(ctx context.Context) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		o, err := loadOrg(ctx, tx)
		if err != nil {
			return err
		}

		members, err := exists(ctx, tx,
			`SELECT 1 FROM accounts WHERE id <> ? LIMIT 1`, o.managementAccountID)
		if err != nil {
			return err
		}
		if members {
			return contracts.ErrOrganizationNotEmpty
		}

		for _, table := range []string{
			"tags", "create_account_statuses", "accounts", "organizational_units", "organization",
		} {
			// The table names are the constants above, never input.
			if err = exec(ctx, tx, "DELETE FROM "+table); err != nil {
				return err
			}
		}
		return nil
	})
}
