package sqlimpl

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gasmod/gas"
	"github.com/gasmod/gas/database"
	"github.com/gasmod/gas/migrate"
	_ "modernc.org/sqlite"

	"tule.dev/accounts/internal/contracts"
)

const managementID = "000000000000"

var testSettings = OrganizationSettings{
	ManagementAccountID:    managementID,
	ManagementAccountEmail: "management@example.com",
	ManagementAccountName:  "Management",
}

// newStore opens a store on a fresh database file in a temporary directory.
func newStore(t *testing.T) *Service {
	t.Helper()
	return openStore(t, filepath.Join(t.TempDir(), "accounts.db"))
}

// openStore opens a store on the database file at path the way the app wires
// it: gas/database, then gas/migrate applying the schema the store registers.
func openStore(t *testing.T, path string) *Service {
	t.Helper()
	ctx := context.Background()
	logger := &gas.NopLogger{}

	cfg := database.DefaultConfig()
	cfg.Database.Dialect = database.DialectSQLite
	cfg.Database.DSN = gas.Secret("file:" + path)
	cfg.Database.MaxOpenConns = 1
	cfg.Database.MaxIdleConns = 1

	db, err := database.New(database.WithConfig(cfg))(nil, logger)
	if err != nil {
		t.Fatalf("new database: %v", err)
	}
	if err = db.Init(ctx); err != nil {
		t.Fatalf("init database: %v", err)
	}
	t.Cleanup(func() {
		if cErr := db.Close(ctx); cErr != nil {
			t.Errorf("close database: %v", cErr)
		}
	})

	mm, err := migrate.New()(db, logger)
	if err != nil {
		t.Fatalf("new migrate: %v", err)
	}
	if err = mm.Init(ctx); err != nil {
		t.Fatalf("init migrate: %v", err)
	}

	settings := testSettings
	s := NewService(&settings)(db, mm)
	if err = s.Init(ctx); err != nil {
		t.Fatalf("init store: %v", err)
	}
	if err = mm.RunPendingContext(ctx); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return s
}

// newOrgStore is newStore with an organization of all features created.
func newOrgStore(t *testing.T) (*Service, *contracts.Organization) {
	t.Helper()
	s := newStore(t)
	o, err := s.CreateOrganization(context.Background(), "")
	if err != nil {
		t.Fatalf("create organization: %v", err)
	}
	return s, o
}

func requireErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

func requireNoErr(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func requireEqual[T comparable](t *testing.T, got, want T, what string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

func requireMatch(t *testing.T, pattern, s, what string) {
	t.Helper()
	if !regexp.MustCompile(pattern).MatchString(s) {
		t.Fatalf("%s: %q does not match %s", what, s, pattern)
	}
}

func rootID(t *testing.T, s *Service) string {
	t.Helper()
	roots, err := s.ListRoots(context.Background(), contracts.PageInput{})
	requireNoErr(t, err, "list roots")
	return roots.Items[0].ID
}

func createAccount(t *testing.T, s *Service, name string) string {
	t.Helper()
	st, err := s.CreateAccount(context.Background(), contracts.CreateAccountInput{
		AccountName: name,
		Email:       name + "@example.com",
	})
	requireNoErr(t, err, "create account "+name)
	if st.State != contracts.CreateAccountStateSucceeded {
		t.Fatalf("create account %s: state %s (%s)", name, st.State, st.FailureReason)
	}
	return st.AccountID
}

func createOU(t *testing.T, s *Service, parentID, name string) *contracts.OrganizationalUnit {
	t.Helper()
	ou, err := s.CreateOrganizationalUnit(context.Background(),
		contracts.CreateOrganizationalUnitInput{ParentID: parentID, Name: name})
	requireNoErr(t, err, "create OU "+name)
	return ou
}

// storeOps calls each store operation with arguments that are well formed but
// name nothing in particular, for the tests that only look at what fails
// before any of them is looked up.
var storeOps = map[string]func(context.Context, *Service) error{
	"DescribeOrganization": func(ctx context.Context, s *Service) error {
		_, err := s.DescribeOrganization(ctx)
		return err
	},
	"DeleteOrganization": func(ctx context.Context, s *Service) error {
		return s.DeleteOrganization(ctx)
	},
	"CreateAccount": func(ctx context.Context, s *Service) error {
		_, err := s.CreateAccount(ctx, contracts.CreateAccountInput{
			AccountName: "a", Email: "a@example.com",
		})
		return err
	},
	"DescribeCreateAccountStatus": func(ctx context.Context, s *Service) error {
		_, err := s.DescribeCreateAccountStatus(ctx, "car-abcdefgh")
		return err
	},
	"ListCreateAccountStatus": func(ctx context.Context, s *Service) error {
		_, err := s.ListCreateAccountStatus(ctx, contracts.ListCreateAccountStatusInput{})
		return err
	},
	"DescribeAccount": func(ctx context.Context, s *Service) error {
		_, err := s.DescribeAccount(ctx, managementID)
		return err
	},
	"ListAccounts": func(ctx context.Context, s *Service) error {
		_, err := s.ListAccounts(ctx, contracts.PageInput{})
		return err
	},
	"ListAccountsForParent": func(ctx context.Context, s *Service) error {
		_, err := s.ListAccountsForParent(ctx, "r-abcd", contracts.PageInput{})
		return err
	},
	"CloseAccount": func(ctx context.Context, s *Service) error {
		return s.CloseAccount(ctx, "111111111111")
	},
	"RemoveAccountFromOrganization": func(ctx context.Context, s *Service) error {
		return s.RemoveAccountFromOrganization(ctx, "111111111111")
	},
	"MoveAccount": func(ctx context.Context, s *Service) error {
		return s.MoveAccount(ctx, contracts.MoveAccountInput{
			AccountID: "111111111111", SourceParentID: "r-abcd", DestinationParentID: "r-abcd",
		})
	},
	"ListRoots": func(ctx context.Context, s *Service) error {
		_, err := s.ListRoots(ctx, contracts.PageInput{})
		return err
	},
	"ListParents": func(ctx context.Context, s *Service) error {
		_, err := s.ListParents(ctx, managementID, contracts.PageInput{})
		return err
	},
	"ListChildren": func(ctx context.Context, s *Service) error {
		_, err := s.ListChildren(ctx, contracts.ListChildrenInput{
			ParentID: "r-abcd", ChildType: contracts.NodeAccount,
		})
		return err
	},
	"CreateOrganizationalUnit": func(ctx context.Context, s *Service) error {
		_, err := s.CreateOrganizationalUnit(ctx, contracts.CreateOrganizationalUnitInput{
			ParentID: "r-abcd", Name: "x",
		})
		return err
	},
	"DescribeOrganizationalUnit": func(ctx context.Context, s *Service) error {
		_, err := s.DescribeOrganizationalUnit(ctx, "ou-abcd-abcdefgh")
		return err
	},
	"UpdateOrganizationalUnit": func(ctx context.Context, s *Service) error {
		_, err := s.UpdateOrganizationalUnit(ctx, contracts.UpdateOrganizationalUnitInput{
			ID: "ou-abcd-abcdefgh",
		})
		return err
	},
	"DeleteOrganizationalUnit": func(ctx context.Context, s *Service) error {
		return s.DeleteOrganizationalUnit(ctx, "ou-abcd-abcdefgh")
	},
	"ListOrganizationalUnitsForParent": func(ctx context.Context, s *Service) error {
		_, err := s.ListOrganizationalUnitsForParent(ctx, "r-abcd", contracts.PageInput{})
		return err
	},
	"TagResource": func(ctx context.Context, s *Service) error {
		return s.TagResource(ctx, "r-abcd", nil)
	},
	"UntagResource": func(ctx context.Context, s *Service) error {
		return s.UntagResource(ctx, "r-abcd", []string{"k"})
	},
	"ListTagsForResource": func(ctx context.Context, s *Service) error {
		_, err := s.ListTagsForResource(ctx, "r-abcd", contracts.PageInput{})
		return err
	},
}

func TestEveryOperationNeedsAnOrganization(t *testing.T) {
	s := newStore(t)
	for name, op := range storeOps {
		t.Run(name, func(t *testing.T) {
			requireErr(t, op(context.Background(), s), contracts.ErrNotInUse)
		})
	}
}

func TestCreateOrganization(t *testing.T) {
	ctx := context.Background()
	s, o := newOrgStore(t)
	arn := "arn:aws:organizations::" + managementID + ":"

	requireMatch(t, `^o-[a-z0-9]{10}$`, o.ID, "organization ID")
	requireEqual(t, o.ARN, arn+"organization/"+o.ID, "organization ARN")
	requireEqual(t, o.FeatureSet, contracts.FeatureSetAll, "default feature set")
	requireEqual(t, o.ManagementAccountID, managementID, "management account ID")
	requireEqual(t, o.ManagementAccountARN, arn+"account/"+o.ID+"/"+managementID,
		"management account ARN")
	requireEqual(t, o.ManagementAccountEmail, testSettings.ManagementAccountEmail,
		"management account email")

	_, err := s.CreateOrganization(ctx, contracts.FeatureSetAll)
	requireErr(t, err, contracts.ErrAlreadyInOrganization)

	got, err := s.DescribeOrganization(ctx)
	requireNoErr(t, err, "describe organization")
	requireEqual(t, got.ARN, o.ARN, "described ARN")

	roots, err := s.ListRoots(ctx, contracts.PageInput{})
	requireNoErr(t, err, "list roots")
	requireEqual(t, len(roots.Items), 1, "roots")
	requireEqual(t, roots.NextToken, "", "roots token")
	root := roots.Items[0]
	requireMatch(t, `^r-[a-z0-9]{4}$`, root.ID, "root ID")
	requireEqual(t, root.Name, "Root", "root name")
	requireEqual(t, root.ARN, arn+"root/"+o.ID+"/"+root.ID, "root ARN")
	requireEqual(t, fmt.Sprint(root.PolicyTypes), "[{SERVICE_CONTROL_POLICY ENABLED}]",
		"root policy types")

	// The management account is a member, in the root, joined by invitation.
	mgmt, err := s.DescribeAccount(ctx, managementID)
	requireNoErr(t, err, "describe management account")
	requireEqual(t, mgmt.JoinedMethod, contracts.JoinedMethodInvited, "joined method")
	requireEqual(t, mgmt.State, contracts.AccountStateActive, "state")
	requireEqual(t, mgmt.Name, testSettings.ManagementAccountName, "name")
	requireEqual(t, mgmt.Paths[0], o.ID+"/"+root.ID+"/"+managementID+"/", "path")
}

func TestConsolidatedBillingEnablesNoPolicyTypes(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	o, err := s.CreateOrganization(ctx, contracts.FeatureSetConsolidatedBilling)
	requireNoErr(t, err, "create organization")
	if o.FeatureSet != contracts.FeatureSetConsolidatedBilling || len(o.AvailablePolicyTypes) != 0 {
		t.Fatalf("organization = %+v", o)
	}

	roots, err := s.ListRoots(ctx, contracts.PageInput{})
	requireNoErr(t, err, "list roots")
	if roots.Items[0].PolicyTypes == nil || len(roots.Items[0].PolicyTypes) != 0 {
		t.Fatalf("root policy types = %#v, want an empty list", roots.Items[0].PolicyTypes)
	}

	// Closing an account needs all features.
	id := createAccount(t, s, "member")
	requireErr(t, s.CloseAccount(ctx, id), contracts.ErrNotInAllFeaturesMode)
}

func TestDeleteOrganization(t *testing.T) {
	ctx := context.Background()
	s, o := newOrgStore(t)

	id := createAccount(t, s, "member")
	requireErr(t, s.DeleteOrganization(ctx), contracts.ErrOrganizationNotEmpty)

	// A closed account is still a member.
	requireNoErr(t, s.CloseAccount(ctx, id), "close account")
	requireErr(t, s.DeleteOrganization(ctx), contracts.ErrOrganizationNotEmpty)

	requireNoErr(t, s.RemoveAccountFromOrganization(ctx, id), "remove account")
	ou := createOU(t, s, rootID(t, s), "Empty")
	requireNoErr(t, s.TagResource(ctx, ou.ID, []contracts.Tag{{Key: "k", Value: "v"}}),
		"tag OU")
	requireNoErr(t, s.DeleteOrganization(ctx), "delete organization")

	_, err := s.DescribeOrganization(ctx)
	requireErr(t, err, contracts.ErrNotInUse)

	// A new organization starts empty: no OUs, no create-account records.
	o2, err := s.CreateOrganization(ctx, "")
	requireNoErr(t, err, "create organization again")
	if o2.ID == o.ID {
		t.Fatal("the new organization has the old one's ID")
	}
	accounts, err := s.ListAccounts(ctx, contracts.PageInput{})
	requireNoErr(t, err, "list accounts")
	if len(accounts.Items) != 1 || accounts.Items[0].ID != managementID {
		t.Fatalf("accounts = %+v, want the management account alone", accounts.Items)
	}
	statuses, err := s.ListCreateAccountStatus(ctx, contracts.ListCreateAccountStatusInput{})
	requireNoErr(t, err, "list create account status")
	if len(statuses.Items) != 0 {
		t.Fatalf("create account records = %+v, want none", statuses.Items)
	}
	ous, err := s.ListOrganizationalUnitsForParent(ctx, rootID(t, s), contracts.PageInput{})
	requireNoErr(t, err, "list OUs")
	if len(ous.Items) != 0 {
		t.Fatalf("OUs = %+v, want none", ous.Items)
	}
}

func TestCreateAccount(t *testing.T) {
	ctx := context.Background()
	s, o := newOrgStore(t)

	st, err := s.CreateAccount(ctx, contracts.CreateAccountInput{
		AccountName: "Dev",
		Email:       "dev@example.com",
		Tags:        []contracts.Tag{{Key: "team", Value: "core"}},
	})
	requireNoErr(t, err, "create account")
	requireEqual(t, st.State, contracts.CreateAccountStateSucceeded, "state")
	requireEqual(t, st.FailureReason, "", "failure reason")
	requireMatch(t, `^car-[a-z0-9]{32}$`, st.ID, "request ID")
	requireMatch(t, `^\d{12}$`, st.AccountID, "account ID")
	requireEqual(t, st.RequestedTimestamp.IsZero() || st.CompletedTimestamp.IsZero(), false,
		"a timestamp is missing")

	a, err := s.DescribeAccount(ctx, st.AccountID)
	requireNoErr(t, err, "describe account")
	root := rootID(t, s)
	requireEqual(t, a.Name, "Dev", "name")
	requireEqual(t, a.Email, "dev@example.com", "email")
	requireEqual(t, a.JoinedMethod, contracts.JoinedMethodCreated, "joined method")
	requireEqual(t, a.State, contracts.AccountStateActive, "state")
	requireEqual(t, a.ARN,
		"arn:aws:organizations::"+managementID+":account/"+o.ID+"/"+st.AccountID, "ARN")
	requireEqual(t, a.Paths[0], o.ID+"/"+root+"/"+st.AccountID+"/", "path")

	tags, err := s.ListTagsForResource(ctx, st.AccountID, contracts.PageInput{})
	requireNoErr(t, err, "list tags")
	requireEqual(t, fmt.Sprint(tags.Items), "[{team core}]", "tags")

	// The record reads back the same, to the millisecond the wire carries.
	again, err := s.DescribeCreateAccountStatus(ctx, st.ID)
	requireNoErr(t, err, "describe create account status")
	requireEqual(t, again.AccountID, st.AccountID, "recorded account ID")
	requireEqual(t, again.State, st.State, "recorded state")
	requireEqual(t, again.RequestedTimestamp.UnixMilli(), st.RequestedTimestamp.UnixMilli(),
		"recorded request time")

	_, err = s.DescribeCreateAccountStatus(ctx, "car-doesnotexist")
	requireErr(t, err, contracts.ErrCreateAccountStatusNotFound)
}

func TestCreateAccountWithATakenEmailFails(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)
	createAccount(t, s, "dev")

	for _, email := range []string{"dev@example.com", "DEV@Example.com", "management@example.com"} {
		st, err := s.CreateAccount(ctx, contracts.CreateAccountInput{
			AccountName: "again", Email: email,
		})
		requireNoErr(t, err, "create account "+email)
		if st.State != contracts.CreateAccountStateFailed ||
			st.FailureReason != contracts.FailureEmailAlreadyExists || st.AccountID != "" {
			t.Fatalf("status for %s = %+v, want FAILED with EMAIL_ALREADY_EXISTS", email, st)
		}
	}

	accounts, err := s.ListAccounts(ctx, contracts.PageInput{})
	requireNoErr(t, err, "list accounts")
	if len(accounts.Items) != 2 {
		t.Fatalf("accounts = %d, want 2", len(accounts.Items))
	}
}

func TestCreateAccountWithTooManyTagsIsRefused(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)

	tags := make([]contracts.Tag, contracts.MaxTagsPerResource+1)
	for i := range tags {
		tags[i] = contracts.Tag{Key: fmt.Sprintf("k%d", i)}
	}
	_, err := s.CreateAccount(ctx, contracts.CreateAccountInput{
		AccountName: "dev", Email: "dev@example.com", Tags: tags,
	})
	requireErr(t, err, contracts.ErrTagLimitExceeded)

	// No account and no record.
	statuses, err := s.ListCreateAccountStatus(ctx, contracts.ListCreateAccountStatusInput{})
	requireNoErr(t, err, "list create account status")
	if len(statuses.Items) != 0 {
		t.Fatalf("records = %+v, want none", statuses.Items)
	}
}

func TestListCreateAccountStatusFiltersByState(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)
	createAccount(t, s, "a")
	createAccount(t, s, "b")
	_, err := s.CreateAccount(ctx, contracts.CreateAccountInput{
		AccountName: "dup", Email: "a@example.com",
	})
	requireNoErr(t, err, "create duplicate")

	tests := []struct {
		states []string
		want   []string
	}{
		{nil, []string{"a", "b", "dup"}},
		{[]string{contracts.CreateAccountStateSucceeded}, []string{"a", "b"}},
		{[]string{contracts.CreateAccountStateFailed}, []string{"dup"}},
		{[]string{"IN_PROGRESS"}, nil},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.states, ","), func(t *testing.T) {
			got, err := s.ListCreateAccountStatus(ctx,
				contracts.ListCreateAccountStatusInput{States: tt.states})
			requireNoErr(t, err, "list")
			var names []string
			for _, st := range got.Items {
				names = append(names, st.AccountName)
			}
			if strings.Join(names, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("names = %v, want %v", names, tt.want)
			}
		})
	}
}

func TestCloseAccount(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)
	id := createAccount(t, s, "dev")

	requireNoErr(t, s.CloseAccount(ctx, id), "close account")
	a, err := s.DescribeAccount(ctx, id)
	requireNoErr(t, err, "describe closed account")
	if a.State != contracts.AccountStateClosed {
		t.Fatalf("state = %s, want CLOSED", a.State)
	}

	requireErr(t, s.CloseAccount(ctx, id), contracts.ErrAccountAlreadyClosed)
	requireErr(t, s.CloseAccount(ctx, managementID), contracts.ErrCannotCloseManagementAccount)
	requireErr(t, s.CloseAccount(ctx, "999999999999"), contracts.ErrAccountNotFound)

	// A closed account is still listed and can still be moved.
	accounts, err := s.ListAccounts(ctx, contracts.PageInput{})
	requireNoErr(t, err, "list accounts")
	if len(accounts.Items) != 2 {
		t.Fatalf("accounts = %d, want the closed one listed too", len(accounts.Items))
	}
	ou := createOU(t, s, rootID(t, s), "Suspended")
	requireNoErr(t, s.MoveAccount(ctx, contracts.MoveAccountInput{
		AccountID: id, SourceParentID: rootID(t, s), DestinationParentID: ou.ID,
	}), "move closed account")
}

func TestRemoveAccountFromOrganization(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)
	id := createAccount(t, s, "dev")
	requireNoErr(t, s.TagResource(ctx, id, []contracts.Tag{{Key: "k", Value: "v"}}), "tag")

	requireErr(t, s.RemoveAccountFromOrganization(ctx, managementID),
		contracts.ErrManagementAccountCannotLeave)
	requireNoErr(t, s.RemoveAccountFromOrganization(ctx, id), "remove account")

	_, err := s.DescribeAccount(ctx, id)
	requireErr(t, err, contracts.ErrAccountNotFound)
	requireErr(t, s.RemoveAccountFromOrganization(ctx, id), contracts.ErrAccountNotFound)
	_, err = s.ListTagsForResource(ctx, id, contracts.PageInput{})
	requireErr(t, err, contracts.ErrTargetNotFound)

	// Its email is free again.
	st, err := s.CreateAccount(ctx, contracts.CreateAccountInput{
		AccountName: "dev", Email: "dev@example.com",
	})
	requireNoErr(t, err, "create account again")
	if st.State != contracts.CreateAccountStateSucceeded {
		t.Fatalf("state = %s, want SUCCEEDED", st.State)
	}
}

func TestMoveAccount(t *testing.T) {
	ctx := context.Background()
	s, o := newOrgStore(t)
	root := rootID(t, s)
	id := createAccount(t, s, "dev")
	ou := createOU(t, s, root, "Workloads")
	other := createOU(t, s, root, "Other")

	move := func(src, dst string) error {
		return s.MoveAccount(ctx, contracts.MoveAccountInput{
			AccountID: id, SourceParentID: src, DestinationParentID: dst,
		})
	}

	requireErr(t, move("ou-abcd-zzzzzzzz", ou.ID), contracts.ErrSourceParentNotFound)
	requireErr(t, move(root, "ou-abcd-zzzzzzzz"), contracts.ErrDestinationParentNotFound)
	requireErr(t, move(root, root), contracts.ErrDuplicateAccount)
	requireErr(t, move(other.ID, ou.ID), contracts.ErrAccountNotFound)
	requireErr(t, s.MoveAccount(ctx, contracts.MoveAccountInput{
		AccountID: "999999999999", SourceParentID: root, DestinationParentID: ou.ID,
	}), contracts.ErrAccountNotFound)

	requireNoErr(t, move(root, ou.ID), "move account")
	a, err := s.DescribeAccount(ctx, id)
	requireNoErr(t, err, "describe account")
	if want := o.ID + "/" + root + "/" + ou.ID + "/" + id + "/"; a.Paths[0] != want {
		t.Fatalf("path = %s, want %s", a.Paths[0], want)
	}
	requireErr(t, move(root, ou.ID), contracts.ErrDuplicateAccount)

	parents, err := s.ListParents(ctx, id, contracts.PageInput{})
	requireNoErr(t, err, "list parents")
	if len(parents.Items) != 1 ||
		parents.Items[0] != (contracts.Node{ID: ou.ID, Type: contracts.NodeOrganizationalUnit}) {
		t.Fatalf("parents = %+v", parents.Items)
	}
	inOU, err := s.ListAccountsForParent(ctx, ou.ID, contracts.PageInput{})
	requireNoErr(t, err, "list accounts for OU")
	if len(inOU.Items) != 1 || inOU.Items[0].ID != id {
		t.Fatalf("accounts in OU = %+v", inOU.Items)
	}
}

func TestCreateOrganizationalUnit(t *testing.T) {
	ctx := context.Background()
	s, o := newOrgStore(t)
	root := rootID(t, s)

	ou := createOU(t, s, root, "Workloads")
	requireMatch(t, `^ou-`+strings.TrimPrefix(root, "r-")+`-[a-z0-9]{8}$`, ou.ID,
		"OU ID carrying the root's suffix")
	requireEqual(t, ou.ARN, "arn:aws:organizations::"+managementID+":ou/"+o.ID+"/"+ou.ID,
		"OU ARN")
	requireEqual(t, ou.Path, o.ID+"/"+root+"/"+ou.ID+"/", "OU path")

	_, err := s.CreateOrganizationalUnit(ctx, contracts.CreateOrganizationalUnitInput{
		ParentID: root, Name: "Workloads",
	})
	requireErr(t, err, contracts.ErrDuplicateOrganizationalUnit)
	_, err = s.CreateOrganizationalUnit(ctx, contracts.CreateOrganizationalUnitInput{
		ParentID: "ou-abcd-zzzzzzzz", Name: "x",
	})
	requireErr(t, err, contracts.ErrParentNotFound)

	// The same name under another parent is fine.
	child := createOU(t, s, ou.ID, "Workloads")
	requireEqual(t, child.Path, ou.Path+child.ID+"/", "child path")

	got, err := s.DescribeOrganizationalUnit(ctx, child.ID)
	requireNoErr(t, err, "describe OU")
	requireEqual(t, *got, *child, "described OU")
	_, err = s.DescribeOrganizationalUnit(ctx, "ou-abcd-zzzzzzzz")
	requireErr(t, err, contracts.ErrOrganizationalUnitNotFound)
}

func TestUpdateOrganizationalUnit(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)
	root := rootID(t, s)
	ou := createOU(t, s, root, "Workloads")
	createOU(t, s, root, "Dev")

	rename := func(name *string) (*contracts.OrganizationalUnit, error) {
		return s.UpdateOrganizationalUnit(ctx, contracts.UpdateOrganizationalUnitInput{
			ID: ou.ID, Name: name,
		})
	}

	renamed, err := rename(new("Prod"))
	requireNoErr(t, err, "rename OU")
	requireEqual(t, renamed.Name, "Prod", "new name")

	_, err = rename(new("Dev"))
	requireErr(t, err, contracts.ErrDuplicateOrganizationalUnit)

	// Renaming to its own name, or not at all, changes nothing.
	for _, name := range []*string{new("Prod"), nil} {
		same, uErr := rename(name)
		requireNoErr(t, uErr, "rename OU to itself")
		requireEqual(t, same.Name, "Prod", "name")
	}

	_, err = s.UpdateOrganizationalUnit(ctx, contracts.UpdateOrganizationalUnitInput{
		ID: "ou-abcd-zzzzzzzz", Name: new("x"),
	})
	requireErr(t, err, contracts.ErrOrganizationalUnitNotFound)
}

func TestDeleteOrganizationalUnit(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)
	root := rootID(t, s)
	ou := createOU(t, s, root, "Workloads")
	child := createOU(t, s, ou.ID, "Prod")
	requireNoErr(t, s.TagResource(ctx, child.ID, []contracts.Tag{{Key: "k", Value: "v"}}),
		"tag OU")

	// Not empty while it holds an OU, or an account.
	requireErr(t, s.DeleteOrganizationalUnit(ctx, ou.ID), contracts.ErrOrganizationalUnitNotEmpty)
	id := createAccount(t, s, "dev")
	move := func(src, dst string) {
		requireNoErr(t, s.MoveAccount(ctx, contracts.MoveAccountInput{
			AccountID: id, SourceParentID: src, DestinationParentID: dst,
		}), "move account")
	}
	move(root, child.ID)
	requireErr(t, s.DeleteOrganizationalUnit(ctx, child.ID),
		contracts.ErrOrganizationalUnitNotEmpty)
	move(child.ID, root)

	requireNoErr(t, s.DeleteOrganizationalUnit(ctx, child.ID), "delete OU")
	requireErr(
		t,
		s.DeleteOrganizationalUnit(ctx, child.ID),
		contracts.ErrOrganizationalUnitNotFound,
	)
	_, err := s.ListTagsForResource(ctx, child.ID, contracts.PageInput{})
	requireErr(t, err, contracts.ErrTargetNotFound)
}

func TestOUsNestFiveLevelsDeep(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)

	parent := rootID(t, s)
	for level := 1; level <= contracts.MaxOUDepth; level++ {
		parent = createOU(t, s, parent, fmt.Sprintf("level %d", level)).ID
	}
	_, err := s.CreateOrganizationalUnit(ctx, contracts.CreateOrganizationalUnitInput{
		ParentID: parent, Name: "too deep",
	})
	requireErr(t, err, contracts.ErrOUDepthLimitExceeded)
}

func TestListChildrenAndParents(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)
	root := rootID(t, s)
	ou := createOU(t, s, root, "Workloads")
	id := createAccount(t, s, "dev")

	accounts, err := s.ListChildren(ctx, contracts.ListChildrenInput{
		ParentID: root, ChildType: contracts.NodeAccount,
	})
	requireNoErr(t, err, "list account children")
	if len(accounts.Items) != 2 || accounts.Items[0].ID != managementID ||
		accounts.Items[1].ID != id || accounts.Items[1].Type != contracts.NodeAccount {
		t.Fatalf("account children = %+v", accounts.Items)
	}

	ous, err := s.ListChildren(ctx, contracts.ListChildrenInput{
		ParentID: root, ChildType: contracts.NodeOrganizationalUnit,
	})
	requireNoErr(t, err, "list OU children")
	if len(ous.Items) != 1 ||
		ous.Items[0] != (contracts.Node{ID: ou.ID, Type: contracts.NodeOrganizationalUnit}) {
		t.Fatalf("OU children = %+v", ous.Items)
	}

	_, err = s.ListChildren(ctx, contracts.ListChildrenInput{
		ParentID: "ou-abcd-zzzzzzzz", ChildType: contracts.NodeAccount,
	})
	requireErr(t, err, contracts.ErrParentNotFound)

	parents, err := s.ListParents(ctx, ou.ID, contracts.PageInput{})
	requireNoErr(t, err, "list parents of OU")
	if len(parents.Items) != 1 ||
		parents.Items[0] != (contracts.Node{ID: root, Type: contracts.NodeRoot}) {
		t.Fatalf("parents = %+v", parents.Items)
	}
	_, err = s.ListParents(ctx, "999999999999", contracts.PageInput{})
	requireErr(t, err, contracts.ErrChildNotFound)

	_, err = s.ListAccountsForParent(ctx, "ou-abcd-zzzzzzzz", contracts.PageInput{})
	requireErr(t, err, contracts.ErrParentNotFound)
	_, err = s.ListOrganizationalUnitsForParent(ctx, "ou-abcd-zzzzzzzz", contracts.PageInput{})
	requireErr(t, err, contracts.ErrParentNotFound)
}

func TestPagination(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)
	want := make([]string, 0, 5)
	want = append(want, managementID)
	for i := range 4 {
		want = append(want, createAccount(t, s, fmt.Sprintf("a%d", i)))
	}

	var got []string
	page := contracts.PageInput{MaxResults: 2}
	for {
		out, err := s.ListAccounts(ctx, page)
		requireNoErr(t, err, "list accounts")
		if len(out.Items) > 2 {
			t.Fatalf("page of %d, want at most 2", len(out.Items))
		}
		for _, a := range out.Items {
			got = append(got, a.ID)
		}
		if out.NextToken == "" {
			break
		}
		page.NextToken = out.NextToken
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("listed %v, want %v in the order they joined", got, want)
	}

	// An exact multiple of the page size ends without a dangling token.
	out, err := s.ListAccounts(ctx, contracts.PageInput{MaxResults: 5})
	requireNoErr(t, err, "list accounts")
	if len(out.Items) != 5 || out.NextToken != "" {
		t.Fatalf("got %d items and token %q, want 5 and none", len(out.Items), out.NextToken)
	}
}

func TestInvalidTokensAreRefused(t *testing.T) {
	ctx := context.Background()
	s, o := newOrgStore(t)
	root := rootID(t, s)
	for i := range 3 {
		createAccount(t, s, fmt.Sprintf("a%d", i))
	}

	first, err := s.ListAccounts(ctx, contracts.PageInput{MaxResults: 1})
	requireNoErr(t, err, "list accounts")
	if first.NextToken == "" {
		t.Fatal("no token for the next page")
	}

	tests := []struct {
		call func() error
		name string
	}{
		{name: "not base64", call: func() error {
			_, err := s.ListAccounts(ctx, contracts.PageInput{NextToken: "!!!"})
			return err
		}},
		{name: "made up", call: func() error {
			_, err := s.ListAccounts(ctx, contracts.PageInput{NextToken: "bm90LWEtdG9rZW4"})
			return err
		}},
		{name: "another listing's", call: func() error {
			_, err := s.ListAccountsForParent(ctx, root,
				contracts.PageInput{NextToken: first.NextToken})
			return err
		}},
		{name: "another scope's", call: func() error {
			tok := encodeToken(o.ID, listAccountsParent, "ou-abcd-zzzzzzzz", "1")
			_, err := s.ListAccountsForParent(ctx, root, contracts.PageInput{NextToken: tok})
			return err
		}},
		{name: "another organization's", call: func() error {
			tok := encodeToken("o-abcdefghij", listAccounts, "", "1")
			_, err := s.ListAccounts(ctx, contracts.PageInput{NextToken: tok})
			return err
		}},
		{name: "a cursor that is not a row", call: func() error {
			tok := encodeToken(o.ID, listAccounts, "", "x")
			_, err := s.ListAccounts(ctx, contracts.PageInput{NextToken: tok})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireErr(t, tt.call(), contracts.ErrInvalidToken)
		})
	}
}

func TestTokensDoNotOutliveTheirOrganization(t *testing.T) {
	// Rowids start over once the organization is deleted, so a token from the
	// old one would otherwise resume inside the new one.
	ctx := context.Background()
	s, _ := newOrgStore(t)
	id := createAccount(t, s, "dev")

	old, err := s.ListAccounts(ctx, contracts.PageInput{MaxResults: 1})
	requireNoErr(t, err, "list accounts")
	if old.NextToken == "" {
		t.Fatal("no token for the next page")
	}

	requireNoErr(t, s.RemoveAccountFromOrganization(ctx, id), "remove account")
	requireNoErr(t, s.DeleteOrganization(ctx), "delete organization")
	_, err = s.CreateOrganization(ctx, "")
	requireNoErr(t, err, "create organization again")
	createAccount(t, s, "dev")

	_, err = s.ListAccounts(ctx, contracts.PageInput{MaxResults: 1, NextToken: old.NextToken})
	requireErr(t, err, contracts.ErrInvalidToken)
}

func TestTags(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)
	root := rootID(t, s)
	ou := createOU(t, s, root, "Workloads")

	for _, id := range []string{root, ou.ID, managementID} {
		requireNoErr(t, s.TagResource(ctx, id, []contracts.Tag{
			{Key: "b", Value: "2"}, {Key: "a", Value: ""},
		}), "tag "+id)
		requireNoErr(t, s.TagResource(ctx, id, []contracts.Tag{{Key: "b", Value: "3"}}),
			"retag "+id)

		got, err := s.ListTagsForResource(ctx, id, contracts.PageInput{})
		requireNoErr(t, err, "list tags of "+id)
		want := []contracts.Tag{{Key: "a", Value: ""}, {Key: "b", Value: "3"}}
		if fmt.Sprint(got.Items) != fmt.Sprint(want) {
			t.Fatalf("tags of %s = %v, want %v in key order", id, got.Items, want)
		}

		requireNoErr(t, s.UntagResource(ctx, id, []string{"a", "missing"}), "untag "+id)
		got, err = s.ListTagsForResource(ctx, id, contracts.PageInput{})
		requireNoErr(t, err, "list tags of "+id)
		if len(got.Items) != 1 || got.Items[0].Key != "b" {
			t.Fatalf("tags of %s after untag = %v", id, got.Items)
		}
	}

	requireErr(t, s.TagResource(ctx, "999999999999", nil), contracts.ErrTargetNotFound)
	requireErr(t, s.UntagResource(ctx, "ou-abcd-zzzzzzzz", []string{"a"}),
		contracts.ErrTargetNotFound)
}

func TestTagLimit(t *testing.T) {
	ctx := context.Background()
	s, _ := newOrgStore(t)

	tags := make([]contracts.Tag, contracts.MaxTagsPerResource)
	for i := range tags {
		tags[i] = contracts.Tag{Key: fmt.Sprintf("k%02d", i)}
	}
	requireNoErr(t, s.TagResource(ctx, managementID, tags), "tag to the limit")
	// Changing a value of a key it has is not one more tag.
	requireNoErr(t, s.TagResource(ctx, managementID, []contracts.Tag{{Key: "k00", Value: "v"}}),
		"retag at the limit")
	requireErr(t, s.TagResource(ctx, managementID, []contracts.Tag{{Key: "one-more"}}),
		contracts.ErrTagLimitExceeded)

	// Tags page by key, 20 at a time by default.
	var count int
	page := contracts.PageInput{}
	for {
		out, err := s.ListTagsForResource(ctx, managementID, page)
		requireNoErr(t, err, "list tags")
		count += len(out.Items)
		if out.NextToken == "" {
			break
		}
		page.NextToken = out.NextToken
	}
	if count != contracts.MaxTagsPerResource {
		t.Fatalf("listed %d tags, want %d", count, contracts.MaxTagsPerResource)
	}
}

func TestDataOutlivesTheConnection(t *testing.T) {
	// The store is a file: what a connection committed is there for the
	// next one, which is what a restart relies on.
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "accounts.db")

	first := openStore(t, path)
	o, err := first.CreateOrganization(ctx, "")
	requireNoErr(t, err, "create organization")

	second := openStore(t, path)
	got, err := second.DescribeOrganization(ctx)
	requireNoErr(t, err, "describe organization")
	if got.ID != o.ID {
		t.Fatalf("organization = %s, want %s", got.ID, o.ID)
	}
}
