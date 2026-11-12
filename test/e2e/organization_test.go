//go:build e2e

package e2e

import (
	"context"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

func TestEveryOperationNeedsAnOrganization(t *testing.T) {
	// AWSOrganizationsNotInUseException is in the Errors list of every
	// in-scope operation but CreateOrganization (API reference). The inputs
	// are well formed, so nothing but the missing organization can fail them.
	c := newClient(t)
	ctx := context.Background()

	calls := append(accountCallsWithoutOrg(ctx, c), treeCallsWithoutOrg(ctx, c)...)
	requireEqual(t, len(calls), 22, "operations covered")
	for _, tt := range calls {
		t.Run(tt.name, func(t *testing.T) {
			requireAs[*types.AWSOrganizationsNotInUseException](t, tt.call())
		})
	}
}

// namedCall is one API call made for its error alone.
type namedCall struct {
	call func() error
	name string
}

// Well-formed IDs for calls made before any organization exists.
const (
	idleAccountID = "111111111111"
	idleRootID    = "r-abcd"
	idleOUID      = "ou-abcd-abcdefgh"
)

// accountCallsWithoutOrg covers the organization and account operations.
func accountCallsWithoutOrg(ctx context.Context, c *awsorg.Client) []namedCall {
	acct := aws.String(idleAccountID)
	return []namedCall{
		{func() error {
			return errOf(c.DescribeOrganization(ctx, &awsorg.DescribeOrganizationInput{}))
		}, "DescribeOrganization"},
		{func() error {
			return errOf(c.DeleteOrganization(ctx, &awsorg.DeleteOrganizationInput{}))
		}, "DeleteOrganization"},
		{func() error {
			return errOf(c.CreateAccount(ctx, &awsorg.CreateAccountInput{
				AccountName: aws.String("Dev"), Email: aws.String("dev@example.com"),
			}))
		}, "CreateAccount"},
		{func() error {
			return errOf(
				c.DescribeCreateAccountStatus(ctx, &awsorg.DescribeCreateAccountStatusInput{
					CreateAccountRequestId: aws.String(unknownCarID),
				}),
			)
		}, "DescribeCreateAccountStatus"},
		{func() error {
			return errOf(c.ListCreateAccountStatus(ctx, &awsorg.ListCreateAccountStatusInput{}))
		}, "ListCreateAccountStatus"},
		{func() error {
			return errOf(c.DescribeAccount(ctx, &awsorg.DescribeAccountInput{AccountId: acct}))
		}, "DescribeAccount"},
		{func() error {
			return errOf(c.ListAccounts(ctx, &awsorg.ListAccountsInput{}))
		}, "ListAccounts"},
		{func() error {
			return errOf(c.ListAccountsForParent(ctx, &awsorg.ListAccountsForParentInput{
				ParentId: aws.String(idleRootID),
			}))
		}, "ListAccountsForParent"},
		{func() error {
			return errOf(c.CloseAccount(ctx, &awsorg.CloseAccountInput{AccountId: acct}))
		}, "CloseAccount"},
		{func() error {
			return errOf(c.RemoveAccountFromOrganization(ctx,
				&awsorg.RemoveAccountFromOrganizationInput{AccountId: acct}))
		}, "RemoveAccountFromOrganization"},
		{func() error {
			return errOf(c.MoveAccount(ctx, &awsorg.MoveAccountInput{
				AccountId: acct, SourceParentId: aws.String(idleRootID),
				DestinationParentId: aws.String(idleOUID),
			}))
		}, "MoveAccount"},
	}
}

// treeCallsWithoutOrg covers the tree and tag operations.
func treeCallsWithoutOrg(ctx context.Context, c *awsorg.Client) []namedCall {
	root, ou, acct := aws.String(idleRootID), aws.String(idleOUID), aws.String(idleAccountID)
	return []namedCall{
		{func() error {
			return errOf(c.ListRoots(ctx, &awsorg.ListRootsInput{}))
		}, "ListRoots"},
		{func() error {
			return errOf(c.ListParents(ctx, &awsorg.ListParentsInput{ChildId: acct}))
		}, "ListParents"},
		{func() error {
			return errOf(c.ListChildren(ctx, &awsorg.ListChildrenInput{
				ParentId: root, ChildType: types.ChildTypeAccount,
			}))
		}, "ListChildren"},
		{func() error {
			return errOf(c.CreateOrganizationalUnit(ctx, &awsorg.CreateOrganizationalUnitInput{
				ParentId: root, Name: aws.String("Workloads"),
			}))
		}, "CreateOrganizationalUnit"},
		{func() error {
			return errOf(c.DescribeOrganizationalUnit(ctx,
				&awsorg.DescribeOrganizationalUnitInput{OrganizationalUnitId: ou}))
		}, "DescribeOrganizationalUnit"},
		{func() error {
			return errOf(c.UpdateOrganizationalUnit(ctx, &awsorg.UpdateOrganizationalUnitInput{
				OrganizationalUnitId: ou, Name: aws.String("Renamed"),
			}))
		}, "UpdateOrganizationalUnit"},
		{func() error {
			return errOf(c.DeleteOrganizationalUnit(ctx,
				&awsorg.DeleteOrganizationalUnitInput{OrganizationalUnitId: ou}))
		}, "DeleteOrganizationalUnit"},
		{func() error {
			return errOf(c.ListOrganizationalUnitsForParent(ctx,
				&awsorg.ListOrganizationalUnitsForParentInput{ParentId: root}))
		}, "ListOrganizationalUnitsForParent"},
		{func() error {
			return errOf(c.TagResource(ctx, &awsorg.TagResourceInput{
				ResourceId: acct, Tags: []types.Tag{tag("k", "v")},
			}))
		}, "TagResource"},
		{func() error {
			return errOf(c.UntagResource(ctx, &awsorg.UntagResourceInput{
				ResourceId: acct, TagKeys: []string{"k"},
			}))
		}, "UntagResource"},
		{func() error {
			return errOf(
				c.ListTagsForResource(ctx, &awsorg.ListTagsForResourceInput{ResourceId: acct}),
			)
		}, "ListTagsForResource"},
	}
}

func TestCreateAndDescribeOrganization(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	created, err := c.CreateOrganization(ctx, &awsorg.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization")
	o := created.Organization

	id := aws.ToString(o.Id)
	requireMatch(t, orgIDPattern, id, "organization ID")
	// FeatureSet defaults to ALL (CreateOrganizationInput.FeatureSet).
	requireEqual(t, o.FeatureSet, types.OrganizationFeatureSetAll, "default feature set")
	requireEqual(t, aws.ToString(o.MasterAccountId), defaultManagementID, "MasterAccountId")
	// ARN formats: Service Authorization Reference, resource types for AWS
	// Organizations; the account ARN also matches the ListAccounts example.
	requireEqual(t, aws.ToString(o.Arn),
		"arn:aws:organizations::"+defaultManagementID+":organization/"+id, "organization ARN")
	requireEqual(t, aws.ToString(o.MasterAccountArn),
		"arn:aws:organizations::"+defaultManagementID+":account/"+id+"/"+defaultManagementID,
		"MasterAccountArn")
	if aws.ToString(o.MasterAccountEmail) == "" {
		t.Fatal("MasterAccountEmail is empty")
	}

	described, err := c.DescribeOrganization(ctx, &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization")
	d := described.Organization
	requireEqual(t, aws.ToString(d.Id), id, "described ID")
	requireEqual(t, aws.ToString(d.Arn), aws.ToString(o.Arn), "described ARN")
	requireEqual(t, d.FeatureSet, o.FeatureSet, "described feature set")
	requireEqual(t, aws.ToString(d.MasterAccountEmail), aws.ToString(o.MasterAccountEmail),
		"described MasterAccountEmail")

	// The management account is a member of the new organization, in the
	// root. It joined by INVITED: CreateOrganization logs
	// AccountJoinedOrganization with joinedMethod:INVITED, and the
	// ListAccounts example shows the management account as INVITED.
	roots, err := c.ListRoots(ctx, &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots")
	requireEqual(t, len(roots.Roots), 1, "root count")
	rootID := aws.ToString(roots.Roots[0].Id)

	mgmt := describeAccount(t, c, defaultManagementID)
	requireEqual(t, aws.ToString(mgmt.Id), defaultManagementID, "management account ID")
	requireEqual(t, mgmt.JoinedMethod, types.AccountJoinedMethodInvited, "management joined method")
	requireEqual(t, mgmt.State, types.AccountStateActive, "management state")
	requireEqual(t, mgmt.Status, types.AccountStatusActive, "management status")
	requireEqual(
		t,
		aws.ToString(mgmt.Email),
		aws.ToString(o.MasterAccountEmail),
		"management email",
	)
	requireEqual(t, aws.ToString(mgmt.Arn), aws.ToString(o.MasterAccountArn), "management ARN")
	if mgmt.JoinedTimestamp == nil {
		t.Fatal("management account has no JoinedTimestamp")
	}
	requireEqual(t, aws.ToString(parentOf(t, c, defaultManagementID).Id), rootID,
		"management account parent")
	if !slices.Equal(accountIDs(t, c), []string{defaultManagementID}) {
		t.Fatalf("accounts = %v, want only the management account", accountIDs(t, c))
	}
}

func TestRootOfANewOrganization(t *testing.T) {
	c, o := newOrg(t)

	roots, err := c.ListRoots(context.Background(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots")
	r := roots.Roots[0]

	requireMatch(t, rootIDPattern, aws.ToString(r.Id), "root ID")
	requireEqual(t, aws.ToString(r.Name), "Root", "root name")
	requireEqual(t, aws.ToString(r.Arn),
		"arn:aws:organizations::"+o.ManagementID+":root/"+o.ID+"/"+aws.ToString(r.Id), "root ARN")

	// CreateOrganization: with FeatureSet ALL the organization is created
	// "with all features enabled and service control policies automatically
	// enabled in the root".
	want := []types.PolicyTypeSummary{{
		Type: types.PolicyTypeServiceControlPolicy, Status: types.PolicyTypeStatusEnabled,
	}}
	if !slices.Equal(r.PolicyTypes, want) {
		t.Fatalf("root policy types = %+v, want SCP enabled", r.PolicyTypes)
	}
}

func TestConsolidatedBillingOrganization(t *testing.T) {
	c := newClient(t)
	ctx := context.Background()

	created, err := c.CreateOrganization(ctx, &awsorg.CreateOrganizationInput{
		FeatureSet: types.OrganizationFeatureSetConsolidatedBilling,
	})
	requireNoErr(t, err, "create organization")
	requireEqual(
		t,
		created.Organization.FeatureSet,
		types.OrganizationFeatureSetConsolidatedBilling,
		"feature set",
	)

	// CreateOrganization: with CONSOLIDATED_BILLING "no policy types are
	// enabled by default".
	roots, err := c.ListRoots(ctx, &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots")
	requireEqual(t, len(roots.Roots[0].PolicyTypes), 0, "root policy types")
}

func TestSecondOrganizationIsRejected(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()

	_, err := c.CreateOrganization(ctx, &awsorg.CreateOrganizationInput{})
	requireAs[*types.AlreadyInOrganizationException](t, err)

	described, err := c.DescribeOrganization(ctx, &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization")
	requireEqual(
		t,
		aws.ToString(described.Organization.Id),
		o.ID,
		"organization after rejected create",
	)
}

func TestDeleteOrganizationWithMembersIsRejected(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()
	member := createAccountID(t, c, "Member", "member@example.com")

	_, err := c.DeleteOrganization(ctx, &awsorg.DeleteOrganizationInput{})
	requireAs[*types.OrganizationNotEmptyException](t, err)

	described, err := c.DescribeOrganization(ctx, &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization after rejected delete")
	requireEqual(t, aws.ToString(described.Organization.Id), o.ID, "organization ID")

	// Once the member is gone, the management account is the only member
	// and the delete succeeds.
	_, err = c.RemoveAccountFromOrganization(ctx, &awsorg.RemoveAccountFromOrganizationInput{
		AccountId: aws.String(member),
	})
	requireNoErr(t, err, "remove member")
	_, err = c.DeleteOrganization(ctx, &awsorg.DeleteOrganizationInput{})
	requireNoErr(t, err, "delete organization")

	_, err = c.DescribeOrganization(ctx, &awsorg.DescribeOrganizationInput{})
	requireAs[*types.AWSOrganizationsNotInUseException](t, err)
}

func TestDeleteThenCreateStartsEmpty(t *testing.T) {
	c, first := newOrg(t)
	ctx := context.Background()

	// An OU, tags on the root and a create-account record whose account has
	// since been removed; the organization has no member accounts, which is
	// all DeleteOrganization requires ("The organization must be empty of
	// member accounts").
	createOU(t, c, first.RootID, "Workloads")
	_, err := c.TagResource(ctx, &awsorg.TagResourceInput{
		ResourceId: aws.String(first.RootID),
		Tags:       []types.Tag{{Key: aws.String("env"), Value: aws.String("dev")}},
	})
	requireNoErr(t, err, "tag root")
	created := createAccount(t, c, "Transient", "transient@example.com")
	_, err = c.RemoveAccountFromOrganization(ctx, &awsorg.RemoveAccountFromOrganizationInput{
		AccountId: created.AccountId,
	})
	requireNoErr(t, err, "remove the member")

	_, err = c.DeleteOrganization(ctx, &awsorg.DeleteOrganizationInput{})
	requireNoErr(t, err, "delete organization")

	second := createOrg(t, c)
	if second.ID == first.ID {
		t.Fatalf("new organization reused ID %s", first.ID)
	}

	ous, err := c.ListOrganizationalUnitsForParent(
		ctx,
		&awsorg.ListOrganizationalUnitsForParentInput{
			ParentId: aws.String(second.RootID),
		},
	)
	requireNoErr(t, err, "list OUs of the new root")
	requireEqual(t, len(ous.OrganizationalUnits), 0, "OUs in the new organization")

	requireEqual(t, len(tagsOf(t, c, second.RootID)), 0, "tags on the new root")

	statuses, err := c.ListCreateAccountStatus(ctx, &awsorg.ListCreateAccountStatusInput{})
	requireNoErr(t, err, "list create account status")
	requireEqual(t, len(statuses.CreateAccountStatuses), 0, "create account records")

	_, err = c.DescribeCreateAccountStatus(ctx, &awsorg.DescribeCreateAccountStatusInput{
		CreateAccountRequestId: created.Id,
	})
	requireAs[*types.CreateAccountStatusNotFoundException](t, err)

	if !slices.Equal(accountIDs(t, c), []string{defaultManagementID}) {
		t.Fatalf("accounts = %v, want only the management account", accountIDs(t, c))
	}
}
