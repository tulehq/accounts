//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

func TestOrganizationalUnitLifecycle(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()

	created, err := c.CreateOrganizationalUnit(ctx, &awsorg.CreateOrganizationalUnitInput{
		ParentId: aws.String(o.RootID),
		Name:     aws.String("Workloads"),
		Tags:     []types.Tag{{Key: aws.String("team"), Value: aws.String("platform")}},
	})
	requireNoErr(t, err, "create OU")
	ou := *created.OrganizationalUnit
	id := aws.ToString(ou.Id)

	// "ou-" then the root's ID suffix, "-", and 8 to 32 more characters.
	requireMatch(t, ouIDPattern, id, "OU ID")
	if !strings.HasPrefix(id, "ou-"+o.rootSuffix()+"-") {
		t.Fatalf("OU ID %s does not carry the root suffix %s", id, o.rootSuffix())
	}
	arn := "arn:aws:organizations::" + o.ManagementID + ":ou/" + o.ID + "/" + id
	requireEqual(t, aws.ToString(ou.Arn), arn, "OU ARN")
	requireEqual(t, aws.ToString(ou.Name), "Workloads", "OU name")
	requireEqual(t, tagsOf(t, c, id)["team"], "platform", "tag from CreateOrganizationalUnit")

	described, err := c.DescribeOrganizationalUnit(ctx, &awsorg.DescribeOrganizationalUnitInput{
		OrganizationalUnitId: aws.String(id),
	})
	requireNoErr(t, err, "describe OU")
	requireEqual(t, aws.ToString(described.OrganizationalUnit.Id), id, "described ID")
	requireEqual(t, aws.ToString(described.OrganizationalUnit.Arn), arn, "described ARN")
	requireEqual(t, aws.ToString(described.OrganizationalUnit.Name), "Workloads", "described name")

	listed, err := c.ListOrganizationalUnitsForParent(
		ctx,
		&awsorg.ListOrganizationalUnitsForParentInput{
			ParentId: aws.String(o.RootID),
		},
	)
	requireNoErr(t, err, "list OUs for root")
	requireEqual(t, len(listed.OrganizationalUnits), 1, "OUs in root")
	requireEqual(t, aws.ToString(listed.OrganizationalUnits[0].Id), id, "listed OU")

	children := childrenOf(t, c, o.RootID, types.ChildTypeOrganizationalUnit)
	if len(children) != 1 || aws.ToString(children[0].Id) != id ||
		children[0].Type != types.ChildTypeOrganizationalUnit {
		t.Fatalf("OU children of root = %+v", children)
	}

	p := parentOf(t, c, id)
	requireEqual(t, aws.ToString(p.Id), o.RootID, "OU parent")
	requireEqual(t, p.Type, types.ParentTypeRoot, "OU parent type")
}

func TestNestedOURenameAndDelete(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()
	id := createOU(t, c, o.RootID, "Workloads")
	arn := "arn:aws:organizations::" + o.ManagementID + ":ou/" + o.ID + "/" + id

	nested := createOU(t, c, id, "Prod")
	np := parentOf(t, c, nested)
	requireEqual(t, aws.ToString(np.Id), id, "nested OU parent")
	requireEqual(t, np.Type, types.ParentTypeOrganizationalUnit, "nested OU parent type")
	if !strings.HasPrefix(nested, "ou-"+o.rootSuffix()+"-") {
		t.Fatalf("nested OU ID %s does not carry the root suffix", nested)
	}

	// UpdateOrganizationalUnit: "The ID and ARN don't change. The child OUs
	// and accounts remain in place".
	updated, err := c.UpdateOrganizationalUnit(ctx, &awsorg.UpdateOrganizationalUnitInput{
		OrganizationalUnitId: aws.String(id),
		Name:                 aws.String("Renamed"),
	})
	requireNoErr(t, err, "rename OU")
	requireEqual(t, aws.ToString(updated.OrganizationalUnit.Id), id, "ID after rename")
	requireEqual(t, aws.ToString(updated.OrganizationalUnit.Arn), arn, "ARN after rename")
	requireEqual(t, aws.ToString(updated.OrganizationalUnit.Name), "Renamed", "name after rename")
	requireEqual(t, aws.ToString(parentOf(t, c, nested).Id), id, "child after rename")

	for _, del := range []string{nested, id} {
		_, err = c.DeleteOrganizationalUnit(ctx, &awsorg.DeleteOrganizationalUnitInput{
			OrganizationalUnitId: aws.String(del),
		})
		requireNoErr(t, err, "delete OU "+del)
		_, err = c.DescribeOrganizationalUnit(ctx, &awsorg.DescribeOrganizationalUnitInput{
			OrganizationalUnitId: aws.String(del),
		})
		requireAs[*types.OrganizationalUnitNotFoundException](t, err)
	}
	requireEqual(t, len(childrenOf(t, c, o.RootID, types.ChildTypeOrganizationalUnit)), 0,
		"OUs in root after delete")
}

func TestListChildrenSeparatesAccountsAndOUs(t *testing.T) {
	c, o := newOrg(t)
	member := createAccountID(t, c, "Member", "member@example.com")
	ou := createOU(t, c, o.RootID, "Workloads")

	children := childrenOf(t, c, o.RootID, types.ChildTypeAccount)
	accounts := make([]string, 0, len(children))
	for _, ch := range children {
		requireEqual(t, ch.Type, types.ChildTypeAccount, "child type")
		accounts = append(accounts, aws.ToString(ch.Id))
	}
	slices.Sort(accounts)
	want := []string{o.ManagementID, member}
	slices.Sort(want)
	if !slices.Equal(accounts, want) {
		t.Fatalf("account children of root = %v, want %v", accounts, want)
	}

	ous := childrenOf(t, c, o.RootID, types.ChildTypeOrganizationalUnit)
	if len(ous) != 1 || aws.ToString(ous[0].Id) != ou {
		t.Fatalf("OU children of root = %+v, want [%s]", ous, ou)
	}
	requireEqual(t, len(childrenOf(t, c, ou, types.ChildTypeAccount)), 0, "accounts in empty OU")
}

func TestDuplicateOUNames(t *testing.T) {
	c, o := newOrg(t)
	first := createOU(t, c, o.RootID, "Workloads")
	other := createOU(t, c, o.RootID, "Sandbox")

	t.Run("same parent", func(t *testing.T) {
		_, err := c.CreateOrganizationalUnit(t.Context(), &awsorg.CreateOrganizationalUnitInput{
			ParentId: aws.String(o.RootID), Name: aws.String("Workloads"),
		})
		requireAs[*types.DuplicateOrganizationalUnitException](t, err)
	})

	t.Run("different parent", func(t *testing.T) {
		// Uniqueness is per parent; the same name one level down is fine.
		createOU(t, c, first, "Workloads")
	})

	t.Run("rename onto a sibling", func(t *testing.T) {
		_, err := c.UpdateOrganizationalUnit(t.Context(), &awsorg.UpdateOrganizationalUnitInput{
			OrganizationalUnitId: aws.String(other), Name: aws.String("Workloads"),
		})
		requireAs[*types.DuplicateOrganizationalUnitException](t, err)

		described, err := c.DescribeOrganizationalUnit(
			t.Context(),
			&awsorg.DescribeOrganizationalUnitInput{
				OrganizationalUnitId: aws.String(other),
			},
		)
		requireNoErr(t, err, "describe OU")
		requireEqual(
			t,
			aws.ToString(described.OrganizationalUnit.Name),
			"Sandbox",
			"name after rejected rename",
		)
	})
}

func TestOUDepthLimit(t *testing.T) {
	// Quotas for AWS Organizations: "OU maximum nesting in a root: Five
	// levels of OUs deep under a root." The sixth level is
	// ConstraintViolationException OU_DEPTH_LIMIT_EXCEEDED ("You attempted to
	// create an OU tree that is too many levels deep").
	c, o := newOrg(t)

	parent := o.RootID
	for level := 1; level <= 5; level++ {
		parent = createOU(t, c, parent, fmt.Sprintf("Level%d", level))
	}

	_, err := c.CreateOrganizationalUnit(
		context.Background(),
		&awsorg.CreateOrganizationalUnitInput{
			ParentId: aws.String(parent), Name: aws.String("Level6"),
		},
	)
	requireConstraint(t, err, types.ConstraintViolationExceptionReasonOuDepthLimitExceeded)
	requireEqual(t, len(childrenOf(t, c, parent, types.ChildTypeOrganizationalUnit)), 0,
		"OUs under the fifth level")
}

func TestDeleteNonEmptyOU(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()

	withOU := createOU(t, c, o.RootID, "HasChild")
	createOU(t, c, withOU, "Child")

	withAccount := createOU(t, c, o.RootID, "HasAccount")
	member := createAccountID(t, c, "Member", "member@example.com")
	_, err := c.MoveAccount(ctx, &awsorg.MoveAccountInput{
		AccountId: aws.String(member), SourceParentId: aws.String(o.RootID),
		DestinationParentId: aws.String(withAccount),
	})
	requireNoErr(t, err, "move account into OU")

	for name, id := range map[string]string{"child OU": withOU, "account": withAccount} {
		t.Run(name, func(t *testing.T) {
			_, err := c.DeleteOrganizationalUnit(t.Context(), &awsorg.DeleteOrganizationalUnitInput{
				OrganizationalUnitId: aws.String(id),
			})
			requireAs[*types.OrganizationalUnitNotEmptyException](t, err)

			_, err = c.DescribeOrganizationalUnit(
				t.Context(),
				&awsorg.DescribeOrganizationalUnitInput{
					OrganizationalUnitId: aws.String(id),
				},
			)
			requireNoErr(t, err, "describe OU after rejected delete")
		})
	}
}

// treeCase is a tree call made for its error, and the check on that error.
type treeCase struct {
	call  func() error
	check func(*testing.T, error)
	name  string
}

func runTreeCases(t *testing.T, c *awsorg.Client, o org, cases []treeCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t, tt.call())
		})
	}
	requireEqual(t, len(childrenOf(t, c, o.RootID, types.ChildTypeOrganizationalUnit)), 0,
		"OUs after rejected calls")
}

func TestTreeUnknownIDs(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()
	missing := aws.String(unknownOUID(o))
	root := aws.String(unknownRootID)

	runTreeCases(t, c, o, []treeCase{
		{func() error {
			return errOf(c.DescribeOrganizationalUnit(ctx,
				&awsorg.DescribeOrganizationalUnitInput{OrganizationalUnitId: missing}))
		}, asOUNotFound, "describe unknown OU"},
		{func() error {
			return errOf(c.UpdateOrganizationalUnit(ctx, &awsorg.UpdateOrganizationalUnitInput{
				OrganizationalUnitId: missing, Name: aws.String("x"),
			}))
		}, asOUNotFound, "update unknown OU"},
		{func() error {
			return errOf(c.DeleteOrganizationalUnit(ctx,
				&awsorg.DeleteOrganizationalUnitInput{OrganizationalUnitId: missing}))
		}, asOUNotFound, "delete unknown OU"},
		{func() error {
			return errOf(c.CreateOrganizationalUnit(ctx, &awsorg.CreateOrganizationalUnitInput{
				ParentId: root, Name: aws.String("x"),
			}))
		}, asParentNotFound, "create OU under unknown root"},
		{func() error {
			return errOf(c.CreateOrganizationalUnit(ctx, &awsorg.CreateOrganizationalUnitInput{
				ParentId: missing, Name: aws.String("x"),
			}))
		}, asParentNotFound, "create OU under unknown OU"},
		{func() error {
			return errOf(c.ListOrganizationalUnitsForParent(ctx,
				&awsorg.ListOrganizationalUnitsForParentInput{ParentId: missing}))
		}, asParentNotFound, "list OUs of unknown parent"},
		{func() error {
			return errOf(c.ListChildren(ctx, &awsorg.ListChildrenInput{
				ParentId: root, ChildType: types.ChildTypeAccount,
			}))
		}, asParentNotFound, "list children of unknown parent"},
		{func() error {
			return errOf(
				c.ListParents(ctx, &awsorg.ListParentsInput{ChildId: aws.String(unknownAccountID)}),
			)
		}, asChildNotFound, "list parents of unknown account"},
		{func() error {
			return errOf(c.ListParents(ctx, &awsorg.ListParentsInput{ChildId: missing}))
		}, asChildNotFound, "list parents of unknown OU"},
	})
}

func TestTreeMalformedIDs(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()

	runTreeCases(t, c, o, []treeCase{
		{func() error {
			return errOf(c.DescribeOrganizationalUnit(
				ctx,
				&awsorg.DescribeOrganizationalUnitInput{
					OrganizationalUnitId: aws.String("ou-abc"),
				},
			))
		}, invalidPattern, "describe malformed OU ID"},
		{func() error {
			return errOf(c.UpdateOrganizationalUnit(ctx, &awsorg.UpdateOrganizationalUnitInput{
				OrganizationalUnitId: aws.String("ou-ABCD-EFGHIJKL"), Name: aws.String("x"),
			}))
		}, invalidPattern, "update malformed OU ID"},
		{func() error {
			return errOf(c.DeleteOrganizationalUnit(ctx,
				&awsorg.DeleteOrganizationalUnitInput{OrganizationalUnitId: aws.String(o.RootID)}))
		}, invalidPattern, "delete malformed OU ID"},
		{func() error {
			return errOf(c.CreateOrganizationalUnit(ctx, &awsorg.CreateOrganizationalUnitInput{
				ParentId: aws.String("parent"), Name: aws.String("x"),
			}))
		}, invalidPattern, "create OU under malformed parent"},
		{func() error {
			return errOf(c.ListChildren(ctx, &awsorg.ListChildrenInput{
				ParentId: aws.String("r-"), ChildType: types.ChildTypeOrganizationalUnit,
			}))
		}, invalidPattern, "list children of malformed parent"},
		// ListParents takes an account or OU ID, "Don't specify a root"; the
		// pattern admits no root ID.
		{func() error {
			return errOf(
				c.ListParents(ctx, &awsorg.ListParentsInput{ChildId: aws.String(o.RootID)}),
			)
		}, invalidPattern, "list parents of malformed child"},
	})
}

func TestOUNameLength(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()
	create := func(name string) func() error {
		return func() error {
			return errOf(c.CreateOrganizationalUnit(ctx, &awsorg.CreateOrganizationalUnitInput{
				ParentId: aws.String(o.RootID), Name: aws.String(name),
			}))
		}
	}

	runTreeCases(t, c, o, []treeCase{
		// Name: length 1 to 128 (CreateOrganizationalUnit reference).
		{create(strings.Repeat("n", 129)), func(t *testing.T, err error) {
			t.Helper()
			requireInvalidInput(t, err, types.InvalidInputExceptionReasonMaxLengthExceeded)
		}, "OU name too long"},
		// Whether "" is INPUT_REQUIRED or MIN_LENGTH_EXCEEDED is not
		// documented, so only the type is asserted.
		{create(""), func(t *testing.T, err error) {
			t.Helper()
			requireAs[*types.InvalidInputException](t, err)
		}, "OU name empty"},
	})
}

func TestOUNameAtTheLimitIsAccepted(t *testing.T) {
	c, o := newOrg(t)
	name := strings.Repeat("n", 128)
	id := createOU(t, c, o.RootID, name)

	out, err := c.DescribeOrganizationalUnit(
		context.Background(),
		&awsorg.DescribeOrganizationalUnitInput{
			OrganizationalUnitId: aws.String(id),
		},
	)
	requireNoErr(t, err, "describe OU")
	requireEqual(t, aws.ToString(out.OrganizationalUnit.Name), name, "name")
}

func asOUNotFound(t *testing.T, err error) {
	t.Helper()
	requireAs[*types.OrganizationalUnitNotFoundException](t, err)
}

func asParentNotFound(t *testing.T, err error) {
	t.Helper()
	requireAs[*types.ParentNotFoundException](t, err)
}

func asChildNotFound(t *testing.T, err error) {
	t.Helper()
	requireAs[*types.ChildNotFoundException](t, err)
}

func invalidPattern(t *testing.T, err error) {
	t.Helper()
	requireInvalidInput(t, err, types.InvalidInputExceptionReasonInvalidPattern)
}

// childrenOf reads every page of ListChildren.
func childrenOf(
	t *testing.T,
	c *awsorg.Client,
	parentID string,
	kind types.ChildType,
) []types.Child {
	t.Helper()

	var all []types.Child
	p := awsorg.NewListChildrenPaginator(c, &awsorg.ListChildrenInput{
		ParentId: aws.String(parentID), ChildType: kind,
	})
	for p.HasMorePages() {
		page, err := p.NextPage(t.Context())
		requireNoErr(t, err, "list children of "+parentID)
		all = append(all, page.Children...)
	}
	return all
}
