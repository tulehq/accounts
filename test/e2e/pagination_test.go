//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// pageSize is small enough that every listing below spans several pages.
const pageSize = 2

// paginated is a fixture with enough of everything to page through: the
// management account and four members in the root, and five OUs under it.
// Four members keep the organization under AWS's default quota of 10
// accounts.
type paginated struct {
	c        *awsorg.Client
	o        org
	accounts []string
	ous      []string
	requests []string
}

func newPaginated(t *testing.T) paginated {
	t.Helper()
	c, o := newOrg(t)
	p := paginated{c: c, o: o, accounts: []string{o.ManagementID}}
	for i := range 4 {
		st := createAccount(
			t,
			c,
			fmt.Sprintf("Member%d", i),
			fmt.Sprintf("member%d@example.com", i),
		)
		p.accounts = append(p.accounts, aws.ToString(st.AccountId))
		p.requests = append(p.requests, aws.ToString(st.Id))
	}
	for i := range 5 {
		p.ous = append(p.ous, createOU(t, c, o.RootID, fmt.Sprintf("Unit%d", i)))
	}
	return p
}

// walkPages reads every page from an SDK paginator and returns the IDs on
// them. MaxResults is the most a page may hold; a page may be shorter, even
// empty, while more remain (List* note in the reference), so only the upper
// bound is checked per page. With more items than pageSize, the walk must
// take more than one page.
func walkPages[O any](
	t *testing.T,
	more func() bool,
	next func(context.Context, ...func(*awsorg.Options)) (O, error),
	ids func(O) []string,
) []string {
	t.Helper()

	var got []string
	pages := 0
	for more() {
		out, err := next(t.Context())
		requireNoErr(t, err, "next page")
		pages++
		page := ids(out)
		if len(page) > pageSize {
			t.Fatalf("page %d holds %d items, MaxResults is %d", pages, len(page), pageSize)
		}
		got = append(got, page...)
		if pages > 50 {
			t.Fatal("paginator did not finish")
		}
	}
	if pages < 2 {
		t.Fatalf("%d items came in %d page(s) with MaxResults %d", len(got), pages, pageSize)
	}
	return got
}

// pageWalk reads one listing through its SDK paginator.
type pageWalk struct {
	walk func(*testing.T) []string
	name string
	want []string
}

func TestPaginatorsWalkEveryPage(t *testing.T) {
	p := newPaginated(t)

	for _, tt := range append(accountWalks(p), treeWalks(p)...) {
		t.Run(tt.name, func(t *testing.T) {
			requireSameIDs(t, tt.walk(t), tt.want)
		})
	}
}

// accountWalks lists the accounts in the root three ways.
func accountWalks(p paginated) []pageWalk {
	c := p.c
	limit := aws.Int32(pageSize)
	root := aws.String(p.o.RootID)
	return []pageWalk{
		{func(t *testing.T) []string {
			pg := awsorg.NewListAccountsPaginator(c, &awsorg.ListAccountsInput{MaxResults: limit})
			return walkPages(
				t,
				pg.HasMorePages,
				pg.NextPage,
				func(o *awsorg.ListAccountsOutput) []string {
					return accountIDList(o.Accounts)
				},
			)
		}, "ListAccounts", p.accounts},
		{func(t *testing.T) []string {
			pg := awsorg.NewListAccountsForParentPaginator(c, &awsorg.ListAccountsForParentInput{
				ParentId: root, MaxResults: limit,
			})
			return walkPages(
				t,
				pg.HasMorePages,
				pg.NextPage,
				func(o *awsorg.ListAccountsForParentOutput) []string { return accountIDList(o.Accounts) },
			)
		}, "ListAccountsForParent", p.accounts},
		{func(t *testing.T) []string {
			pg := awsorg.NewListChildrenPaginator(c, &awsorg.ListChildrenInput{
				ParentId: root, ChildType: types.ChildTypeAccount, MaxResults: limit,
			})
			return walkPages(t, pg.HasMorePages, pg.NextPage,
				func(o *awsorg.ListChildrenOutput) []string { return childIDList(o.Children) })
		}, "ListChildren accounts", p.accounts},
	}
}

// treeWalks lists the OUs and the create-account requests.
func treeWalks(p paginated) []pageWalk {
	c := p.c
	limit := aws.Int32(pageSize)
	root := aws.String(p.o.RootID)
	return []pageWalk{
		{func(t *testing.T) []string {
			pg := awsorg.NewListChildrenPaginator(c, &awsorg.ListChildrenInput{
				ParentId: root, ChildType: types.ChildTypeOrganizationalUnit, MaxResults: limit,
			})
			return walkPages(t, pg.HasMorePages, pg.NextPage,
				func(o *awsorg.ListChildrenOutput) []string { return childIDList(o.Children) })
		}, "ListChildren OUs", p.ous},
		{func(t *testing.T) []string {
			pg := awsorg.NewListOrganizationalUnitsForParentPaginator(c,
				&awsorg.ListOrganizationalUnitsForParentInput{ParentId: root, MaxResults: limit})
			return walkPages(t, pg.HasMorePages, pg.NextPage,
				func(o *awsorg.ListOrganizationalUnitsForParentOutput) []string {
					return ouIDList(o.OrganizationalUnits)
				})
		}, "ListOrganizationalUnitsForParent", p.ous},
		{func(t *testing.T) []string {
			pg := awsorg.NewListCreateAccountStatusPaginator(c,
				&awsorg.ListCreateAccountStatusInput{MaxResults: limit})
			return walkPages(
				t,
				pg.HasMorePages,
				pg.NextPage,
				func(o *awsorg.ListCreateAccountStatusOutput) []string { return statusIDList(o.CreateAccountStatuses) },
			)
		}, "ListCreateAccountStatus", p.requests},
	}
}

func TestSingleItemListsPaginate(t *testing.T) {
	c, o := newOrg(t)
	ctx := context.Background()

	roots := awsorg.NewListRootsPaginator(c, &awsorg.ListRootsInput{MaxResults: aws.Int32(1)})
	var rootIDs []string
	for roots.HasMorePages() {
		page, err := roots.NextPage(ctx)
		requireNoErr(t, err, "list roots page")
		for _, r := range page.Roots {
			rootIDs = append(rootIDs, aws.ToString(r.Id))
		}
	}
	requireSameIDs(t, rootIDs, []string{o.RootID})

	parents := awsorg.NewListParentsPaginator(c, &awsorg.ListParentsInput{
		ChildId: aws.String(o.ManagementID), MaxResults: aws.Int32(1),
	})
	var parentIDs []string
	for parents.HasMorePages() {
		page, err := parents.NextPage(ctx)
		requireNoErr(t, err, "list parents page")
		for _, p := range page.Parents {
			parentIDs = append(parentIDs, aws.ToString(p.Id))
		}
	}
	requireSameIDs(t, parentIDs, []string{o.RootID})
}

// listCalls calls each paginated operation once with the given MaxResults
// and NextToken.
func listCalls(c *awsorg.Client, o org) map[string]func(maxResults *int32, token *string) error {
	ctx := context.Background()
	root := aws.String(o.RootID)
	return map[string]func(*int32, *string) error{
		"ListAccounts": func(m *int32, tok *string) error {
			return errOf(
				c.ListAccounts(ctx, &awsorg.ListAccountsInput{MaxResults: m, NextToken: tok}),
			)
		},
		"ListAccountsForParent": func(m *int32, tok *string) error {
			return errOf(c.ListAccountsForParent(ctx, &awsorg.ListAccountsForParentInput{
				ParentId: root, MaxResults: m, NextToken: tok,
			}))
		},
		"ListChildren": func(m *int32, tok *string) error {
			return errOf(c.ListChildren(ctx, &awsorg.ListChildrenInput{
				ParentId: root, ChildType: types.ChildTypeAccount, MaxResults: m, NextToken: tok,
			}))
		},
		"ListOrganizationalUnitsForParent": func(m *int32, tok *string) error {
			return errOf(
				c.ListOrganizationalUnitsForParent(
					ctx,
					&awsorg.ListOrganizationalUnitsForParentInput{
						ParentId: root, MaxResults: m, NextToken: tok,
					},
				),
			)
		},
		"ListCreateAccountStatus": func(m *int32, tok *string) error {
			return errOf(c.ListCreateAccountStatus(ctx, &awsorg.ListCreateAccountStatusInput{
				MaxResults: m, NextToken: tok,
			}))
		},
		"ListRoots": func(m *int32, tok *string) error {
			return errOf(c.ListRoots(ctx, &awsorg.ListRootsInput{MaxResults: m, NextToken: tok}))
		},
		"ListParents": func(m *int32, tok *string) error {
			return errOf(c.ListParents(ctx, &awsorg.ListParentsInput{
				ChildId: aws.String(o.ManagementID), MaxResults: m, NextToken: tok,
			}))
		},
	}
}

func TestMaxResultsBounds(t *testing.T) {
	// MaxResults: "Valid Range: Minimum value of 1. Maximum value of 20." for
	// every paginated operation in scope (API reference). Out of range is
	// InvalidInputException MIN_VALUE_EXCEEDED / MAX_VALUE_EXCEEDED.
	c, o := newOrg(t)

	for name, call := range listCalls(c, o) {
		t.Run(name, func(t *testing.T) {
			requireNoErr(t, call(aws.Int32(1), nil), "MaxResults 1")
			requireNoErr(t, call(aws.Int32(20), nil), "MaxResults 20")
			requireInvalidInput(
				t,
				call(aws.Int32(0), nil),
				types.InvalidInputExceptionReasonMinValueExceeded,
			)
			requireInvalidInput(
				t,
				call(aws.Int32(21), nil),
				types.InvalidInputExceptionReasonMaxValueExceeded,
			)
		})
	}
}

func TestForeignNextTokenIsRejected(t *testing.T) {
	// INVALID_PAGINATION_TOKEN: "Get the value for the NextToken parameter
	// from the response to a previous call of the operation."
	c, o := newOrg(t)

	for name, call := range listCalls(c, o) {
		t.Run(name, func(t *testing.T) {
			requireInvalidInput(t, call(nil, aws.String("not-a-token-this-service-issued")),
				types.InvalidInputExceptionReasonInvalidPaginationToken)
		})
	}

	t.Run("ListTagsForResource", func(t *testing.T) {
		_, err := c.ListTagsForResource(t.Context(), &awsorg.ListTagsForResourceInput{
			ResourceId: aws.String(
				o.RootID,
			),
			NextToken: aws.String("not-a-token-this-service-issued"),
		})
		requireInvalidInput(t, err, types.InvalidInputExceptionReasonInvalidPaginationToken)
	})
}

func accountIDList(accounts []types.Account) []string {
	ids := make([]string, 0, len(accounts))
	for _, a := range accounts {
		ids = append(ids, aws.ToString(a.Id))
	}
	return ids
}

func childIDList(children []types.Child) []string {
	ids := make([]string, 0, len(children))
	for _, ch := range children {
		ids = append(ids, aws.ToString(ch.Id))
	}
	return ids
}

func ouIDList(ous []types.OrganizationalUnit) []string {
	ids := make([]string, 0, len(ous))
	for _, ou := range ous {
		ids = append(ids, aws.ToString(ou.Id))
	}
	return ids
}

func statusIDList(statuses []types.CreateAccountStatus) []string {
	ids := make([]string, 0, len(statuses))
	for _, s := range statuses {
		ids = append(ids, aws.ToString(s.Id))
	}
	return ids
}

// requireSameIDs fails unless got holds exactly the IDs in want, each once,
// in any order.
func requireSameIDs(t *testing.T, got, want []string) {
	t.Helper()
	g, w := slices.Clone(got), slices.Clone(want)
	slices.Sort(g)
	slices.Sort(w)
	if !slices.Equal(g, w) {
		t.Fatalf("IDs = %v, want %v (each once)", got, want)
	}
}
