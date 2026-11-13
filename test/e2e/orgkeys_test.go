//go:build e2e

package e2e

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// These tests hold identity policies with aws:PrincipalOrgID and
// aws:PrincipalOrgPaths conditions, against a real identity that asks this
// service for the keys. Identity keeps an account's keys for 30 seconds, so
// every account is placed before any of its principals signs a request.
// The unknown case, identity unable to ask this service, cannot arise while
// this service is answering the request, so it is a unit test of authz.

// orgKeysFixture is an organization with member account inOU in the OU ou
// and member account underRoot directly under the root.
type orgKeysFixture struct {
	s         *identityStack
	o         org
	ou        string
	inOU      string
	underRoot string
}

func TestOrganizationKeysAreSupplied(t *testing.T) {
	s := startIdentityStack(t)
	f := &orgKeysFixture{s: s, o: createOrg(t, s.root)}
	f.ou = createOU(t, s.root, f.o.RootID, "Engineering")
	f.inOU = createAccountID(t, s.root, "InOU", "in-ou@example.com")
	_, err := s.root.MoveAccount(t.Context(), &awsorg.MoveAccountInput{
		AccountId:           aws.String(f.inOU),
		SourceParentId:      aws.String(f.o.RootID),
		DestinationParentId: aws.String(f.ou),
	})
	requireNoErr(t, err, "move the account into the OU")
	f.underRoot = createAccountID(t, s.root, "UnderRoot", "under-root@example.com")

	t.Run("aws:PrincipalOrgID allows the management account's user", f.testManagementOrgID)
	t.Run("aws:PrincipalOrgPaths is the management account's path", f.testManagementOrgPaths)
	t.Run("a member account's user is allowed by its organization and path",
		f.testMemberAllowed)
	t.Run("a member account outside the path is refused", f.testMemberOutsidePath)
	t.Run("a removed account is refused", f.testRemovedAccount)
}

func (f *orgKeysFixture) path(parts ...string) string {
	p := f.o.ID + "/" + f.o.RootID + "/"
	for _, part := range parts {
		p += part + "/"
	}
	return p
}

func (f *orgKeysFixture) testManagementOrgID(t *testing.T) {
	c := f.s.userWithPolicy(t, "orgid", conditionDoc("organizations:ListRoots",
		`{"StringEquals":{"aws:PrincipalOrgID":"`+f.o.ID+`"}}`))
	_, err := c.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots with aws:PrincipalOrgID of the organization")

	putUserPolicy(t, f.s.iam, "orgid", conditionDoc("organizations:ListRoots",
		`{"StringEquals":{"aws:PrincipalOrgID":"o-zzzzzzzzzz"}}`))
	err = errOf(c.ListRoots(t.Context(), &awsorg.ListRootsInput{}))
	requireAccessDenied(t, err, "User: "+userARNPrefix+"orgid is not authorized to "+
		"perform: organizations:ListRoots on resource: * because no identity-based "+
		"policy allows the organizations:ListRoots action")

	// A Deny on any other organization does not apply.
	putUserPolicy(t, f.s.iam, "orgid", `{"Version":"2012-10-17","Statement":[`+
		`{"Effect":"Allow","Action":"organizations:ListRoots","Resource":"*"},`+
		`{"Effect":"Deny","Action":"organizations:ListRoots","Resource":"*",`+
		`"Condition":{"StringNotEquals":{"aws:PrincipalOrgID":"`+f.o.ID+`"}}}]}`)
	_, err = c.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots under a Deny on other organizations")
}

func (f *orgKeysFixture) testManagementOrgPaths(t *testing.T) {
	c := f.s.userWithPolicy(t, "orgpath", conditionDoc("organizations:ListRoots",
		`{"ForAnyValue:StringEquals":{"aws:PrincipalOrgPaths":"`+f.path()+`"}}`))
	_, err := c.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots with the management account's path")

	putUserPolicy(t, f.s.iam, "orgpath", conditionDoc("organizations:ListRoots",
		`{"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":"`+f.path(f.ou)+`*"}}`))
	err = errOf(c.ListRoots(t.Context(), &awsorg.ListRootsInput{}))
	requireAccessDenied(t, err, "User: "+userARNPrefix+"orgpath is not authorized to "+
		"perform: organizations:ListRoots on resource: * because no identity-based "+
		"policy allows the organizations:ListRoots action")
}

// ouDescribeDoc allows DescribeOrganization to a principal of the
// organization whose account is in the OU or below it.
func (f *orgKeysFixture) ouDescribeDoc() string {
	return conditionDoc("organizations:DescribeOrganization",
		`{"StringEquals":{"aws:PrincipalOrgID":"`+f.o.ID+`"},`+
			`"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":"`+f.path(f.ou)+`*"}}`)
}

// memberUser creates an IAM user in member with the policy doc, through a
// session of the member's OrganizationAccountAccessRole, and returns an
// Organizations client signed with its key.
func (f *orgKeysFixture) memberUser(t *testing.T, member, name, doc string) *awsorg.Client {
	t.Helper()
	ic := iamClient(f.s.identityURL, f.s.organizationRoleSession(t, member))
	key := createUserKey(t, ic, name)
	putUserPolicy(t, ic, name, doc)
	return orgClientWith(f.s.srv, key)
}

func (f *orgKeysFixture) testMemberAllowed(t *testing.T) {
	c := f.memberUser(t, f.inOU, "member", f.ouDescribeDoc())
	_, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization from the account in the OU")
}

func (f *orgKeysFixture) testMemberOutsidePath(t *testing.T) {
	c := f.memberUser(t, f.underRoot, "member", f.ouDescribeDoc())
	err := errOf(c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{}))
	requireAccessDenied(t, err, "User: arn:aws:iam::"+f.underRoot+":user/member is not "+
		"authorized to perform: organizations:DescribeOrganization on resource: * "+
		"because no identity-based policy allows the "+
		"organizations:DescribeOrganization action")
}

// testRemovedAccount removes an account whose user the conditions allow.
// A principal of an account outside the organization is refused before
// its policies are evaluated, as DescribeOrganization's errors say.
func (f *orgKeysFixture) testRemovedAccount(t *testing.T) {
	removed := createAccountID(t, f.s.root, "Removed", "removed@example.com")
	c := f.memberUser(t, removed, "member", conditionDoc("organizations:DescribeOrganization",
		`{"StringEquals":{"aws:PrincipalOrgID":"`+f.o.ID+`"}}`))
	_, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization while a member")

	_, err = f.s.root.RemoveAccountFromOrganization(t.Context(),
		&awsorg.RemoveAccountFromOrganizationInput{AccountId: aws.String(removed)})
	requireNoErr(t, err, "remove the member")
	requireAs[*types.AWSOrganizationsNotInUseException](t,
		errOf(c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})))
}

// TestOrganizationKeysAreAbsentWithoutAnOrganization evaluates a principal
// of an account in no organization: neither key is in its request, so a
// positive condition on them does not hold and a Null one does.
func TestOrganizationKeysAreAbsentWithoutAnOrganization(t *testing.T) {
	s := startIdentityStack(t)
	c := s.userWithPolicy(t, "outside", conditionDoc("organizations:CreateOrganization",
		`{"StringLike":{"aws:PrincipalOrgID":"o-*"}}`))
	err := errOf(c.CreateOrganization(t.Context(), &awsorg.CreateOrganizationInput{}))
	requireAccessDenied(t, err, "User: "+userARNPrefix+"outside is not authorized to "+
		"perform: organizations:CreateOrganization on resource: * because no "+
		"identity-based policy allows the organizations:CreateOrganization action")

	putUserPolicy(t, s.iam, "outside", conditionDoc("organizations:CreateOrganization",
		`{"Null":{"aws:PrincipalOrgID":"true","aws:PrincipalOrgPaths":"true"}}`))
	_, err = c.CreateOrganization(t.Context(), &awsorg.CreateOrganizationInput{})
	requireNoErr(t, err, "create organization with both keys absent")
}
