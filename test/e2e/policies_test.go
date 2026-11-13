//go:build e2e

package e2e

import (
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsorg "github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// These tests hold identity-issued keys to their IAM policies, against a
// real identity, as identity_test.go runs it.

const userARNPrefix = "arn:aws:iam::" + defaultManagementID + ":user/"

// policyFixture is an organization with two member accounts, A tagged
// team=ops, under an identity stack.
type policyFixture struct {
	s    *identityStack
	o    org
	a, b string
}

func TestIdentityPoliciesAreEnforced(t *testing.T) {
	s := startIdentityStack(t)
	f := &policyFixture{s: s, o: createOrg(t, s.root)}
	f.a = createAccountID(t, s.root, "A", "a@example.com")
	f.b = createAccountID(t, s.root, "B", "b@example.com")
	_, err := s.root.TagResource(t.Context(), &awsorg.TagResourceInput{
		ResourceId: aws.String(f.a),
		Tags:       []types.Tag{{Key: aws.String("team"), Value: aws.String("ops")}},
	})
	requireNoErr(t, err, "tag account A")

	t.Run("a user with no policy is denied", f.testNoPolicy)
	t.Run("a policy allows exactly its action", f.testOneAction)
	t.Run("a resource-scoped policy allows that resource only", f.testResourceScoped)
	t.Run("an operation on several resources needs each", f.testSeveralResources)
	t.Run("an explicit deny beats an allow", f.testExplicitDeny)
	t.Run("aws:SourceIp is honored", f.testSourceIP)
	t.Run("aws:RequestedRegion is the service's whatever the signature", f.testRequestedRegion)
	t.Run("aws:ResourceTag and aws:RequestTag are honored", f.testTagConditions)
	t.Run("a create with tags also needs TagResource", f.testTagOnCreate)
	t.Run("a role session gets the role's permissions", s.testRolePermissions)
	t.Run("aws:PrincipalArn is a session's role ARN with its path", s.testRolePathCondition)
	t.Run("aws:PrincipalTag is honored", s.testPrincipalTag)
	t.Run("a session whose role was deleted is refused", s.testOrphanedSession)
	t.Run("a member account's session is refused but DescribeOrganization", f.testMemberAccount)
	t.Run("a removed or closed account may not describe the organization",
		f.testFormerMember)
	t.Run("the root key is always allowed", f.testRootKey)
}

func (f *policyFixture) accountARN(id string) string {
	return "arn:aws:organizations::" + defaultManagementID + ":account/" + f.o.ID + "/" + id
}

func (f *policyFixture) testNoPolicy(t *testing.T) {
	c := orgClientWith(f.s.srv, createUserKey(t, f.s.iam, "nopolicy"))
	err := errOf(c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{}))
	requireAccessDenied(t, err, "User: "+userARNPrefix+"nopolicy is not authorized to "+
		"perform: organizations:DescribeOrganization on resource: * because no "+
		"identity-based policy allows the organizations:DescribeOrganization action")
}

func (f *policyFixture) testOneAction(t *testing.T) {
	c := f.s.userWithPolicy(t, "lister", allowDoc("organizations:ListAccounts", "*"))
	requireEqual(t, len(accountIDs(t, c)), 3, "accounts listed")
	err := errOf(c.ListRoots(t.Context(), &awsorg.ListRootsInput{}))
	requireAccessDenied(t, err, "User: "+userARNPrefix+"lister is not authorized to "+
		"perform: organizations:ListRoots on resource: * because no identity-based "+
		"policy allows the organizations:ListRoots action")
	err = errOf(c.DescribeAccount(t.Context(),
		&awsorg.DescribeAccountInput{AccountId: aws.String(f.a)}))
	requireCode(t, err, "AccessDeniedException")
}

func (f *policyFixture) testResourceScoped(t *testing.T) {
	c := f.s.userWithPolicy(t, "scoped",
		allowDoc("organizations:DescribeAccount", f.accountARN(f.a)))
	requireEqual(t, aws.ToString(describeAccount(t, c, f.a).Id), f.a, "account A")
	err := errOf(c.DescribeAccount(t.Context(),
		&awsorg.DescribeAccountInput{AccountId: aws.String(f.b)}))
	requireAccessDenied(t, err, "User: "+userARNPrefix+"scoped is not authorized to "+
		"perform: organizations:DescribeAccount on resource: "+f.accountARN(f.b)+
		" because no identity-based policy allows the organizations:DescribeAccount action")
}

func (f *policyFixture) testSeveralResources(t *testing.T) {
	ou := createOU(t, f.s.root, f.o.RootID, "Target")
	c := f.s.userWithPolicy(t, "mover",
		allowDoc("organizations:MoveAccount", f.accountARN(f.b)))
	err := errOf(c.MoveAccount(t.Context(), &awsorg.MoveAccountInput{
		AccountId:           aws.String(f.b),
		SourceParentId:      aws.String(f.o.RootID),
		DestinationParentId: aws.String(ou),
	}))
	requireAccessDenied(t, err, "User: "+userARNPrefix+"mover is not authorized to "+
		"perform: organizations:MoveAccount on resource: arn:aws:organizations::"+
		defaultManagementID+":root/"+f.o.ID+"/"+f.o.RootID+
		" because no identity-based policy allows the organizations:MoveAccount action")
	requireEqual(t, aws.ToString(parentOf(t, f.s.root, f.b).Id), f.o.RootID, "B's parent")
}

func (f *policyFixture) testExplicitDeny(t *testing.T) {
	c := f.s.userWithPolicy(t, "denied", `{"Version":"2012-10-17","Statement":[`+
		`{"Effect":"Allow","Action":"organizations:*","Resource":"*"},`+
		`{"Effect":"Deny","Action":"organizations:DescribeAccount","Resource":"*"}]}`)
	_, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization")
	err = errOf(c.DescribeAccount(t.Context(),
		&awsorg.DescribeAccountInput{AccountId: aws.String(f.a)}))
	requireAccessDenied(t, err, "User: "+userARNPrefix+"denied is not authorized to "+
		"perform: organizations:DescribeAccount on resource: "+f.accountARN(f.a)+
		" with an explicit deny in an identity-based policy")
}

func (f *policyFixture) testSourceIP(t *testing.T) {
	local := f.s.userWithPolicy(t, "local", conditionDoc("organizations:ListRoots",
		`{"IpAddress":{"aws:SourceIp":"127.0.0.0/8"}}`))
	_, err := local.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots from loopback")

	remote := f.s.userWithPolicy(t, "remote", conditionDoc("organizations:ListRoots",
		`{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}`))
	requireCode(t, errOf(remote.ListRoots(t.Context(), &awsorg.ListRootsInput{})),
		"AccessDeniedException")
}

func (f *policyFixture) testTagConditions(t *testing.T) {
	c := f.s.userWithPolicy(t, "tagger", `{"Version":"2012-10-17","Statement":[`+
		`{"Effect":"Allow","Action":"organizations:DescribeAccount","Resource":"*",`+
		`"Condition":{"StringEquals":{"aws:ResourceTag/team":"ops"}}},`+
		`{"Effect":"Allow","Action":"organizations:TagResource","Resource":"*",`+
		`"Condition":{"StringEquals":{"aws:RequestTag/env":"dev"}}}]}`)
	describeAccount(t, c, f.a)
	requireCode(t, errOf(c.DescribeAccount(t.Context(),
		&awsorg.DescribeAccountInput{AccountId: aws.String(f.b)})), "AccessDeniedException")

	tag := func(value string) error {
		return errOf(c.TagResource(t.Context(), &awsorg.TagResourceInput{
			ResourceId: aws.String(f.b),
			Tags:       []types.Tag{{Key: aws.String("env"), Value: aws.String(value)}},
		}))
	}
	requireNoErr(t, tag("dev"), "tag env=dev")
	requireCode(t, tag("prod"), "AccessDeniedException")
	requireEqual(t, tagsOf(t, f.s.root, f.b)["env"], "dev", "B's env tag")
}

func (f *policyFixture) testMemberAccount(t *testing.T) {
	c := orgClientWith(f.s.srv, f.s.organizationRoleSession(t, f.a))
	_, err := c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{})
	requireNoErr(t, err, "describe organization from the member account")
	for name, call := range map[string]func() error{
		"DescribeAccount": func() error {
			return errOf(c.DescribeAccount(t.Context(),
				&awsorg.DescribeAccountInput{AccountId: aws.String(f.a)}))
		},
		"ListAccounts": func() error {
			return errOf(c.ListAccounts(t.Context(), &awsorg.ListAccountsInput{}))
		},
	} {
		t.Run(name, func(t *testing.T) {
			requireAccessDenied(t, call(),
				"You don't have permissions to access this resource.")
		})
	}
}

func (f *policyFixture) testRootKey(t *testing.T) {
	_, err := f.s.root.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots with the root key")
	describeAccount(t, f.s.root, f.b)
}

func (f *policyFixture) testTagOnCreate(t *testing.T) {
	c := f.s.userWithPolicy(t, "creator",
		allowDoc("organizations:CreateOrganizationalUnit", "*"))
	create := func(name string, tags ...types.Tag) error {
		return errOf(c.CreateOrganizationalUnit(t.Context(),
			&awsorg.CreateOrganizationalUnitInput{
				ParentId: aws.String(f.o.RootID), Name: aws.String(name), Tags: tags,
			}))
	}
	requireNoErr(t, create("Untagged"), "create an OU without tags")
	env := types.Tag{Key: aws.String("env"), Value: aws.String("dev")}
	requireAccessDenied(t, create("Tagged", env), "User: "+userARNPrefix+"creator is not "+
		"authorized to perform: organizations:TagResource on resource: * because no "+
		"identity-based policy allows the organizations:TagResource action")

	putUserPolicy(t, f.s.iam, "creator", `{"Version":"2012-10-17","Statement":[`+
		`{"Effect":"Allow","Action":"organizations:CreateOrganizationalUnit","Resource":"*"},`+
		`{"Effect":"Allow","Action":"organizations:TagResource","Resource":"*",`+
		`"Condition":{"StringEquals":{"aws:RequestTag/env":"dev"}}}]}`)
	requireNoErr(t, create("Tagged", env), "create an OU tagged env=dev")
	prod := types.Tag{Key: aws.String("env"), Value: aws.String("prod")}
	requireCode(t, create("Prod", prod), "AccessDeniedException")
}

// testFormerMember takes sessions in two new member accounts, removes one
// from the organization and closes the other, and describes the
// organization with each session.
func (f *policyFixture) testFormerMember(t *testing.T) {
	removed := createAccountID(t, f.s.root, "Removed", "removed@example.com")
	closed := createAccountID(t, f.s.root, "Closed", "closed@example.com")
	removedSession := orgClientWith(f.s.srv, f.s.organizationRoleSession(t, removed))
	closedSession := orgClientWith(f.s.srv, f.s.organizationRoleSession(t, closed))
	describe := func(c *awsorg.Client) error {
		return errOf(c.DescribeOrganization(t.Context(), &awsorg.DescribeOrganizationInput{}))
	}
	requireNoErr(t, describe(removedSession), "describe organization while a member")

	_, err := f.s.root.RemoveAccountFromOrganization(t.Context(),
		&awsorg.RemoveAccountFromOrganizationInput{AccountId: aws.String(removed)})
	requireNoErr(t, err, "remove the member")
	requireAs[*types.AWSOrganizationsNotInUseException](t, describe(removedSession))

	_, err = f.s.root.CloseAccount(t.Context(),
		&awsorg.CloseAccountInput{AccountId: aws.String(closed)})
	requireNoErr(t, err, "close the member")
	requireAccessDenied(t, describe(closedSession),
		"You don't have permissions to access this resource.")
}

func (f *policyFixture) testRequestedRegion(t *testing.T) {
	key := createUserKey(t, f.s.iam, "regional")
	putUserPolicy(t, f.s.iam, "regional", `{"Version":"2012-10-17","Statement":[`+
		`{"Effect":"Allow","Action":"organizations:ListRoots","Resource":"*"},`+
		`{"Effect":"Deny","Action":"organizations:ListRoots","Resource":"*",`+
		`"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}`)
	elsewhere := clientFor(f.s.srv, func(o *awsorg.Options) {
		o.Credentials = credentials.StaticCredentialsProvider{Value: key}
		o.Region = "eu-west-1"
		o.RetryMaxAttempts = 1
	})
	requireAccessDenied(t, errOf(elsewhere.ListRoots(t.Context(), &awsorg.ListRootsInput{})),
		"User: "+userARNPrefix+"regional is not authorized to perform: "+
			"organizations:ListRoots on resource: * with an explicit deny in an "+
			"identity-based policy")
}

// testRolePermissions creates a role in the management account that trusts
// a user with no policy of its own, gives the role one permission, and
// calls accounts with a session of it.
func (s *identityStack) testRolePermissions(t *testing.T) {
	userKey := createUserKey(t, s.iam, "assumer")
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"AWS":"` + userARNPrefix + `assumer"},"Action":"sts:AssumeRole"}]}`
	_, err := s.iam.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String("auditor"),
		Path:                     aws.String("/audit/"),
		AssumeRolePolicyDocument: aws.String(trust),
	})
	requireNoErr(t, err, "create role")
	_, err = s.iam.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
		RoleName:       aws.String("auditor"),
		PolicyName:     aws.String("list"),
		PolicyDocument: aws.String(allowDoc("organizations:ListAccounts", "*")),
	})
	requireNoErr(t, err, "put role policy")

	out, err := stsClient(s.identityURL, userKey).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::" + defaultManagementID + ":role/audit/auditor"),
		RoleSessionName: aws.String("e2e"),
	})
	requireNoErr(t, err, "assume role")
	c := orgClientWith(s.srv, aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	})

	accountIDs(t, c)
	err = errOf(c.ListRoots(t.Context(), &awsorg.ListRootsInput{}))
	requireAccessDenied(t, err, "User: arn:aws:sts::"+defaultManagementID+
		":assumed-role/auditor/e2e is not authorized to perform: organizations:ListRoots "+
		"on resource: * because no identity-based policy allows the "+
		"organizations:ListRoots action")

	// The IAM user's own key has none of the role's permissions.
	requireCode(t, errOf(orgClientWith(s.srv, userKey).ListAccounts(t.Context(),
		&awsorg.ListAccountsInput{})), "AccessDeniedException")
}

// roleSession creates a role at path that trusts the IAM user assumer, with
// the inline policy doc and tags, and returns a client signing with a
// session of it named e2e.
func (s *identityStack) roleSession(
	t *testing.T, assumer aws.Credentials, assumerName, path, name, doc string,
	tags ...iamtypes.Tag,
) *awsorg.Client {
	t.Helper()
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow",` +
		`"Principal":{"AWS":"` + userARNPrefix + assumerName + `"},"Action":"sts:AssumeRole"}]}`
	_, err := s.iam.CreateRole(t.Context(), &iam.CreateRoleInput{
		RoleName:                 aws.String(name),
		Path:                     aws.String(path),
		AssumeRolePolicyDocument: aws.String(trust),
		Tags:                     tags,
	})
	requireNoErr(t, err, "create role "+name)
	_, err = s.iam.PutRolePolicy(t.Context(), &iam.PutRolePolicyInput{
		RoleName:       aws.String(name),
		PolicyName:     aws.String("organizations"),
		PolicyDocument: aws.String(doc),
	})
	requireNoErr(t, err, "put a policy for role "+name)
	out, err := stsClient(s.identityURL, assumer).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::" + defaultManagementID + ":role" + path + name),
		RoleSessionName: aws.String("e2e"),
	})
	requireNoErr(t, err, "assume role "+name)
	return orgClientWith(s.srv, aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	})
}

// testRolePathCondition gives a role at /deploy/ an Allow conditioned on
// its ARN with the path and a Deny on any role under that path: the
// session's aws:PrincipalArn is the role's ARN with its path, so both
// apply.
func (s *identityStack) testRolePathCondition(t *testing.T) {
	c := s.roleSession(t, createUserKey(t, s.iam, "deployer"), "deployer", "/deploy/",
		"release", `{"Version":"2012-10-17","Statement":[`+
			`{"Effect":"Allow","Action":["organizations:ListRoots","organizations:ListAccounts"],`+
			`"Resource":"*","Condition":{"ArnEquals":{"aws:PrincipalArn":`+
			`"arn:aws:iam::`+defaultManagementID+`:role/deploy/release"}}},`+
			`{"Effect":"Deny","Action":"organizations:ListAccounts","Resource":"*",`+
			`"Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/deploy/*"}}}]}`)

	_, err := c.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots, allowed on the role ARN with its path")
	err = errOf(c.ListAccounts(t.Context(), &awsorg.ListAccountsInput{}))
	requireAccessDenied(t, err, "User: arn:aws:sts::"+defaultManagementID+
		":assumed-role/release/e2e is not authorized to perform: "+
		"organizations:ListAccounts on resource: * with an explicit deny in an "+
		"identity-based policy")
}

// testPrincipalTag allows ListRoots to principals tagged team=ops: an IAM
// user tagged so, and a session of a role tagged so, are allowed; an
// untagged user with the same policy is not.
func (s *identityStack) testPrincipalTag(t *testing.T) {
	doc := conditionDoc("organizations:ListRoots",
		`{"StringEquals":{"aws:PrincipalTag/team":"ops"}}`)
	ops := []iamtypes.Tag{{Key: aws.String("team"), Value: aws.String("ops")}}

	tagged := s.userWithPolicy(t, "tagged", doc)
	_, err := s.iam.TagUser(t.Context(), &iam.TagUserInput{
		UserName: aws.String("tagged"), Tags: ops,
	})
	requireNoErr(t, err, "tag user")
	_, err = tagged.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots as a user tagged team=ops")

	untagged := s.userWithPolicy(t, "untagged", doc)
	err = errOf(untagged.ListRoots(t.Context(), &awsorg.ListRootsInput{}))
	requireAccessDenied(t, err, "User: "+userARNPrefix+"untagged is not authorized to "+
		"perform: organizations:ListRoots on resource: * because no identity-based "+
		"policy allows the organizations:ListRoots action")

	session := s.roleSession(t, createUserKey(t, s.iam, "opsassumer"), "opsassumer", "/",
		"opsrole", doc, ops...)
	_, err = session.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots as a session of a role tagged team=ops")
}

// testOrphanedSession takes a session of a role, deletes the role, and
// calls with the session, which still authenticates until it expires.
func (s *identityStack) testOrphanedSession(t *testing.T) {
	c := s.roleSession(t, createUserKey(t, s.iam, "orphaner"), "orphaner", "/",
		"doomed", allowDoc("organizations:ListRoots", "*"))
	_, err := c.ListRoots(t.Context(), &awsorg.ListRootsInput{})
	requireNoErr(t, err, "list roots while the role exists")

	_, err = s.iam.DeleteRolePolicy(t.Context(), &iam.DeleteRolePolicyInput{
		RoleName: aws.String("doomed"), PolicyName: aws.String("organizations"),
	})
	requireNoErr(t, err, "delete the role's policy")
	_, err = s.iam.DeleteRole(t.Context(), &iam.DeleteRoleInput{RoleName: aws.String("doomed")})
	requireNoErr(t, err, "delete the role")

	err = errOf(c.ListRoots(t.Context(), &awsorg.ListRootsInput{}))
	requireAccessDenied(t, err, "User: arn:aws:sts::"+defaultManagementID+
		":assumed-role/doomed/e2e is not authorized to perform: organizations:ListRoots "+
		"on resource: * because no identity-based policy allows the "+
		"organizations:ListRoots action")
}

func TestStandaloneEvaluatesNothing(t *testing.T) {
	c, o := newOrg(t)
	id := createAccountID(t, c, "A", "a@example.com")
	ou := createOU(t, c, o.RootID, "OU")
	_, err := c.MoveAccount(t.Context(), &awsorg.MoveAccountInput{
		AccountId: aws.String(id), SourceParentId: aws.String(o.RootID),
		DestinationParentId: aws.String(ou),
	})
	requireNoErr(t, err, "move account with the static key")
	_, err = c.DeleteOrganizationalUnit(t.Context(),
		&awsorg.DeleteOrganizationalUnitInput{OrganizationalUnitId: aws.String(ou)})
	requireCode(t, err, "OrganizationalUnitNotEmptyException")
}

// userWithPolicy creates an IAM user with the inline policy doc and returns
// a client signing with its key.
func (s *identityStack) userWithPolicy(t *testing.T, name, doc string) *awsorg.Client {
	t.Helper()
	key := createUserKey(t, s.iam, name)
	putUserPolicy(t, s.iam, name, doc)
	return orgClientWith(s.srv, key)
}

func putUserPolicy(t *testing.T, ic *iam.Client, user, doc string) {
	t.Helper()
	_, err := ic.PutUserPolicy(t.Context(), &iam.PutUserPolicyInput{
		UserName:       aws.String(user),
		PolicyName:     aws.String("organizations"),
		PolicyDocument: aws.String(doc),
	})
	requireNoErr(t, err, "put a policy for "+user)
}

// organizationRoleSession assumes OrganizationAccountAccessRole in the
// member account as the root user.
func (s *identityStack) organizationRoleSession(t *testing.T, member string) aws.Credentials {
	t.Helper()
	out, err := stsClient(s.identityURL, s.rootCreds).AssumeRole(t.Context(), &sts.AssumeRoleInput{
		RoleArn:         aws.String("arn:aws:iam::" + member + ":role/" + organizationRole),
		RoleSessionName: aws.String("e2e"),
	})
	requireNoErr(t, err, "assume role in "+member)
	return aws.Credentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
	}
}

func allowDoc(action, resource string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + action +
		`","Resource":"` + resource + `"}]}`
}

func conditionDoc(action, condition string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"` + action +
		`","Resource":"*","Condition":` + condition + `}]}`
}

// requireAccessDenied fails unless err is Organizations' modeled
// AccessDeniedException, with status 400 and the message.
func requireAccessDenied(t *testing.T, err error, msg string) {
	t.Helper()
	var e *types.AccessDeniedException
	if !errors.As(err, &e) {
		t.Fatalf("want AccessDeniedException, got %v", err)
	}
	requireStatus(t, err, http.StatusBadRequest)
	requireEqual(t, e.ErrorMessage(), msg, "AccessDeniedException message")
}
