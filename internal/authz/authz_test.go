package authz

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"tule.dev/policy"
	"tule.dev/sigv4"

	"tule.dev/accounts/internal/contracts"
	"tule.dev/accounts/internal/orgapi"
)

const (
	management = "000000000000"
	member     = "111111111111"
	userARN    = "arn:aws:iam::000000000000:user/team/dev"
	sessionARN = "arn:aws:sts::000000000000:assumed-role/ops/e2e"
	roleARN    = "arn:aws:iam::000000000000:role/platform/ops"
	accountARN = "arn:aws:organizations::000000000000:account/o-abcdefghij/111111111111"
	ouARN      = "arn:aws:organizations::000000000000:ou/o-abcdefghij/ou-abcd-12345678"
)

func principal(p sigv4.Principal) Principal {
	return Principal{Principal: p}
}

func user(docs ...string) Principal {
	p := principal(sigv4.Principal{
		AccountID:    management,
		ARN:          userARN,
		PrincipalARN: userARN,
		UserID:       "AIDAEXAMPLEUSERID0001",
		Type:         sigv4.PrincipalTypeUser,
		AccessKeyID:  "AKIAEXAMPLE",
	})
	for _, d := range docs {
		p.Policies = append(p.Policies, json.RawMessage(d))
	}
	return p
}

func allow(action, resource string) string {
	return statement("Allow", action, resource, "")
}

func statement(effect, action, resource, condition string) string {
	c := ""
	if condition != "" {
		c = `,"Condition":` + condition
	}
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":%q,"Action":%q,`+
		`"Resource":%q%s}]}`, effect, action, resource, c)
}

func request() *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://accounts.local/", nil)
	r.RemoteAddr = "192.0.2.10:4242"
	return r
}

func requireAccessDenied(t *testing.T, err error, msg string) {
	t.Helper()
	var e *orgapi.Error
	if !errors.As(err, &e) {
		t.Fatalf("got %v, want an *orgapi.Error", err)
	}
	if e.Type != "AccessDeniedException" || e.Status != http.StatusBadRequest ||
		e.Message != msg {
		t.Fatalf("got %s %d %q,\nwant AccessDeniedException 400 %q", e.Type, e.Status,
			e.Message, msg)
	}
}

func TestAPolicyAllowsOnlyWhatItNames(t *testing.T) {
	a := New(management)
	p := user(allow("organizations:DescribeAccount", accountARN))
	res := []Resource{{ARN: accountARN}}

	if err := a.Authorize(request(), p, "organizations:DescribeAccount", res, nil); err != nil {
		t.Fatalf("allowed action: %v", err)
	}
	err := a.Authorize(request(), p, "organizations:CloseAccount", res, nil)
	requireAccessDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"organizations:CloseAccount on resource: "+accountARN+
		" because no identity-based policy allows the organizations:CloseAccount action")
}

func TestAUserWithNoPolicyIsDenied(t *testing.T) {
	err := New(management).Authorize(request(), user(), "organizations:ListAccounts",
		[]Resource{{ARN: "*"}}, nil)
	requireAccessDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"organizations:ListAccounts on resource: * because no identity-based policy "+
		"allows the organizations:ListAccounts action")
}

func TestAnExplicitDenyWins(t *testing.T) {
	p := user(allow("organizations:*", "*"),
		statement("Deny", "organizations:DescribeAccount", accountARN, ""))
	err := New(management).Authorize(request(), p, "organizations:DescribeAccount",
		[]Resource{{ARN: accountARN}}, nil)
	requireAccessDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"organizations:DescribeAccount on resource: "+accountARN+
		" with an explicit deny in an identity-based policy")
}

func TestEveryResourceIsEvaluated(t *testing.T) {
	// MoveAccount acts on the account and both parents; the second is denied.
	p := user(allow("organizations:MoveAccount", accountARN),
		allow("organizations:MoveAccount", "arn:aws:organizations::000000000000:root/*"))
	root := "arn:aws:organizations::000000000000:root/o-abcdefghij/r-abcd"
	err := New(management).Authorize(request(), p, "organizations:MoveAccount",
		[]Resource{{ARN: accountARN}, {ARN: ouARN}, {ARN: root}}, nil)
	requireAccessDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"organizations:MoveAccount on resource: "+ouARN+
		" because no identity-based policy allows the organizations:MoveAccount action")

	if err = New(management).Authorize(request(), p, "organizations:MoveAccount",
		[]Resource{{ARN: accountARN}, {ARN: root}}, nil); err != nil {
		t.Fatalf("every resource allowed: %v", err)
	}
}

func TestResourceTagsAndOperationKeysReachConditions(t *testing.T) {
	a := New(management)
	p := user(statement("Allow", "organizations:TagResource", "*",
		`{"StringEquals":{"aws:ResourceTag/team":"ops","aws:RequestTag/env":"dev"}}`))
	tagged := []Resource{{ARN: accountARN, Tags: []contracts.Tag{{Key: "team", Value: "ops"}}}}
	keys := map[string][]string{"aws:RequestTag/env": {"dev"}, "aws:TagKeys": {"env"}}

	if err := a.Authorize(request(), p, "organizations:TagResource", tagged, keys); err != nil {
		t.Fatalf("matching tags: %v", err)
	}
	untagged := []Resource{{ARN: accountARN}}
	if err := a.Authorize(request(), p, "organizations:TagResource", untagged,
		keys); err == nil {
		t.Fatal("a resource without the tag was allowed")
	}
	if err := a.Authorize(request(), p, "organizations:TagResource", tagged,
		map[string][]string{"aws:RequestTag/env": {"prod"}}); err == nil {
		t.Fatal("a request tag that does not match was allowed")
	}
}

func TestAnEscapedResourceTagKeyInADenyApplies(t *testing.T) {
	// "aws:ResourceTag/team" spelled with JSON escapes: the resource's tags
	// are supplied whatever the documents say, so the Deny still applies.
	p := user(allow("organizations:DescribeAccount", "*"),
		`{"Version":"2012-10-17","Statement":[{"Effect":"Deny",`+
			`"Action":"organizations:DescribeAccount","Resource":"*","Condition":`+
			`{"StringEquals":{"aws:\u0052esourceTag\/team":"ops"}}}]}`)
	err := New(management).Authorize(request(), p, "organizations:DescribeAccount",
		[]Resource{{ARN: accountARN, Tags: []contracts.Tag{{Key: "team", Value: "ops"}}}}, nil)
	requireAccessDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"organizations:DescribeAccount on resource: "+accountARN+
		" with an explicit deny in an identity-based policy")
}

func TestNoResourceIsAFaultNotAnAllow(t *testing.T) {
	p := user(allow("organizations:*", "*"))
	for _, res := range [][]Resource{nil, {}} {
		err := New(management).Authorize(request(), p, "organizations:ListAccounts", res, nil)
		var e *orgapi.Error
		if err == nil || errors.As(err, &e) {
			t.Fatalf("no resource: got %v, want a fault", err)
		}
	}
}

func TestRequestedRegionIsTheServicesRegion(t *testing.T) {
	// The request is signed for no region at all here; a Deny on the
	// service's region applies whatever the signature says.
	p := user(allow("organizations:ListAccounts", "*"),
		statement("Deny", "organizations:ListAccounts", "*",
			`{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}`))
	err := New(management).Authorize(request(), p, "organizations:ListAccounts",
		[]Resource{{ARN: "*"}}, nil)
	requireAccessDenied(t, err, "User: "+userARN+" is not authorized to perform: "+
		"organizations:ListAccounts on resource: * with an explicit deny in an "+
		"identity-based policy")
}

func TestSourceIPIsHonored(t *testing.T) {
	p := user(statement("Allow", "organizations:ListAccounts", "*",
		`{"IpAddress":{"aws:SourceIp":"192.0.2.0/24"}}`))
	a := New(management)
	if err := a.Authorize(request(), p, "organizations:ListAccounts",
		[]Resource{{ARN: "*"}}, nil); err != nil {
		t.Fatalf("from inside the range: %v", err)
	}
	r := request()
	r.RemoteAddr = "198.51.100.1:4242"
	if err := a.Authorize(r, p, "organizations:ListAccounts",
		[]Resource{{ARN: "*"}}, nil); err == nil {
		t.Fatal("a request from outside the range was allowed")
	}
}

func TestTheRootPrincipalIsNotEvaluated(t *testing.T) {
	root := principal(sigv4.Principal{
		AccountID: management,
		ARN:       "arn:aws:iam::000000000000:root",
		Root:      true,
	})
	a := New(management)
	if err := a.Authorize(request(), root, "organizations:DeleteOrganization",
		[]Resource{{ARN: "*"}}, nil); err != nil {
		t.Fatalf("root: %v", err)
	}
	if !a.IsRoot(root) || a.RequireManagementAccount(root) != nil {
		t.Fatal("the management account's root is not root")
	}

	// Root of another account is not this service's root.
	root.AccountID = "111111111111"
	root.ARN = "arn:aws:iam::111111111111:root"
	if a.IsRoot(root) {
		t.Fatal("the root of another account is root here")
	}
	requireAccessDenied(t, a.RequireManagementAccount(root),
		"You don't have permissions to access this resource.")
	if err := a.Authorize(request(), root, "organizations:DeleteOrganization",
		[]Resource{{ARN: "*"}}, nil); err == nil {
		t.Fatal("the root of another account skipped evaluation")
	}
}

func TestAMemberAccountPrincipalIsRefused(t *testing.T) {
	a := New(management)
	member := principal(sigv4.Principal{
		AccountID: "111111111111",
		ARN:       "arn:aws:sts::111111111111:assumed-role/OrganizationAccountAccessRole/x",
	})
	requireAccessDenied(t, a.RequireManagementAccount(member),
		"You don't have permissions to access this resource.")
	if err := a.RequireManagementAccount(user()); err != nil {
		t.Fatalf("management account user: %v", err)
	}
}

func TestADocumentThatDoesNotParseIsAFault(t *testing.T) {
	err := New(management).Authorize(request(), user(`{"Statement":"nope"}`),
		"organizations:ListAccounts", []Resource{{ARN: "*"}}, nil)
	var e *orgapi.Error
	if err == nil || errors.As(err, &e) {
		t.Fatalf("got %v, want a plain error the dispatcher answers as ServiceException", err)
	}
}

func TestTheCacheIsBounded(t *testing.T) {
	a := New(management)
	for i := range maxCachedPolicies + 10 {
		doc := allow("organizations:ListAccounts", fmt.Sprintf("arn:aws:organizations::*:x%d", i))
		if err := a.Authorize(request(), user(doc), "organizations:ListAccounts",
			[]Resource{{ARN: "*"}}, nil); err == nil {
			t.Fatal("a policy for another resource allowed the request")
		}
	}
	if n := a.cachedPolicies(); n != maxCachedPolicies {
		t.Fatalf("cached %d documents, want %d", n, maxCachedPolicies)
	}
	// The same document is parsed once.
	b := New(management)
	doc := allow("organizations:ListAccounts", "*")
	for range 3 {
		if err := b.Authorize(request(), user(doc, doc), "organizations:ListAccounts",
			[]Resource{{ARN: "*"}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := b.cachedPolicies(); n != 1 {
		t.Fatalf("cached %d documents, want 1", n)
	}
}

func TestGlobalKeys(t *testing.T) {
	now := time.Date(2026, 11, 13, 10, 0, 0, 0, time.FixedZone("EET", 2*3600))
	got := GlobalKeys(request(), taggedSession(map[string]string{"team": "ops", "Env": "dev"}), now)
	want := map[string][]string{
		"aws:CurrentTime":       {"2026-11-13T08:00:00Z"},
		"aws:EpochTime":         {"1794556800"},
		"aws:SecureTransport":   {"false"},
		"aws:SourceIp":          {"192.0.2.10"},
		"aws:RequestedRegion":   {"us-east-1"},
		"aws:PrincipalTag/team": {"ops"},
		"aws:PrincipalTag/Env":  {"dev"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestGlobalKeysOfTheConnection(t *testing.T) {
	now := time.Now()
	t.Run("TLS", func(t *testing.T) {
		r := request()
		r.TLS = &tls.ConnectionState{}
		got := GlobalKeys(r, user(), now)["aws:SecureTransport"]
		if !reflect.DeepEqual(got, []string{"true"}) {
			t.Fatalf("aws:SecureTransport = %v", got)
		}
	})
	t.Run("IPv6 source", func(t *testing.T) {
		r := request()
		r.RemoteAddr = "[2001:db8::1]:4242"
		got := GlobalKeys(r, user(), now)["aws:SourceIp"]
		if !reflect.DeepEqual(got, []string{"2001:db8::1"}) {
			t.Fatalf("aws:SourceIp = %v", got)
		}
	})
}

// session is a session of the role ops, at path /platform/, in the
// management account, with the policy docs.
func session(docs ...string) Principal {
	p := principal(sigv4.Principal{
		AccountID:    management,
		ARN:          sessionARN,
		PrincipalARN: roleARN,
		UserID:       "AROAEXAMPLEROLEID0001:e2e",
		Type:         sigv4.PrincipalTypeAssumedRole,
		AccessKeyID:  "ASIAEXAMPLE",
	})
	for _, d := range docs {
		p.Policies = append(p.Policies, json.RawMessage(d))
	}
	return p
}

func taggedSession(tags map[string]string) Principal {
	p := session()
	p.Tags = tags
	return p
}

func TestCallerOf(t *testing.T) {
	got := CallerOf(session())
	want := policy.Caller{
		AccountID:    management,
		ARN:          sessionARN,
		PrincipalARN: roleARN,
		UserID:       "AROAEXAMPLEROLEID0001:e2e",
		Type:         policy.PrincipalTypeAssumedRole,
	}
	if got != want {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestPrincipalKeysReachConditions(t *testing.T) {
	a := New(management)
	for name, tc := range map[string]struct {
		condition string
		p         Principal
	}{
		"aws:PrincipalArn with the role's path": {
			p:         session(),
			condition: `{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/platform/*"}}`,
		},
		"aws:PrincipalArn of a user": {
			p:         user(),
			condition: `{"ArnEquals":{"aws:PrincipalArn":"` + userARN + `"}}`,
		},
		"aws:PrincipalAccount": {
			p:         session(),
			condition: `{"StringEquals":{"aws:PrincipalAccount":"` + management + `"}}`,
		},
		"aws:PrincipalType": {
			p:         session(),
			condition: `{"StringEquals":{"aws:PrincipalType":"AssumedRole"}}`,
		},
		"aws:userid": {
			p:         session(),
			condition: `{"StringLike":{"aws:userid":"AROAEXAMPLEROLEID0001:*"}}`,
		},
		"aws:username": {
			p:         user(),
			condition: `{"StringEquals":{"aws:username":"dev"}}`,
		},
		"aws:PrincipalTag": {
			p:         taggedSession(map[string]string{"team": "ops"}),
			condition: `{"StringEquals":{"aws:PrincipalTag/team":"ops"}}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			deny := statement("Deny", "organizations:ListAccounts", "*", tc.condition)
			tc.p.Policies = append(tc.p.Policies,
				json.RawMessage(allow("organizations:ListAccounts", "*")),
				json.RawMessage(deny))
			err := a.Authorize(request(), tc.p, "organizations:ListAccounts",
				[]Resource{{ARN: "*"}}, nil)
			requireAccessDenied(t, err, "User: "+tc.p.ARN+" is not authorized to perform: "+
				"organizations:ListAccounts on resource: * with an explicit deny in an "+
				"identity-based policy")
		})
	}
}

func TestTheRequestCannotSetPrincipalKeys(t *testing.T) {
	// An operation key named like a principal key does not replace the
	// principal's: the Deny on the role path still applies.
	p := session(allow("organizations:ListAccounts", "*"),
		statement("Deny", "organizations:ListAccounts", "*",
			`{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::*:role/platform/*"}}`))
	err := New(management).Authorize(request(), p, "organizations:ListAccounts",
		[]Resource{{ARN: "*"}},
		map[string][]string{"aws:PrincipalArn": {"arn:aws:iam::000000000000:role/other"}})
	requireAccessDenied(t, err, "User: "+sessionARN+" is not authorized to perform: "+
		"organizations:ListAccounts on resource: * with an explicit deny in an "+
		"identity-based policy")
}

func TestASessionWhoseRoleWasDeletedIsRefused(t *testing.T) {
	p := session(allow("organizations:*", "*"))
	p.PrincipalARN = ""
	err := New(management).Authorize(request(), p, "organizations:ListAccounts",
		[]Resource{{ARN: "*"}}, nil)
	requireAccessDenied(t, err, "User: "+sessionARN+" is not authorized to perform: "+
		"organizations:ListAccounts on resource: * because no identity-based policy "+
		"allows the organizations:ListAccounts action")
}

func TestACallerWhoseFieldsDisagreeIsRefused(t *testing.T) {
	for name, edit := range map[string]func(*Principal){
		"no type":               func(p *Principal) { p.Type = "" },
		"no unique ID":          func(p *Principal) { p.UserID = "" },
		"another account's ARN": func(p *Principal) { p.AccountID = member },
		"another role":          func(p *Principal) { p.PrincipalARN = "arn:aws:iam::000000000000:role/x" },
	} {
		t.Run(name, func(t *testing.T) {
			p := session(allow("organizations:*", "*"))
			edit(&p)
			err := New(management).Authorize(request(), p, "organizations:ListAccounts",
				[]Resource{{ARN: "*"}}, nil)
			requireAccessDenied(t, err, "User: "+sessionARN+" is not authorized to perform: "+
				"organizations:ListAccounts on resource: * because no identity-based policy "+
				"allows the organizations:ListAccounts action")
		})
	}
}

// memberSession is a session of OrganizationAccountAccessRole in a member
// account, with AdministratorAccess.
func memberSession() Principal {
	const arn = "arn:aws:sts::111111111111:assumed-role/OrganizationAccountAccessRole/x"
	return principal(sigv4.Principal{
		AccountID:    member,
		ARN:          arn,
		PrincipalARN: "arn:aws:iam::111111111111:role/OrganizationAccountAccessRole",
		UserID:       "AROAEXAMPLEROLEID0002:x",
		Type:         sigv4.PrincipalTypeAssumedRole,
		Policies:     []json.RawMessage{json.RawMessage(allow("*", "*"))},
	})
}

func TestAnotherAccountNeedsAResourcePolicy(t *testing.T) {
	p := memberSession()
	err := New(management).Authorize(request(), p, "organizations:DescribeAccount",
		[]Resource{{ARN: accountARN}}, nil)
	requireAccessDenied(t, err, "User: "+p.ARN+" is not authorized to perform: "+
		"organizations:DescribeAccount on resource: "+accountARN+
		" because no resource-based policy allows the organizations:DescribeAccount action")
}

func TestInOwnAccountTheIdentityPoliciesDecide(t *testing.T) {
	a := New(management)
	p := memberSession()
	if err := a.AuthorizeInOwnAccount(request(), p, "organizations:DescribeOrganization",
		[]Resource{{ARN: "*"}}, nil); err != nil {
		t.Fatalf("member session with an Allow: %v", err)
	}
	p.Policies = nil
	err := a.AuthorizeInOwnAccount(request(), p, "organizations:DescribeOrganization",
		[]Resource{{ARN: "*"}}, nil)
	requireAccessDenied(t, err, "User: "+p.ARN+" is not authorized to perform: "+
		"organizations:DescribeOrganization on resource: * because no identity-based "+
		"policy allows the organizations:DescribeOrganization action")
}
