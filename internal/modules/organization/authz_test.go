package organization

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"tule.dev/sigv4"

	"tule.dev/accounts/internal/authz"
	"tule.dev/accounts/internal/contracts"
	"tule.dev/accounts/internal/orgapi"
)

// referencePath is AWS's service reference for Organizations, as fetched on
// 2026-11-13 from
// https://servicereference.us-east-1.amazonaws.com/v1/organizations/organizations.json.
const referencePath = "testdata/service-reference.json"

type reference struct {
	Operations []struct {
		Name              string `json:"Name"`
		AuthorizedActions []struct {
			Name    string `json:"Name"`
			Service string `json:"Service"`
		} `json:"AuthorizedActions"`
	} `json:"Operations"`
	Actions []struct {
		Name      string `json:"Name"`
		Resources []struct {
			Name string `json:"Name"`
		} `json:"Resources"`
		ActionConditionKeys []string `json:"ActionConditionKeys"`
	} `json:"Actions"`
}

func readReference(t *testing.T) reference {
	t.Helper()
	raw, err := os.ReadFile(referencePath)
	if err != nil {
		t.Fatalf("read the reference: %v", err)
	}
	var ref reference
	if err = json.Unmarshal(raw, &ref); err != nil {
		t.Fatalf("parse the reference: %v", err)
	}
	return ref
}

// referenceActions maps each action of the reference to the resource types
// it lists.
func referenceActions(t *testing.T) map[string][]string {
	t.Helper()
	ref := readReference(t)
	out := map[string][]string{}
	for _, a := range ref.Actions {
		types := []string{}
		for _, r := range a.Resources {
			types = append(types, r.Name)
		}
		out["organizations:"+a.Name] = types
	}
	return out
}

// fakeStore serves the two reads authorization makes.
type fakeStore struct {
	contracts.OrganizationProvider
	org      *contracts.Organization
	tags     map[string][]contracts.Tag
	accounts map[string]*contracts.Account
	lookups  int
}

func (s *fakeStore) DescribeOrganization(context.Context) (*contracts.Organization, error) {
	if s.org == nil {
		return nil, contracts.ErrNotInUse
	}
	return s.org, nil
}

func (s *fakeStore) DescribeAccount(_ context.Context, id string) (*contracts.Account, error) {
	s.lookups++
	a, ok := s.accounts[id]
	if !ok {
		return nil, contracts.ErrAccountNotFound
	}
	return a, nil
}

func (s *fakeStore) ResourceTags(_ context.Context, id string) ([]contracts.Tag, error) {
	return s.tags[id], nil
}

func newTestModule() *Module {
	return NewModule(nil, &fakeStore{
		org: &contracts.Organization{ID: "o-abcdefghij", ManagementAccountID: "000000000000"},
		tags: map[string][]contracts.Tag{
			"111111111111": {{Key: "team", Value: "ops"}},
		},
	}, authz.New("000000000000"))
}

const (
	accountID = "111111111111"
	rootID    = "r-abcd"
	ouID      = "ou-abcd-12345678"
	arnPrefix = "arn:aws:organizations::000000000000:"
)

// sampleBodies is a valid request body for every routed operation, naming
// the resources the operation acts on.
var sampleBodies = map[string]string{
	"CreateOrganization":            `{}`,
	"DescribeOrganization":          `{}`,
	"DeleteOrganization":            `{}`,
	"CreateAccount":                 `{"AccountName":"a","Email":"a@example.com"}`,
	"DescribeCreateAccountStatus":   `{"CreateAccountRequestId":"car-abcdefgh"}`,
	"ListCreateAccountStatus":       `{}`,
	"DescribeAccount":               `{"AccountId":"111111111111"}`,
	"ListAccounts":                  `{}`,
	"ListAccountsForParent":         `{"ParentId":"ou-abcd-12345678"}`,
	"CloseAccount":                  `{"AccountId":"111111111111"}`,
	"RemoveAccountFromOrganization": `{"AccountId":"111111111111"}`,
	"MoveAccount": `{"AccountId":"111111111111","SourceParentId":"r-abcd",` +
		`"DestinationParentId":"ou-abcd-12345678"}`,
	"ListRoots":                        `{}`,
	"ListParents":                      `{"ChildId":"ou-abcd-12345678"}`,
	"ListChildren":                     `{"ParentId":"r-abcd","ChildType":"ACCOUNT"}`,
	"CreateOrganizationalUnit":         `{"ParentId":"r-abcd","Name":"x"}`,
	"DescribeOrganizationalUnit":       `{"OrganizationalUnitId":"ou-abcd-12345678"}`,
	"UpdateOrganizationalUnit":         `{"OrganizationalUnitId":"ou-abcd-12345678","Name":"y"}`,
	"DeleteOrganizationalUnit":         `{"OrganizationalUnitId":"ou-abcd-12345678"}`,
	"ListOrganizationalUnitsForParent": `{"ParentId":"r-abcd"}`,
	"TagResource":                      `{"ResourceId":"111111111111","Tags":[{"Key":"k","Value":"v"}]}`,
	"UntagResource":                    `{"ResourceId":"r-abcd","TagKeys":["k"]}`,
	"ListTagsForResource":              `{"ResourceId":"ou-abcd-12345678"}`,
}

func TestEveryRoutedOperationHasAnEntry(t *testing.T) {
	m := newTestModule()
	routed := make([]string, 0, len(m.handlers))
	mapped := make([]string, 0, len(operations))
	for op := range m.handlers {
		routed = append(routed, op)
	}
	for op := range operations {
		mapped = append(mapped, op)
	}
	sort.Strings(routed)
	sort.Strings(mapped)
	if !reflect.DeepEqual(routed, mapped) {
		t.Fatalf("routed operations %v\nhave authorization entries %v", routed, mapped)
	}
	for _, op := range routed {
		if _, ok := sampleBodies[op]; !ok {
			t.Errorf("%s has no sample body", op)
		}
	}
}

func TestEveryEntryIsTheReferences(t *testing.T) {
	ref := referenceActions(t)
	m := newTestModule()
	for op, entry := range operations {
		t.Run(op, func(t *testing.T) {
			types, ok := ref[entry.action]
			if !ok {
				t.Fatalf("%s is not an action of the reference", entry.action)
			}
			if entry.action != "organizations:"+op {
				t.Errorf("%s is evaluated as %s", op, entry.action)
			}
			res, _, err := entry.targets(t.Context(), m, []byte(sampleBodies[op]))
			if err != nil {
				t.Fatalf("targets: %v", err)
			}
			if len(res) == 0 {
				t.Fatal("no resource is evaluated")
			}
			for _, r := range res {
				got := resourceType(r.ARN)
				if len(types) == 0 {
					if r.ARN != "*" {
						t.Errorf("evaluated on %s; the reference lists no resource type", r.ARN)
					}
					continue
				}
				if !slices.Contains(types, got) {
					t.Errorf("evaluated on %s (%s); the reference lists %v", r.ARN, got, types)
				}
			}
		})
	}
}

// resourceType is the reference's name for the type of an Organizations
// ARN this service builds.
func resourceType(arn string) string {
	resource, ok := strings.CutPrefix(arn, arnPrefix)
	if !ok {
		return "not an ARN of the organization: " + arn
	}
	kind, _, _ := strings.Cut(resource, "/")
	switch kind {
	case "account", "root":
		return kind
	case "ou":
		return "organizationalunit"
	}
	return "unknown " + kind
}

// TestEveryAuthorizedActionIsChecked holds each entry to the actions the
// reference's Operations list authorizes the operation with: its own, and
// organizations:TagResource for a create that takes tags. An action the
// reference lists that the entry does not check fails the test.
func TestEveryAuthorizedActionIsChecked(t *testing.T) {
	listed := map[string][]string{}
	for _, o := range readReference(t).Operations {
		for _, a := range o.AuthorizedActions {
			listed[o.Name] = append(listed[o.Name], a.Service+":"+a.Name)
		}
	}
	for op, entry := range operations {
		checked := []string{entry.action}
		if entry.tagsOnCreate {
			checked = append(checked, tagAction)
		}
		want := listed[op]
		sort.Strings(checked)
		sort.Strings(want)
		if !reflect.DeepEqual(checked, want) {
			t.Errorf("%s checks %v; the reference authorizes it with %v", op, checked, want)
		}
	}
}

func TestTargetsAreTheRequestsResources(t *testing.T) {
	m := newTestModule()
	for op, want := range map[string][]string{
		"DescribeAccount": {arnPrefix + "account/o-abcdefghij/" + accountID},
		"MoveAccount": {
			arnPrefix + "account/o-abcdefghij/" + accountID,
			arnPrefix + "root/o-abcdefghij/" + rootID,
			arnPrefix + "ou/o-abcdefghij/" + ouID,
		},
		"ListParents":         {arnPrefix + "ou/o-abcdefghij/" + ouID},
		"UntagResource":       {arnPrefix + "root/o-abcdefghij/" + rootID},
		"ListAccounts":        {"*"},
		"CreateAccount":       {"*"},
		"ListTagsForResource": {arnPrefix + "ou/o-abcdefghij/" + ouID},
	} {
		res, _, err := operations[op].targets(t.Context(), m, []byte(sampleBodies[op]))
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		var got []string
		for _, r := range res {
			got = append(got, r.ARN)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", op, got, want)
		}
	}

	res, _, err := operations["DescribeAccount"].targets(t.Context(), m,
		[]byte(sampleBodies["DescribeAccount"]))
	if err != nil || !reflect.DeepEqual(res[0].Tags, []contracts.Tag{{Key: "team", Value: "ops"}}) {
		t.Fatalf("the account's tags = %v, %v", res, err)
	}
}

func TestTagKeysComeFromTheRequest(t *testing.T) {
	m := newTestModule()
	_, keys, err := operations["CreateAccount"].targets(t.Context(), m, []byte(
		`{"AccountName":"a","Email":"a@example.com",`+
			`"Tags":[{"Key":"env","Value":"dev"},{"Key":"team","Value":""}]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := opKeys{
		"aws:RequestTag/env":  {"dev"},
		"aws:RequestTag/team": {""},
		"aws:TagKeys":         {"env", "team"},
	}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("got %v, want %v", keys, want)
	}

	_, _, err = operations["CreateOrganizationalUnit"].targets(t.Context(), m, []byte(
		`{"ParentId":"r-abcd","Name":"x","Tags":[{"Key":"Env","Value":"a"},`+
			`{"Key":"env","Value":"b"}]}`))
	var e *orgapi.Error
	if !errors.As(err, &e) || e.Reason != orgapi.ReasonDuplicateTagKey {
		t.Fatalf("keys differing only by case: %v, want DUPLICATE_TAG_KEY", err)
	}

	_, keys, err = operations["UntagResource"].targets(t.Context(), m,
		[]byte(`{"ResourceId":"r-abcd","TagKeys":["a","b","a"]}`))
	if err != nil || !reflect.DeepEqual(keys, opKeys{"aws:TagKeys": {"a", "b"}}) {
		t.Fatalf("untag keys = %v, %v", keys, err)
	}
}

func TestTheRequestContextIsCapped(t *testing.T) {
	m := newTestModule()
	tags := make([]string, 0, contracts.MaxTagsPerResource+1)
	keys := make([]string, 0, contracts.MaxTagsPerResource+1)
	for i := range contracts.MaxTagsPerResource + 1 {
		tags = append(tags, fmt.Sprintf(`{"Key":"k%d","Value":"v"}`, i))
		keys = append(keys, fmt.Sprintf(`"k%d"`, i))
	}
	for op, body := range map[string]string{
		"TagResource": `{"ResourceId":"r-abcd","Tags":[` + strings.Join(tags, ",") + `]}`,
		"CreateOrganizationalUnit": `{"ParentId":"r-abcd","Name":"x","Tags":[` +
			strings.Join(tags, ",") + `]}`,
		"UntagResource": `{"ResourceId":"r-abcd","TagKeys":[` + strings.Join(keys, ",") + `]}`,
	} {
		_, _, err := operations[op].targets(t.Context(), m, []byte(body))
		if !errors.Is(err, contracts.ErrTagLimitExceeded) {
			t.Errorf("%s with %d tags: %v, want the tag limit", op, len(tags), err)
		}
	}
}

func TestTargetsThatCannotBeEvaluated(t *testing.T) {
	m := newTestModule()
	requireType := func(t *testing.T, err error, want string) {
		t.Helper()
		var e *orgapi.Error
		if errors.As(err, &e) && e.Type == want {
			return
		}
		if errors.Is(err, contracts.ErrTargetNotFound) && want == orgapi.TypeTargetNotFound ||
			errors.Is(err, contracts.ErrNotInUse) && want == orgapi.TypeNotInUse {
			return
		}
		t.Fatalf("got %v, want %s", err, want)
	}

	t.Run("an invalid ID fails as its handler fails", func(t *testing.T) {
		_, _, err := operations["DescribeAccount"].targets(t.Context(), m,
			[]byte(`{"AccountId":"12"}`))
		requireType(t, err, orgapi.TypeInvalidInput)
	})
	t.Run("a body of the wrong shape fails as its handler fails", func(t *testing.T) {
		_, _, err := operations["DescribeAccount"].targets(t.Context(), m,
			[]byte(`{"AccountId":12}`))
		requireType(t, err, orgapi.TypeSerialization)
	})
	t.Run("a policy ID names no target", func(t *testing.T) {
		_, _, err := operations["TagResource"].targets(t.Context(), m,
			[]byte(`{"ResourceId":"p-abcdefgh","Tags":[]}`))
		requireType(t, err, orgapi.TypeTargetNotFound)
	})
	t.Run("without an organization nothing has an ARN", func(t *testing.T) {
		none := NewModule(nil, &fakeStore{}, authz.New("000000000000"))
		_, _, err := operations["DescribeAccount"].targets(t.Context(), none,
			[]byte(sampleBodies["DescribeAccount"]))
		requireType(t, err, orgapi.TypeNotInUse)
		// An operation on "*" needs none.
		if _, _, err = operations["ListAccounts"].targets(t.Context(), none,
			[]byte(`{}`)); err != nil {
			t.Fatalf("ListAccounts: %v", err)
		}
	})
}

func TestDescribeOrganizationNeedsAnActiveMember(t *testing.T) {
	store := &fakeStore{accounts: map[string]*contracts.Account{
		"111111111111": {ID: "111111111111", State: contracts.AccountStateActive},
		"222222222222": {ID: "222222222222", State: contracts.AccountStateClosed},
	}}
	m := NewModule(nil, store, authz.New("000000000000"))
	entry := operations["DescribeOrganization"]
	caller := func(account string) authz.Principal {
		return authz.Principal{Principal: sigv4.Principal{
			AccountID: account,
			ARN:       "arn:aws:sts::" + account + ":assumed-role/r/s",
		}}
	}

	if err := m.requireCallerAccount(t.Context(), caller("111111111111"), entry); err != nil {
		t.Fatalf("active member: %v", err)
	}
	err := m.requireCallerAccount(t.Context(), caller("333333333333"), entry)
	if !errors.Is(err, contracts.ErrNotInUse) {
		t.Fatalf("not a member: %v, want AWSOrganizationsNotInUseException", err)
	}
	err = m.requireCallerAccount(t.Context(), caller("222222222222"), entry)
	var e *orgapi.Error
	if !errors.As(err, &e) || e.Type != orgapi.TypeAccessDenied {
		t.Fatalf("closed member: %v, want AccessDeniedException", err)
	}

	store.lookups = 0
	if err = m.requireCallerAccount(t.Context(), caller("000000000000"), entry); err != nil ||
		store.lookups != 0 {
		t.Fatalf("management account: %v after %d lookups", err, store.lookups)
	}
	err = m.requireCallerAccount(t.Context(), caller("111111111111"),
		operations["ListAccounts"])
	if !errors.As(err, &e) || e.Type != orgapi.TypeAccessDenied {
		t.Fatalf("member calling ListAccounts: %v, want AccessDeniedException", err)
	}
}

func TestStoredTagKeysCollidingByCase(t *testing.T) {
	m := newTestModule()
	store := m.store.(*fakeStore)
	store.tags[rootID] = []contracts.Tag{{Key: "Env", Value: "prod"}}

	// Adding env beside Env is refused; changing Env's value is not.
	_, _, err := operations["TagResource"].targets(t.Context(), m,
		[]byte(`{"ResourceId":"r-abcd","Tags":[{"Key":"env","Value":"dev"}]}`))
	var e *orgapi.Error
	if !errors.As(err, &e) || e.Reason != orgapi.ReasonDuplicateTagKey {
		t.Fatalf("a key colliding with a stored one: %v, want DUPLICATE_TAG_KEY", err)
	}
	if _, _, err = operations["TagResource"].targets(t.Context(), m,
		[]byte(`{"ResourceId":"r-abcd","Tags":[{"Key":"Env","Value":"dev"}]}`)); err != nil {
		t.Fatalf("changing a stored key's value: %v", err)
	}

	// A resource that holds both is not evaluated.
	store.tags[rootID] = []contracts.Tag{{Key: "Env", Value: "a"}, {Key: "env", Value: "b"}}
	_, _, err = operations["ListChildren"].targets(t.Context(), m,
		[]byte(sampleBodies["ListChildren"]))
	if err == nil || errors.As(err, &e) {
		t.Fatalf("stored keys colliding by case: %v, want a fault", err)
	}
}
