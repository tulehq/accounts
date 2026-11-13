package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/accounts/internal/authz"
	"tule.dev/accounts/internal/contracts"
	"tule.dev/accounts/internal/orgapi"
)

// operation is how a request to an operation is authorized: the IAM action
// it is evaluated as, and targets, which returns the resources it acts on
// (each evaluated, as AWS evaluates an action on several resources) and the
// operation's own condition keys, from the request body. anyAccount marks
// the one operation a principal of a member account may call. tagsOnCreate
// marks a create that takes tags, which also needs tagAction when the
// request carries any.
type operation struct {
	targets      func(ctx context.Context, m *Module, body []byte) ([]authz.Resource, opKeys, error)
	action       string
	anyAccount   bool
	tagsOnCreate bool
}

// tagAction is the action a create that tags its new resource needs beside
// its own: "If the request includes tags, then the requester must have the
// organizations:TagResource permission" (the API reference for
// CreateAccount and CreateOrganizationalUnit), and the reference's
// Operations list names organizations:TagResource among their authorized
// actions. The resource does not exist yet, and its ID is not known before
// it is created, so the action is evaluated on "*", with the request's tag
// keys: a policy must grant it on "*", conditioned on aws:RequestTag or
// aws:TagKeys if it is to be narrowed.
const tagAction = "organizations:TagResource"

// opKeys are an operation's condition keys beyond the global ones.
type opKeys = map[string][]string

// operations is every routed operation's authorization: the action and
// resource types the Service Authorization Reference lists for it (the AWS
// Organizations page, and AWS's service reference JSON at
// https://servicereference.us-east-1.amazonaws.com/v1/organizations/organizations.json),
// with each resource's ARN in the reference's format, and the condition keys
// it lists for the action that this service has: aws:RequestTag/${TagKey}
// and aws:TagKeys from the request's tags, and aws:ResourceTag/${TagKey}
// from each resource's stored tags. An action the reference lists no
// resource type for is evaluated on "*", which is the only Resource that
// allows it. A test holds every handler to an entry here, and every action
// to the reference.
var operations = map[string]operation{
	"CreateOrganization": {action: "organizations:CreateOrganization", targets: anyResource},
	"DescribeOrganization": {
		action:     "organizations:DescribeOrganization",
		targets:    anyResource,
		anyAccount: true,
	},
	"DeleteOrganization": {action: "organizations:DeleteOrganization", targets: anyResource},

	"CreateAccount": {
		action:       "organizations:CreateAccount",
		tagsOnCreate: true,
		targets: on(func(_ context.Context, _ *Module, req orgapi.CreateAccountRequest) (
			[]authz.Resource, opKeys, error,
		) {
			keys, err := requestTagKeys(req.Tags)
			return []authz.Resource{{ARN: "*"}}, keys, err
		}),
	},
	"DescribeCreateAccountStatus": {
		action: "organizations:DescribeCreateAccountStatus", targets: anyResource,
	},
	"ListCreateAccountStatus": {
		action: "organizations:ListCreateAccountStatus", targets: anyResource,
	},
	"DescribeAccount": {action: "organizations:DescribeAccount", targets: accountIDTarget},
	"ListAccounts":    {action: "organizations:ListAccounts", targets: anyResource},
	"ListAccountsForParent": {
		action: "organizations:ListAccountsForParent", targets: parentPageTarget,
	},
	"CloseAccount": {action: "organizations:CloseAccount", targets: accountIDTarget},
	"RemoveAccountFromOrganization": {
		action: "organizations:RemoveAccountFromOrganization", targets: accountIDTarget,
	},
	"MoveAccount": {
		action: "organizations:MoveAccount",
		targets: on(func(ctx context.Context, m *Module, req orgapi.MoveAccountRequest) (
			[]authz.Resource, opKeys, error,
		) {
			return noKeys(m.resources(ctx,
				target{"AccountId", req.AccountID, orgapi.AccountID},
				target{"SourceParentId", req.SourceParentID, orgapi.ParentID},
				target{"DestinationParentId", req.DestinationParentID, orgapi.ParentID},
			))
		}),
	},

	"ListRoots": {action: "organizations:ListRoots", targets: anyResource},
	"ListParents": {
		action: "organizations:ListParents",
		targets: on(func(ctx context.Context, m *Module, req orgapi.ListParentsRequest) (
			[]authz.Resource, opKeys, error,
		) {
			return noKeys(m.resources(ctx, target{"ChildId", req.ChildID, orgapi.ChildID}))
		}),
	},
	"ListChildren": {
		action: "organizations:ListChildren",
		targets: on(func(ctx context.Context, m *Module, req orgapi.ListChildrenRequest) (
			[]authz.Resource, opKeys, error,
		) {
			return noKeys(m.resources(ctx, target{"ParentId", req.ParentID, orgapi.ParentID}))
		}),
	},
	"CreateOrganizationalUnit": {
		action:       "organizations:CreateOrganizationalUnit",
		tagsOnCreate: true,
		targets: on(
			func(ctx context.Context, m *Module, req orgapi.CreateOrganizationalUnitRequest) (
				[]authz.Resource, opKeys, error,
			) {
				keys, err := requestTagKeys(req.Tags)
				if err != nil {
					return nil, nil, err
				}
				res, err := m.resources(ctx, target{"ParentId", req.ParentID, orgapi.ParentID})
				return res, keys, err
			},
		),
	},
	"DescribeOrganizationalUnit": {
		action: "organizations:DescribeOrganizationalUnit", targets: ouIDTarget,
	},
	"UpdateOrganizationalUnit": {
		action: "organizations:UpdateOrganizationalUnit",
		targets: on(
			func(ctx context.Context, m *Module, req orgapi.UpdateOrganizationalUnitRequest) (
				[]authz.Resource, opKeys, error,
			) {
				return noKeys(m.resources(
					ctx,
					target{
						"OrganizationalUnitId",
						req.OrganizationalUnitID,
						orgapi.OrganizationalUnitID,
					},
				))
			},
		),
	},
	"DeleteOrganizationalUnit": {
		action: "organizations:DeleteOrganizationalUnit", targets: ouIDTarget,
	},
	"ListOrganizationalUnitsForParent": {
		action: "organizations:ListOrganizationalUnitsForParent", targets: parentPageTarget,
	},

	"TagResource": {
		action: "organizations:TagResource",
		targets: on(func(ctx context.Context, m *Module, req orgapi.TagResourceRequest) (
			[]authz.Resource, opKeys, error,
		) {
			res, err := m.resources(
				ctx,
				target{"ResourceId", req.ResourceID, orgapi.TaggableResourceID},
			)
			if err != nil {
				return nil, nil, err
			}
			keys, err := requestTagKeys(req.Tags)
			if err != nil {
				return nil, nil, err
			}
			return res, keys, noCaseCollision(req.Tags, res[0].Tags)
		}),
	},
	"UntagResource": {
		action: "organizations:UntagResource",
		targets: on(func(ctx context.Context, m *Module, req orgapi.UntagResourceRequest) (
			[]authz.Resource, opKeys, error,
		) {
			res, err := m.resources(
				ctx,
				target{"ResourceId", req.ResourceID, orgapi.TaggableResourceID},
			)
			if err != nil {
				return nil, nil, err
			}
			keys, err := untagKeys(req.TagKeys)
			return res, keys, err
		}),
	},
	"ListTagsForResource": {
		action: "organizations:ListTagsForResource",
		targets: on(func(ctx context.Context, m *Module, req orgapi.ListTagsForResourceRequest) (
			[]authz.Resource, opKeys, error,
		) {
			return noKeys(m.resources(ctx,
				target{"ResourceId", req.ResourceID, orgapi.TaggableResourceID},
			))
		}),
	},
}

// on adapts a targets function of the operation's own request body, decoded
// as its handler decodes it.
func on[T any](
	fn func(ctx context.Context, m *Module, req T) ([]authz.Resource, opKeys, error),
) func(context.Context, *Module, []byte) ([]authz.Resource, opKeys, error) {
	return func(ctx context.Context, m *Module, body []byte) ([]authz.Resource, opKeys, error) {
		req, err := decodeBytes[T](body)
		if err != nil {
			return nil, nil, err
		}
		return fn(ctx, m, req)
	}
}

func anyResource(context.Context, *Module, []byte) ([]authz.Resource, opKeys, error) {
	return []authz.Resource{{ARN: "*"}}, nil, nil
}

var accountIDTarget = on(func(ctx context.Context, m *Module, req orgapi.AccountIDRequest) (
	[]authz.Resource, opKeys, error,
) {
	return noKeys(m.resources(ctx, target{"AccountId", req.AccountID, orgapi.AccountID}))
})

var parentPageTarget = on(func(ctx context.Context, m *Module, req orgapi.ParentPageRequest) (
	[]authz.Resource, opKeys, error,
) {
	return noKeys(m.resources(ctx, target{"ParentId", req.ParentID, orgapi.ParentID}))
})

var ouIDTarget = on(func(ctx context.Context, m *Module, req orgapi.OrganizationalUnitIDRequest) (
	[]authz.Resource, opKeys, error,
) {
	return noKeys(m.resources(ctx,
		target{"OrganizationalUnitId", req.OrganizationalUnitID, orgapi.OrganizationalUnitID},
	))
})

// target is a request field naming a resource, and the rule its handler
// holds it to.
type target struct {
	field string
	id    string
	rule  orgapi.Rule
}

// errNoSuchTarget marks an ID that is valid but names a kind of resource
// this service holds none of.
var errNoSuchTarget = errors.New("organization: the ID names no resource this service holds")

// resources returns the resources the targets name, with their ARNs and
// tags. Each ID is first held to its handler's rule, with its error, since
// only a valid ID makes an ARN; a request with several invalid fields may
// so report a different one first than for the root principal. The ARNs
// need the organization, so without one the request fails as its handler
// would, with AWSOrganizationsNotInUseException. A policy, resource policy
// or responsibility transfer ID, which TagResource and its kin accept but
// this service holds none of, has no ARN to evaluate (a policy's carries its
// type), and fails as its handler would, with TargetNotFoundException.
func (m *Module) resources(ctx context.Context, targets ...target) ([]authz.Resource, error) {
	for _, t := range targets {
		if err := t.rule.Require(t.field, t.id); err != nil {
			return nil, err
		}
	}
	o, err := m.store.DescribeOrganization(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]authz.Resource, 0, len(targets))
	for _, t := range targets {
		arn, err := resourceARN(o, t.id)
		if errors.Is(err, errNoSuchTarget) {
			return nil, contracts.ErrTargetNotFound
		}
		if err != nil {
			return nil, err
		}
		tags, err := m.store.ResourceTags(ctx, t.id)
		if err != nil {
			return nil, err
		}
		if err = storedKeysDistinct(t.id, tags); err != nil {
			return nil, err
		}
		out = append(out, authz.Resource{ARN: arn, Tags: tags})
	}
	return out, nil
}

// noKeys is the result of an operation with no condition keys of its own.
func noKeys(res []authz.Resource, err error) ([]authz.Resource, opKeys, error) {
	return res, nil, err
}

// resourceARN is the ARN of the account, root or OU with the ID, in the
// reference's formats:
//
//	arn:${Partition}:organizations::${Account}:account/o-${OrganizationId}/${AccountId}
//	arn:${Partition}:organizations::${Account}:root/o-${OrganizationId}/r-${RootId}
//	arn:${Partition}:organizations::${Account}:ou/o-${OrganizationId}/ou-${OrganizationalUnitId}
//
// where Account is the management account. The ID has passed its rule.
func resourceARN(o *contracts.Organization, id string) (string, error) {
	prefix := "arn:aws:organizations::" + o.ManagementAccountID + ":"
	switch {
	case strings.HasPrefix(id, "r-"):
		return prefix + "root/" + o.ID + "/" + id, nil
	case strings.HasPrefix(id, "ou-"):
		return prefix + "ou/" + o.ID + "/" + id, nil
	case orgapi.AccountID.Check("", id) == nil:
		return prefix + "account/" + o.ID + "/" + id, nil
	case strings.HasPrefix(id, "p-"), strings.HasPrefix(id, "rp-"),
		strings.HasPrefix(id, "rt-"):
		return "", errNoSuchTarget
	}
	return "", fmt.Errorf("organization: no ARN for the resource ID %q", id)
}

// requestTagKeys supplies aws:RequestTag/${TagKey} and aws:TagKeys from a
// request's tags, which the reference lists for CreateAccount,
// CreateOrganizationalUnit and TagResource. The tags are held to the rules
// their handler holds them to first, which bound each key and value, and to
// at most contracts.MaxTagsPerResource of them, which bounds the context
// passed to the evaluator: more than that many distinct keys could never be
// stored, and the handlers refuse them with the same error.
func requestTagKeys(tags []orgapi.Tag) (opKeys, error) {
	if len(tags) == 0 {
		return nil, nil
	}
	if err := orgapi.Tags(tags); err != nil {
		return nil, err
	}
	if len(tags) > contracts.MaxTagsPerResource {
		return nil, contracts.ErrTagLimitExceeded
	}
	if err := distinctIgnoringCase(tags); err != nil {
		return nil, err
	}
	keys := opKeys{}
	names := make([]string, 0, len(tags))
	for _, t := range tags {
		keys["aws:RequestTag/"+t.Key] = []string{*t.Value}
		names = append(names, t.Key)
	}
	keys["aws:TagKeys"] = names
	return keys, nil
}

// distinctIgnoringCase refuses tags whose keys differ only by case. Tag
// keys are case-sensitive, and orgapi.Tags has refused exact repeats, but
// condition keys are matched case-insensitively, so tule.dev/policy would
// merge aws:RequestTag/Env and aws:RequestTag/env into one key with both
// values, and a condition on one would be matched against the other's
// value. AWS documents no answer for such a request; it is refused, for an
// evaluated principal only, as orgapi.Tags refuses an exact repeat.
func distinctIgnoringCase(tags []orgapi.Tag) error {
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		k := strings.ToLower(t.Key)
		if seen[k] {
			return errDuplicateTagKey()
		}
		seen[k] = true
	}
	return nil
}

// errDuplicateTagKey is the refusal of tag keys that differ only by case.
func errDuplicateTagKey() error {
	return orgapi.ErrInvalidInputReason(orgapi.ReasonDuplicateTagKey,
		"Tag keys must be unique among the tags attached to the same entity.")
}

// noCaseCollision refuses, as distinctIgnoringCase does, request tags that
// would add a key differing only by case from one the resource has: the
// resource would then hold both, and its aws:ResourceTag keys would merge.
// The same key in the same case only changes its value.
func noCaseCollision(tags []orgapi.Tag, stored []contracts.Tag) error {
	have := make(map[string]string, len(stored))
	for _, t := range stored {
		have[strings.ToLower(t.Key)] = t.Key
	}
	for _, t := range tags {
		if k, ok := have[strings.ToLower(t.Key)]; ok && k != t.Key {
			return errDuplicateTagKey()
		}
	}
	return nil
}

// storedKeysDistinct fails, as a fault, for a resource whose stored tag
// keys differ only by case, which the root user can store: its
// aws:ResourceTag keys would merge, so it is not evaluated at all.
func storedKeysDistinct(id string, tags []contracts.Tag) error {
	seen := make(map[string]bool, len(tags))
	for _, t := range tags {
		k := strings.ToLower(t.Key)
		if seen[k] {
			return fmt.Errorf("organization: %s has tag keys that differ only by case; "+
				"it is not evaluated", id)
		}
		seen[k] = true
	}
	return nil
}

// untagKeys supplies aws:TagKeys from UntagResource's TagKeys, held to the
// key rules, and to at most contracts.MaxTagsPerResource distinct keys, to
// bound the context. A resource never has more tags than that, but AWS
// documents no limit on the list, so for a principal that is evaluated this
// is a limit AWS does not have; the root principal is not held to it.
func untagKeys(names []string) (opKeys, error) {
	if len(names) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(names))
	distinct := make([]string, 0, len(names))
	for _, k := range names {
		if err := orgapi.TagKeyOf("TagKeys", k); err != nil {
			return nil, err
		}
		if !seen[k] {
			seen[k] = true
			distinct = append(distinct, k)
		}
		if len(distinct) > contracts.MaxTagsPerResource {
			return nil, contracts.ErrTagLimitExceeded
		}
	}
	return opKeys{"aws:TagKeys": distinct}, nil
}

// authorize authorizes the request to op by its entry in operations, before
// its handler runs: the root principal is allowed; a principal of a member
// account is refused anything but DescribeOrganization; any other principal
// must have an identity policy allowing each action the request needs on
// every resource it acts on, and none denying it. It leaves the body for the
// handler to read again.
func (m *Module) authorize(ctx gas.Context, op string) error {
	entry, ok := operations[op]
	if !ok {
		return fmt.Errorf("organization: %s has no authorization entry", op)
	}
	r := ctx.Request()
	p, err := authz.Caller(r)
	if err != nil {
		return err
	}
	if m.authz.IsRoot(p) {
		return nil
	}
	if err = m.requireCallerAccount(ctx, p, entry); err != nil {
		return err
	}

	body, err := rereadableBody(r)
	if err != nil {
		return err
	}
	resources, keys, err := entry.targets(ctx, m, body)
	if err != nil {
		return err
	}
	return m.authorizeActions(r, p, entry, resources, keys)
}

// requireCallerAccount refuses a caller whose account may not call the
// operation, before its policies are looked at. Only the management
// account's principals may call an operation other than anyAccount ones. A
// principal of another account may call DescribeOrganization only while its
// account is an ACTIVE member: an account that is not a member, such as one
// removed from the organization, is answered with
// AWSOrganizationsNotInUseException, as the DescribeOrganization API
// reference's Errors section says ("Your account isn't a member of an
// organization"), and a closed one with orgapi.ErrAccountNotActive.
func (m *Module) requireCallerAccount(
	ctx context.Context,
	p authz.Principal,
	entry operation,
) error {
	if !entry.anyAccount {
		return m.authz.RequireManagementAccount(p)
	}
	if m.authz.InManagementAccount(p) {
		return nil
	}
	a, err := m.store.DescribeAccount(ctx, p.AccountID)
	switch {
	case errors.Is(err, contracts.ErrAccountNotFound):
		return contracts.ErrNotInUse
	case err != nil:
		return err
	case a.State != contracts.AccountStateActive:
		return orgapi.ErrAccountNotActive()
	}
	return nil
}

// authorizeActions evaluates the entry's action on resources and, for a
// create carrying tags, tagAction on "*", with the same keys.
func (m *Module) authorizeActions(
	r *http.Request,
	p authz.Principal,
	entry operation,
	resources []authz.Resource,
	keys opKeys,
) error {
	if err := m.authz.Authorize(r, p, entry.action, resources, keys); err != nil {
		return err
	}
	if entry.tagsOnCreate && len(keys["aws:TagKeys"]) > 0 {
		return m.authz.Authorize(r, p, tagAction, []authz.Resource{{ARN: "*"}}, keys)
	}
	return nil
}

// rereadableBody reads r's body, which the verifier has buffered, and puts
// it back for the handler.
func rereadableBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("organization: read the request body: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// decodeBytes is decode for a body already read.
func decodeBytes[T any](body []byte) (T, error) {
	var out T
	err := json.NewDecoder(bytes.NewReader(body)).Decode(&out)
	if err != nil && !errors.Is(err, io.EOF) {
		return out, errSerialization()
	}
	return out, nil
}
