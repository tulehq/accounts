// Package authz evaluates a verified principal's IAM identity policies for
// a request, through tule.dev/policy, as Organizations does: the root
// principal is never evaluated, a principal of a member account may call
// only what a member account may, and any other principal needs a policy
// that allows the action on every resource the request acts on and none
// that denies it.
//
// Which action and resources an operation is evaluated as is the
// organization module's table; this package is the evaluation behind it.
package authz

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"tule.dev/policy"
	"tule.dev/sigv4"

	"tule.dev/accounts/internal/contracts"
	"tule.dev/accounts/internal/orgapi"
)

// maxCachedPolicies bounds the parsed policy documents kept. Every
// principal's documents are parsed on each request otherwise; a few
// thousand distinct documents is far beyond what a local organization
// uses, and an entry is a parsed document of at most IAM's size limits.
const maxCachedPolicies = 1024

// Authorizer evaluates requests for the organization whose management
// account is managementAccountID. It is safe for concurrent use.
type Authorizer struct {
	cache               map[[sha256.Size]byte]*policy.Policy
	managementAccountID string
	mu                  sync.Mutex
}

// New returns an Authorizer for the organization of the management account.
func New(managementAccountID string) *Authorizer {
	return &Authorizer{
		managementAccountID: managementAccountID,
		cache:               map[[sha256.Size]byte]*policy.Policy{},
	}
}

// Resource is one resource a request acts on: its ARN, and its tags for the
// aws:ResourceTag keys.
type Resource struct {
	ARN  string
	Tags []contracts.Tag
}

// Principal is a request's verified principal.
type Principal struct {
	sigv4.Principal
}

// Region is the region this service serves, which is aws:RequestedRegion.
// Organizations is a global service whose endpoint is in us-east-1
// ("AWS Organizations endpoints and quotas", AWS General Reference). The
// verifier accepts a request signed for any region, so the signing region
// is the caller's choice and never used: a Deny on aws:RequestedRegion
// would otherwise be lifted by signing for another region.
const Region = "us-east-1"

// Caller returns the verified principal of r. Every request but the health
// probes passes the signature check first, which puts it there, so a
// request without one is a fault.
func Caller(r *http.Request) (Principal, error) {
	p, ok := sigv4.PrincipalFrom(r.Context())
	if !ok {
		return Principal{}, fmt.Errorf("authz: the request carries no verified principal")
	}
	if err := checkRoot(Principal{Principal: p}); err != nil {
		return Principal{}, err
	}
	return Principal{Principal: p}, nil
}

// checkRoot fails when p's Root and Type disagree: Root skips evaluation
// here, while policy.Authorize grants full access to a Type of Account, so
// a principal that is one but not the other would be root to one and not
// the other. The keysource and the static key always set both together, so
// a principal that does not is a fault.
func checkRoot(p Principal) error {
	if p.Root != (p.Type == sigv4.PrincipalTypeAccount) {
		return fmt.Errorf("authz: principal %s has Root %t but type %q", p.ARN, p.Root, p.Type)
	}
	return nil
}

// RequireManagementAccount refuses a principal of any account but the
// management account, as Organizations refuses one of a member account
// with AccessDeniedException before its policies are looked at: the API
// reference says of every operation this service serves but
// DescribeOrganization "You can only call this operation from the
// management account or a member account that is a delegated
// administrator", or "from the management account". This service has no
// delegated administrators.
func (a *Authorizer) RequireManagementAccount(p Principal) error {
	if a.InManagementAccount(p) {
		return nil
	}
	return orgapi.ErrNotManagementAccount()
}

// InManagementAccount reports whether p is a principal of the management
// account, its root user included.
func (a *Authorizer) InManagementAccount(p Principal) bool {
	return p.AccountID == a.managementAccountID
}

// IsRoot reports whether p is the root user of this service's account, the
// management account: Root on a principal of any other account, which
// would be another account's root user, does not skip evaluation, and such
// a principal is refused as any principal of another account is.
func (a *Authorizer) IsRoot(p Principal) bool {
	return p.Root && a.InManagementAccount(p)
}

// Authorize evaluates p's identity policies for action on each of
// resources, which are the management account's, with the global condition
// keys of r and the operation's keys in opKeys, and returns the
// AccessDeniedException of the first resource they do not allow. The
// management account's root principal is allowed without evaluation. A
// request for no resource is a fault, never an allow: every operation acts
// on at least one, "*" included.
//
// Evaluation is policy.Authorize's, with no resource-based policy: this
// service stores none (Organizations' resource policy is for delegated
// administration, which is not served). Within the management account an
// identity-based Allow allows, as policy.Evaluate decided before; a
// principal of another account is denied with "because no resource-based
// policy allows the <action> action" even when its identity policies allow
// the action, since nothing can grant it. Callers keep such principals out
// with RequireManagementAccount first, as Organizations does.
func (a *Authorizer) Authorize(
	r *http.Request,
	p Principal,
	action string,
	resources []Resource,
	opKeys map[string][]string,
) error {
	return a.authorize(r, p, a.managementAccountID, action, resources, opKeys)
}

// AuthorizeInOwnAccount is Authorize for an operation any account in the
// organization may call, DescribeOrganization: the request is evaluated as
// one within p's own account, so p's identity policies alone decide, as
// Organizations lets "any account in the organization" call it with its
// own permissions. The caller must have checked that p's account is a
// member.
func (a *Authorizer) AuthorizeInOwnAccount(
	r *http.Request,
	p Principal,
	action string,
	resources []Resource,
	opKeys map[string][]string,
) error {
	return a.authorize(r, p, p.AccountID, action, resources, opKeys)
}

func (a *Authorizer) authorize(
	r *http.Request,
	p Principal,
	resourceAccount string,
	action string,
	resources []Resource,
	opKeys map[string][]string,
) error {
	if err := checkRoot(p); err != nil {
		return err
	}
	if a.IsRoot(p) {
		return nil
	}
	if len(resources) == 0 {
		return fmt.Errorf("authz: %s names no resource to evaluate", action)
	}
	policies, err := a.parse(p)
	if err != nil {
		return err
	}
	caller := CallerOf(p)
	global := GlobalKeys(r, p, time.Now())
	for _, res := range resources {
		out := policy.Authorize(policy.AuthorizeRequest{
			Action:          action,
			Resource:        res.ARN,
			ResourceAccount: resourceAccount,
			Caller:          caller,
			Context:         contextFor(global, opKeys, res),
		}, nil, policies...)
		if out.Decision != policy.Allow {
			return orgapi.ErrNotAuthorized(p.ARN, action, res.ARN, out.Reason.Message(action))
		}
	}
	return nil
}

// CallerOf is p as tule.dev/policy's Caller, from the fields identity's
// keysource fills: the account, the ARN that signed, aws:PrincipalArn (a
// role session's role ARN with its path, empty for a session whose role
// was deleted), aws:userid and aws:PrincipalType. policy.Authorize supplies
// aws:PrincipalArn, aws:PrincipalAccount, aws:userid, aws:PrincipalType and
// aws:username from it, refuses a Caller whose fields disagree, and refuses
// a session whose role was deleted.
func CallerOf(p Principal) policy.Caller {
	return policy.Caller{
		AccountID:    p.AccountID,
		ARN:          p.ARN,
		PrincipalARN: p.PrincipalARN,
		UserID:       p.UserID,
		Type:         policy.PrincipalType(p.Type),
	}
}

// contextFor is the request context evaluated for one resource: the global
// keys, the operation's, and the resource's aws:ResourceTag keys.
func contextFor(global, opKeys map[string][]string, res Resource) map[string][]string {
	keys := make(map[string][]string, len(global)+len(opKeys)+len(res.Tags))
	for k, v := range global {
		keys[k] = v
	}
	for k, v := range opKeys {
		keys[k] = v
	}
	for _, t := range res.Tags {
		keys["aws:ResourceTag/"+t.Key] = []string{t.Value}
	}
	return keys
}

// parse returns p's policy documents parsed, from the cache when a document
// was seen before. Identity checked every document when it was stored, so
// one that does not parse is a fault, never a document to skip.
func (a *Authorizer) parse(p Principal) ([]*policy.Policy, error) {
	out := make([]*policy.Policy, 0, len(p.Policies))
	for i, doc := range p.Policies {
		parsed, err := a.parseDocument(doc)
		if err != nil {
			return nil, fmt.Errorf("authz: parse policy %d of %s: %w", i, p.ARN, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

func (a *Authorizer) parseDocument(doc json.RawMessage) (*policy.Policy, error) {
	sum := sha256.Sum256(doc)
	a.mu.Lock()
	cached, ok := a.cache[sum]
	a.mu.Unlock()
	if ok {
		return cached, nil
	}

	parsed, err := policy.ParseIdentity(doc)
	if err != nil {
		return nil, fmt.Errorf("parse identity policy: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) >= maxCachedPolicies {
		// Drop an arbitrary entry: the cache only saves parsing, so which
		// document goes matters to speed alone.
		for k := range a.cache {
			delete(a.cache, k)
			break
		}
	}
	a.cache[sum] = parsed
	return parsed, nil
}

// cachedPolicies reports how many parsed documents the cache holds, for
// tests.
func (a *Authorizer) cachedPolicies() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.cache)
}

// GlobalKeys are the global condition keys ("AWS global condition context
// keys", IAM User Guide) this service supplies for a request by p at now,
// beside the principal's identity keys policy.Authorize supplies from
// CallerOf, which also fill the policy variables:
//
//   - aws:SourceIp, the address the connection came from. Nothing is
//     expected in front of this service, so X-Forwarded-For is not read.
//   - aws:CurrentTime and aws:EpochTime.
//   - aws:SecureTransport, whether the request came over TLS.
//   - aws:RequestedRegion, always Region, whatever region the request was
//     signed for.
//   - aws:PrincipalTag/<key> for each of the principal's tags: an IAM
//     user's, or a role session's role and session tags, as identity
//     merges them. Identity keeps the keys unique regardless of case and at
//     most 50.
func GlobalKeys(r *http.Request, p Principal, now time.Time) map[string][]string {
	now = now.UTC()
	keys := map[string][]string{
		"aws:CurrentTime":     {now.Format(time.RFC3339)},
		"aws:EpochTime":       {strconv.FormatInt(now.Unix(), 10)},
		"aws:SecureTransport": {strconv.FormatBool(r.TLS != nil)},
		"aws:RequestedRegion": {Region},
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		keys["aws:SourceIp"] = []string{host}
	}
	for k, v := range p.Tags {
		keys["aws:PrincipalTag/"+k] = []string{v}
	}
	return keys
}
