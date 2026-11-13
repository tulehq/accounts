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
	"strings"
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
	return Principal{Principal: p}, nil
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
// resources, with the global condition keys of r and the operation's keys
// in opKeys, and returns the AccessDeniedException of the first resource
// they do not allow. The management account's root principal is allowed
// without evaluation. A
// request for no resource is a fault, never an allow: every operation acts
// on at least one, "*" included.
func (a *Authorizer) Authorize(
	r *http.Request,
	p Principal,
	action string,
	resources []Resource,
	opKeys map[string][]string,
) error {
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
	global := GlobalKeys(r, p, time.Now())
	for _, res := range resources {
		out := policy.Evaluate(policy.Request{
			Action:    action,
			Resource:  res.ARN,
			Principal: p.ARN,
			Context:   contextFor(global, opKeys, res),
		}, policies...)
		switch out.Decision {
		case policy.Allow:
		case policy.ExplicitDeny:
			return orgapi.ErrExplicitlyDenied(p.ARN, action, res.ARN)
		default:
			return orgapi.ErrNotAllowed(p.ARN, action, res.ARN)
		}
	}
	return nil
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
// which also fill the policy variables:
//
//   - aws:SourceIp, the address the connection came from. Nothing is
//     expected in front of this service, so X-Forwarded-For is not read.
//   - aws:CurrentTime and aws:EpochTime.
//   - aws:SecureTransport, whether the request came over TLS.
//   - aws:PrincipalAccount, and aws:PrincipalArn: an IAM user's ARN, or for a
//     role session the role's ARN, which AWS gives with the role's path.
//     The path is not known here (the session ARN carries none), so the
//     role ARN has none; a condition on a role path does not match.
//   - aws:username, for an IAM user, and aws:PrincipalType.
//   - aws:RequestedRegion, always Region, whatever region the request was
//     signed for.
//
// aws:userid is left out, as the unique IDs it is made of are identity's
// and do not reach this service; tule.dev/policy derives it for the root
// user, which is never evaluated here anyway. aws:PrincipalTag is not
// supplied either: the principal's tags do not reach this service.
func GlobalKeys(r *http.Request, p Principal, now time.Time) map[string][]string {
	now = now.UTC()
	keys := map[string][]string{
		"aws:CurrentTime":      {now.Format(time.RFC3339)},
		"aws:EpochTime":        {strconv.FormatInt(now.Unix(), 10)},
		"aws:SecureTransport":  {strconv.FormatBool(r.TLS != nil)},
		"aws:PrincipalAccount": {p.AccountID},
		"aws:RequestedRegion":  {Region},
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		keys["aws:SourceIp"] = []string{host}
	}
	if name, ok := userName(p.ARN); ok {
		keys["aws:PrincipalArn"] = []string{p.ARN}
		keys["aws:username"] = []string{name}
		keys["aws:PrincipalType"] = []string{"User"}
	} else if role, ok := sessionRoleARN(p.ARN); ok {
		keys["aws:PrincipalArn"] = []string{role}
		keys["aws:PrincipalType"] = []string{"AssumedRole"}
	}
	return keys
}

// userName returns the user name of an IAM user ARN,
// arn:PARTITION:iam::ACCOUNT:user/PATH/NAME: its last path segment.
func userName(arn string) (string, bool) {
	resource, ok := resourceOf(arn, "iam")
	if !ok {
		return "", false
	}
	path, ok := strings.CutPrefix(resource, "user/")
	if !ok {
		return "", false
	}
	name := path[strings.LastIndex(path, "/")+1:]
	return name, name != ""
}

// sessionRoleARN returns the role ARN of an assumed-role session ARN,
// arn:PARTITION:sts::ACCOUNT:assumed-role/ROLE/SESSION, without the role's
// path, which the session ARN does not carry.
func sessionRoleARN(arn string) (string, bool) {
	resource, ok := resourceOf(arn, "sts")
	if !ok {
		return "", false
	}
	rest, ok := strings.CutPrefix(resource, "assumed-role/")
	if !ok {
		return "", false
	}
	role, session, ok := strings.Cut(rest, "/")
	if !ok || role == "" || session == "" {
		return "", false
	}
	fields := strings.SplitN(arn, ":", 6)
	return "arn:" + fields[1] + ":iam::" + fields[4] + ":role/" + role, true
}

// resourceOf returns the resource field of an ARN of service with no
// region, as IAM and STS ARNs have none.
func resourceOf(arn, service string) (string, bool) {
	fields := strings.SplitN(arn, ":", 6)
	if len(fields) != 6 || fields[0] != "arn" || fields[1] == "" || fields[2] != service ||
		fields[3] != "" || fields[4] == "" {
		return "", false
	}
	return fields[5], true
}
