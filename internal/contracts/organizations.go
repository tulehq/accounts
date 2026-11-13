// Package contracts defines the organization store interface the HTTP modules
// depend on, with its input and output types and sentinel errors.
package contracts

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotInUse is returned by every operation but CreateOrganization while
	// there is no organization.
	ErrNotInUse = errors.New("organizations: no organization exists")

	// ErrAlreadyInOrganization is returned by CreateOrganization when the
	// organization exists already.
	ErrAlreadyInOrganization = errors.New("organizations: organization already exists")

	// ErrOrganizationNotEmpty is returned by DeleteOrganization while any
	// account other than the management account is a member.
	ErrOrganizationNotEmpty = errors.New("organizations: organization has member accounts")

	// ErrAccountNotFound is returned when no member account has the given ID,
	// and by MoveAccount when the account is not in the source parent.
	ErrAccountNotFound = errors.New("organizations: account not found")

	// ErrAccountAlreadyClosed is returned by CloseAccount for a closed
	// account.
	ErrAccountAlreadyClosed = errors.New("organizations: account already closed")

	// ErrCreateAccountStatusNotFound is returned when no create-account
	// request has the given ID.
	ErrCreateAccountStatusNotFound = errors.New("organizations: create account request not found")

	// ErrParentNotFound is returned when no root or OU has the given parent
	// ID.
	ErrParentNotFound = errors.New("organizations: parent not found")

	// ErrSourceParentNotFound is returned by MoveAccount when the source
	// parent does not exist.
	ErrSourceParentNotFound = errors.New("organizations: source parent not found")

	// ErrDestinationParentNotFound is returned by MoveAccount when the
	// destination parent does not exist.
	ErrDestinationParentNotFound = errors.New("organizations: destination parent not found")

	// ErrDuplicateAccount is returned by MoveAccount when the account is in
	// the destination already.
	ErrDuplicateAccount = errors.New("organizations: account already in destination")

	// ErrChildNotFound is returned by ListParents when no account or OU has
	// the given child ID.
	ErrChildNotFound = errors.New("organizations: child not found")

	// ErrOrganizationalUnitNotFound is returned when no OU has the given ID.
	ErrOrganizationalUnitNotFound = errors.New("organizations: organizational unit not found")

	// ErrOrganizationalUnitNotEmpty is returned by DeleteOrganizationalUnit
	// while the OU holds accounts or other OUs.
	ErrOrganizationalUnitNotEmpty = errors.New("organizations: organizational unit not empty")

	// ErrDuplicateOrganizationalUnit is returned when an OU of the same name
	// exists under the same parent.
	ErrDuplicateOrganizationalUnit = errors.New(
		"organizations: organizational unit name taken in parent")

	// ErrTargetNotFound is returned by the tag operations when no account, OU
	// or root has the given resource ID.
	ErrTargetNotFound = errors.New("organizations: tag target not found")

	// ErrManagementAccountCannotLeave is returned by
	// RemoveAccountFromOrganization for the management account.
	ErrManagementAccountCannotLeave = errors.New(
		"organizations: the management account cannot be removed")

	// ErrCannotCloseManagementAccount is returned by CloseAccount for the
	// management account.
	ErrCannotCloseManagementAccount = errors.New(
		"organizations: the management account cannot be closed")

	// ErrNotInAllFeaturesMode is returned by CloseAccount in an organization
	// created with the CONSOLIDATED_BILLING feature set.
	ErrNotInAllFeaturesMode = errors.New("organizations: all features are not enabled")

	// ErrOUDepthLimitExceeded is returned when an OU would sit deeper than
	// MaxOUDepth below the root.
	ErrOUDepthLimitExceeded = errors.New("organizations: OU nesting limit exceeded")

	// ErrOUNumberLimitExceeded is returned when the organization holds
	// MaxOrganizationalUnits OUs already.
	ErrOUNumberLimitExceeded = errors.New("organizations: OU limit exceeded")

	// ErrTagLimitExceeded is returned when a resource would carry more than
	// MaxTagsPerResource tags.
	ErrTagLimitExceeded = errors.New("organizations: tag limit exceeded")

	// ErrInvalidToken is returned for a pagination token the store did not
	// issue for that listing.
	ErrInvalidToken = errors.New("organizations: invalid pagination token")
)

// The quotas Organizations enforces that apply here, from the Organizations
// quotas documentation. The account quota is left out: it is adjustable on
// AWS, so no one value of it is the AWS behavior.
const (
	// MaxOUDepth is how many levels of OUs may nest under the root.
	MaxOUDepth = 5
	// MaxOrganizationalUnits is how many OUs an organization may hold.
	MaxOrganizationalUnits = 2000
	// MaxTagsPerResource is how many tags a root, OU or account may carry.
	MaxTagsPerResource = 50
)

// DefaultPageSize is how many items a list operation returns when the request
// sets no MaxResults. Organizations documents no default, so it is the
// largest page the operations accept.
const DefaultPageSize = 20

// The organization feature sets.
const (
	FeatureSetAll                 = "ALL"
	FeatureSetConsolidatedBilling = "CONSOLIDATED_BILLING"
)

// The account states this service puts an account in. CreateAccount and
// CreateOrganization make an account ACTIVE and CloseAccount makes it CLOSED
// at once; the transitional states AWS passes through are never reported.
const (
	AccountStateActive = "ACTIVE"
	AccountStateClosed = "CLOSED"
)

// How an account joined the organization: the management account was
// INVITED, as AWS reports it, and every account CreateAccount makes was
// CREATED.
const (
	JoinedMethodInvited = "INVITED"
	JoinedMethodCreated = "CREATED"
)

// The create-account request states and the one failure reason this service
// produces. CreateAccount is synchronous, so IN_PROGRESS is never reported.
const (
	CreateAccountStateSucceeded = "SUCCEEDED"
	CreateAccountStateFailed    = "FAILED"
	FailureEmailAlreadyExists   = "EMAIL_ALREADY_EXISTS"
)

// The kinds of parent and child in the organization tree.
const (
	NodeRoot               = "ROOT"
	NodeOrganizationalUnit = "ORGANIZATIONAL_UNIT"
	NodeAccount            = "ACCOUNT"
)

// The policy type and status a root reports when all features are enabled:
// CreateOrganization enables service control policies in the root.
const (
	PolicyTypeServiceControl = "SERVICE_CONTROL_POLICY"
	PolicyTypeStatusEnabled  = "ENABLED"
)

// DefaultRoleName is the role CreateAccount records for an account when the
// request names none.
const DefaultRoleName = "OrganizationAccountAccessRole"

// OrganizationProvider is the store the Organizations API is served from:
// the organization, its accounts, its tree of root and OUs, and tags.
type OrganizationProvider interface {
	CreateOrganization(ctx context.Context, featureSet string) (*Organization, error)
	DescribeOrganization(ctx context.Context) (*Organization, error)
	DeleteOrganization(ctx context.Context) error

	CreateAccount(ctx context.Context, in CreateAccountInput) (*CreateAccountStatus, error)
	DescribeCreateAccountStatus(ctx context.Context, requestID string) (*CreateAccountStatus, error)
	ListCreateAccountStatus(
		ctx context.Context,
		in ListCreateAccountStatusInput,
	) (*Page[CreateAccountStatus], error)
	DescribeAccount(ctx context.Context, accountID string) (*Account, error)
	ListAccounts(ctx context.Context, page PageInput) (*Page[Account], error)
	ListAccountsForParent(
		ctx context.Context,
		parentID string,
		page PageInput,
	) (*Page[Account], error)
	CloseAccount(ctx context.Context, accountID string) error
	RemoveAccountFromOrganization(ctx context.Context, accountID string) error
	MoveAccount(ctx context.Context, in MoveAccountInput) error

	ListRoots(ctx context.Context, page PageInput) (*Page[Root], error)
	ListParents(ctx context.Context, childID string, page PageInput) (*Page[Node], error)
	ListChildren(ctx context.Context, in ListChildrenInput) (*Page[Node], error)
	CreateOrganizationalUnit(
		ctx context.Context,
		in CreateOrganizationalUnitInput,
	) (*OrganizationalUnit, error)
	DescribeOrganizationalUnit(ctx context.Context, ouID string) (*OrganizationalUnit, error)
	UpdateOrganizationalUnit(
		ctx context.Context,
		in UpdateOrganizationalUnitInput,
	) (*OrganizationalUnit, error)
	DeleteOrganizationalUnit(ctx context.Context, ouID string) error
	ListOrganizationalUnitsForParent(
		ctx context.Context,
		parentID string,
		page PageInput,
	) (*Page[OrganizationalUnit], error)

	TagResource(ctx context.Context, resourceID string, tags []Tag) error
	UntagResource(ctx context.Context, resourceID string, keys []string) error
	ListTagsForResource(ctx context.Context, resourceID string, page PageInput) (*Page[Tag], error)

	// ResourceTags returns every tag of the resource with the ID, in key
	// order, or none when no resource has it, for the aws:ResourceTag
	// condition keys. It needs no organization.
	ResourceTags(ctx context.Context, resourceID string) ([]Tag, error)
}

// PolicyTypeSummary is a policy type and its status in a root.
type PolicyTypeSummary struct {
	Type   string
	Status string
}

// Organization describes the organization. AvailablePolicyTypes is what AWS
// still reports in that deprecated field.
type Organization struct {
	ID                     string
	ARN                    string
	FeatureSet             string
	ManagementAccountID    string
	ManagementAccountARN   string
	ManagementAccountEmail string
	AvailablePolicyTypes   []PolicyTypeSummary
}

// Account is a member account. Paths holds its one path in the tree.
type Account struct {
	JoinedTimestamp time.Time
	ID              string
	ARN             string
	Email           string
	Name            string
	State           string
	JoinedMethod    string
	Paths           []string
}

// CreateAccountStatus is the record of one CreateAccount request. AccountID
// is set when it succeeded and FailureReason when it failed.
type CreateAccountStatus struct {
	RequestedTimestamp time.Time
	CompletedTimestamp time.Time
	ID                 string
	AccountName        string
	AccountID          string
	State              string
	FailureReason      string
}

// Root is the organization's root.
type Root struct {
	ID          string
	ARN         string
	Name        string
	PolicyTypes []PolicyTypeSummary
}

// OrganizationalUnit is an OU. Path is its path in the tree, ending in its own
// ID.
type OrganizationalUnit struct {
	ID   string
	ARN  string
	Name string
	Path string
}

// Node is a parent or a child in the tree: its ID and one of NodeRoot,
// NodeOrganizationalUnit and NodeAccount.
type Node struct {
	ID   string
	Type string
}

// Tag is one of a resource's tags.
type Tag struct {
	Key   string
	Value string
}

// PageInput selects one page of a listing. MaxResults of zero means
// DefaultPageSize.
type PageInput struct {
	NextToken  string
	MaxResults int
}

// Page is one page of a listing. NextToken is empty on the last page.
type Page[T any] struct {
	NextToken string
	Items     []T
}

// CreateAccountInput creates a member account in the root. An empty RoleName
// means DefaultRoleName.
type CreateAccountInput struct {
	AccountName string
	Email       string
	RoleName    string
	Tags        []Tag
}

// ListCreateAccountStatusInput pages through the create-account requests,
// keeping only those in States when it is not empty.
type ListCreateAccountStatusInput struct {
	States []string
	Page   PageInput
}

// MoveAccountInput moves an account from SourceParentID, which must hold it,
// to DestinationParentID.
type MoveAccountInput struct {
	AccountID           string
	SourceParentID      string
	DestinationParentID string
}

// ListChildrenInput pages through the children of one type, NodeAccount or
// NodeOrganizationalUnit, of a parent.
type ListChildrenInput struct {
	ParentID  string
	ChildType string
	Page      PageInput
}

// CreateOrganizationalUnitInput creates an OU under ParentID.
type CreateOrganizationalUnitInput struct {
	ParentID string
	Name     string
	Tags     []Tag
}

// UpdateOrganizationalUnitInput renames an OU. A nil Name leaves it as it is.
type UpdateOrganizationalUnitInput struct {
	Name *string
	ID   string
}
