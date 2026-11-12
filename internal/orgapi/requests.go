package orgapi

// The request bodies this service reads. Field names and types follow the
// Organizations API model and the SDK's request snapshots. A value the caller
// may legitimately send as empty, or whose absence means something, is a
// pointer, so an absent field can be told from an empty one.

// CreateOrganizationRequest is the body of CreateOrganization.
type CreateOrganizationRequest struct {
	FeatureSet string `json:"FeatureSet"`
}

// CreateAccountRequest is the body of CreateAccount.
type CreateAccountRequest struct {
	RoleName               *string `json:"RoleName"`
	AccountName            string  `json:"AccountName"`
	Email                  string  `json:"Email"`
	IamUserAccessToBilling string  `json:"IamUserAccessToBilling"`
	Tags                   []Tag   `json:"Tags"`
}

// DescribeCreateAccountStatusRequest is the body of
// DescribeCreateAccountStatus.
type DescribeCreateAccountStatusRequest struct {
	CreateAccountRequestID string `json:"CreateAccountRequestId"`
}

// ListCreateAccountStatusRequest is the body of ListCreateAccountStatus.
type ListCreateAccountStatusRequest struct {
	MaxResults *int     `json:"MaxResults"`
	NextToken  string   `json:"NextToken"`
	States     []string `json:"States"`
}

// AccountIDRequest is the body of the operations that take nothing but an
// account ID: DescribeAccount, CloseAccount and
// RemoveAccountFromOrganization.
type AccountIDRequest struct {
	AccountID string `json:"AccountId"`
}

// PageRequest is the body of the list operations that take nothing but a
// page: ListAccounts and ListRoots.
type PageRequest struct {
	MaxResults *int   `json:"MaxResults"`
	NextToken  string `json:"NextToken"`
}

// ParentPageRequest is the body of the list operations scoped to a parent:
// ListAccountsForParent and ListOrganizationalUnitsForParent.
type ParentPageRequest struct {
	MaxResults *int   `json:"MaxResults"`
	ParentID   string `json:"ParentId"`
	NextToken  string `json:"NextToken"`
}

// MoveAccountRequest is the body of MoveAccount.
type MoveAccountRequest struct {
	AccountID           string `json:"AccountId"`
	SourceParentID      string `json:"SourceParentId"`
	DestinationParentID string `json:"DestinationParentId"`
}

// ListParentsRequest is the body of ListParents.
type ListParentsRequest struct {
	MaxResults *int   `json:"MaxResults"`
	ChildID    string `json:"ChildId"`
	NextToken  string `json:"NextToken"`
}

// ListChildrenRequest is the body of ListChildren.
type ListChildrenRequest struct {
	MaxResults *int   `json:"MaxResults"`
	ParentID   string `json:"ParentId"`
	ChildType  string `json:"ChildType"`
	NextToken  string `json:"NextToken"`
}

// CreateOrganizationalUnitRequest is the body of CreateOrganizationalUnit.
type CreateOrganizationalUnitRequest struct {
	ParentID string `json:"ParentId"`
	Name     string `json:"Name"`
	Tags     []Tag  `json:"Tags"`
}

// OrganizationalUnitIDRequest is the body of the operations that take nothing
// but an OU ID: DescribeOrganizationalUnit and DeleteOrganizationalUnit.
type OrganizationalUnitIDRequest struct {
	OrganizationalUnitID string `json:"OrganizationalUnitId"`
}

// UpdateOrganizationalUnitRequest is the body of UpdateOrganizationalUnit.
type UpdateOrganizationalUnitRequest struct {
	Name                 *string `json:"Name"`
	OrganizationalUnitID string  `json:"OrganizationalUnitId"`
}

// TagResourceRequest is the body of TagResource.
type TagResourceRequest struct {
	ResourceID string `json:"ResourceId"`
	Tags       []Tag  `json:"Tags"`
}

// UntagResourceRequest is the body of UntagResource.
type UntagResourceRequest struct {
	ResourceID string   `json:"ResourceId"`
	TagKeys    []string `json:"TagKeys"`
}

// ListTagsForResourceRequest is the body of ListTagsForResource, which takes
// no MaxResults.
type ListTagsForResourceRequest struct {
	ResourceID string `json:"ResourceId"`
	NextToken  string `json:"NextToken"`
}

// Tag is one tag in a request. Value is a pointer because an empty value is
// allowed and a missing one is not.
type Tag struct {
	Value *string `json:"Value"`
	Key   string  `json:"Key"`
}
