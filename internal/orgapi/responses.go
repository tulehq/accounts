package orgapi

// The response bodies this service writes, following the SDK's response
// snapshots. Every field the model marks optional is omitted when empty, so a
// response carries only what this service actually knows; the lists a list
// operation returns are always present, empty or not.

// PolicyTypeSummary is a policy type and its status in a root.
type PolicyTypeSummary struct {
	Status string `json:"Status,omitempty"`
	Type   string `json:"Type,omitempty"`
}

// Organization describes the organization. The Master* names are the wire
// names AWS kept for the management account.
type Organization struct {
	Arn                  string              `json:"Arn,omitempty"`
	FeatureSet           string              `json:"FeatureSet,omitempty"`
	ID                   string              `json:"Id,omitempty"`
	MasterAccountArn     string              `json:"MasterAccountArn,omitempty"`
	MasterAccountEmail   string              `json:"MasterAccountEmail,omitempty"`
	MasterAccountID      string              `json:"MasterAccountId,omitempty"`
	AvailablePolicyTypes []PolicyTypeSummary `json:"AvailablePolicyTypes,omitempty"`
}

// OrganizationResponse is the body of CreateOrganization and
// DescribeOrganization.
type OrganizationResponse struct {
	Organization Organization `json:"Organization"`
}

// Account is a member account.
type Account struct {
	JoinedTimestamp *Timestamp `json:"JoinedTimestamp,omitempty"`
	Arn             string     `json:"Arn,omitempty"`
	Email           string     `json:"Email,omitempty"`
	ID              string     `json:"Id,omitempty"`
	JoinedMethod    string     `json:"JoinedMethod,omitempty"`
	Name            string     `json:"Name,omitempty"`
	State           string     `json:"State,omitempty"`
	Status          string     `json:"Status,omitempty"`
	Paths           []string   `json:"Paths,omitempty"`
}

// DescribeAccountResponse is the body of DescribeAccount.
type DescribeAccountResponse struct {
	Account Account `json:"Account"`
}

// ListAccountsResponse is the body of ListAccounts and ListAccountsForParent.
type ListAccountsResponse struct {
	NextToken string    `json:"NextToken,omitempty"`
	Accounts  []Account `json:"Accounts"`
}

// CreateAccountStatus is the record of one CreateAccount request.
type CreateAccountStatus struct {
	CompletedTimestamp *Timestamp `json:"CompletedTimestamp,omitempty"`
	RequestedTimestamp *Timestamp `json:"RequestedTimestamp,omitempty"`
	AccountID          string     `json:"AccountId,omitempty"`
	AccountName        string     `json:"AccountName,omitempty"`
	FailureReason      string     `json:"FailureReason,omitempty"`
	ID                 string     `json:"Id,omitempty"`
	State              string     `json:"State,omitempty"`
}

// CreateAccountStatusResponse is the body of CreateAccount and
// DescribeCreateAccountStatus.
type CreateAccountStatusResponse struct {
	CreateAccountStatus CreateAccountStatus `json:"CreateAccountStatus"`
}

// ListCreateAccountStatusResponse is the body of ListCreateAccountStatus.
type ListCreateAccountStatusResponse struct {
	NextToken             string                `json:"NextToken,omitempty"`
	CreateAccountStatuses []CreateAccountStatus `json:"CreateAccountStatuses"`
}

// Root is the organization's root.
type Root struct {
	Arn         string              `json:"Arn,omitempty"`
	ID          string              `json:"Id,omitempty"`
	Name        string              `json:"Name,omitempty"`
	PolicyTypes []PolicyTypeSummary `json:"PolicyTypes"`
}

// ListRootsResponse is the body of ListRoots.
type ListRootsResponse struct {
	NextToken string `json:"NextToken,omitempty"`
	Roots     []Root `json:"Roots"`
}

// Node is a parent or a child in the tree.
type Node struct {
	ID   string `json:"Id,omitempty"`
	Type string `json:"Type,omitempty"`
}

// ListParentsResponse is the body of ListParents.
type ListParentsResponse struct {
	NextToken string `json:"NextToken,omitempty"`
	Parents   []Node `json:"Parents"`
}

// ListChildrenResponse is the body of ListChildren.
type ListChildrenResponse struct {
	NextToken string `json:"NextToken,omitempty"`
	Children  []Node `json:"Children"`
}

// OrganizationalUnit is an OU.
type OrganizationalUnit struct {
	Arn  string `json:"Arn,omitempty"`
	ID   string `json:"Id,omitempty"`
	Name string `json:"Name,omitempty"`
	Path string `json:"Path,omitempty"`
}

// OrganizationalUnitResponse is the body of CreateOrganizationalUnit,
// DescribeOrganizationalUnit and UpdateOrganizationalUnit.
type OrganizationalUnitResponse struct {
	OrganizationalUnit OrganizationalUnit `json:"OrganizationalUnit"`
}

// ListOrganizationalUnitsResponse is the body of
// ListOrganizationalUnitsForParent.
type ListOrganizationalUnitsResponse struct {
	NextToken           string               `json:"NextToken,omitempty"`
	OrganizationalUnits []OrganizationalUnit `json:"OrganizationalUnits"`
}

// ResponseTag is one tag in a response, where the value is always present.
type ResponseTag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
}

// ListTagsForResourceResponse is the body of ListTagsForResource.
type ListTagsForResourceResponse struct {
	NextToken string        `json:"NextToken,omitempty"`
	Tags      []ResponseTag `json:"Tags"`
}

// EmptyResponse is the body of the operations that answer with nothing.
type EmptyResponse struct{}
