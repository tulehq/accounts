package sqlimpl

// Settings configures where the store keeps its data: Path is the SQLite
// database file, created with its directory when it does not exist.
type Settings struct {
	Path string `validate:"required"`
}

// OrganizationSettings describes the management account. It is configured,
// not created: CreateOrganization makes this account the management account
// and the first member of the new organization.
type OrganizationSettings struct {
	ManagementAccountID    string `validate:"required"`
	ManagementAccountEmail string `validate:"required"`
	ManagementAccountName  string `validate:"required"`
}
