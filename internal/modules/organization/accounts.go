package organization

import (
	"github.com/gasmod/gas"

	"tule.dev/accounts/internal/contracts"
	"tule.dev/accounts/internal/orgapi"
)

// The values the enumerations of the account operations take.
var (
	billingAccess       = []string{"ALLOW", "DENY"}
	createAccountStates = []string{
		"IN_PROGRESS", contracts.CreateAccountStateSucceeded, contracts.CreateAccountStateFailed,
	}
)

// accountStatus is the deprecated Status field, which AWS announced it removes
// from its responses by 9 September 2026 and the SDK still models: a closed
// account reports SUSPENDED there, since Status has no CLOSED.
func accountStatus(state string) string {
	if state == contracts.AccountStateClosed {
		return "SUSPENDED"
	}
	return state
}

func (m *Module) createAccount(ctx gas.Context) error {
	req, err := decode[orgapi.CreateAccountRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.Email.Require("Email", req.Email); err != nil {
		return err
	}
	if err = orgapi.AccountName.Require("AccountName", req.AccountName); err != nil {
		return err
	}
	if err = orgapi.CheckRoleName(req.RoleName); err != nil {
		return err
	}
	if err = orgapi.Enum("IamUserAccessToBilling", req.IamUserAccessToBilling,
		billingAccess...); err != nil {
		return err
	}
	tags, err := tagsOf(req.Tags)
	if err != nil {
		return err
	}

	in := contracts.CreateAccountInput{
		AccountName: req.AccountName,
		Email:       req.Email,
		Tags:        tags,
	}
	if req.RoleName != nil {
		in.RoleName = *req.RoleName
	}
	out, err := m.store.CreateAccount(ctx, in)
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.CreateAccountStatusResponse{
		CreateAccountStatus: wireStatus(out),
	})
}

func (m *Module) describeCreateAccountStatus(ctx gas.Context) error {
	req, err := decode[orgapi.DescribeCreateAccountStatusRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.CreateAccountRequestID.Require("CreateAccountRequestId",
		req.CreateAccountRequestID); err != nil {
		return err
	}

	out, err := m.store.DescribeCreateAccountStatus(ctx, req.CreateAccountRequestID)
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.CreateAccountStatusResponse{
		CreateAccountStatus: wireStatus(out),
	})
}

func (m *Module) listCreateAccountStatus(ctx gas.Context) error {
	req, err := decode[orgapi.ListCreateAccountStatusRequest](ctx)
	if err != nil {
		return err
	}
	page, err := pageOf(req.MaxResults, req.NextToken)
	if err != nil {
		return err
	}
	for _, st := range req.States {
		if err = orgapi.RequireEnum("States", st, createAccountStates...); err != nil {
			return err
		}
	}

	out, err := m.store.ListCreateAccountStatus(ctx, contracts.ListCreateAccountStatusInput{
		States: req.States,
		Page:   page,
	})
	if err != nil {
		return err
	}
	resp := orgapi.ListCreateAccountStatusResponse{
		NextToken:             out.NextToken,
		CreateAccountStatuses: make([]orgapi.CreateAccountStatus, 0, len(out.Items)),
	}
	for i := range out.Items {
		resp.CreateAccountStatuses = append(resp.CreateAccountStatuses, wireStatus(&out.Items[i]))
	}
	return orgapi.Write(ctx, resp)
}

func (m *Module) describeAccount(ctx gas.Context) error {
	req, err := decode[orgapi.AccountIDRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.AccountID.Require("AccountId", req.AccountID); err != nil {
		return err
	}

	out, err := m.store.DescribeAccount(ctx, req.AccountID)
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.DescribeAccountResponse{Account: wireAccount(out)})
}

func (m *Module) listAccounts(ctx gas.Context) error {
	req, err := decode[orgapi.PageRequest](ctx)
	if err != nil {
		return err
	}
	page, err := pageOf(req.MaxResults, req.NextToken)
	if err != nil {
		return err
	}

	out, err := m.store.ListAccounts(ctx, page)
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, wireAccounts(out))
}

func (m *Module) listAccountsForParent(ctx gas.Context) error {
	req, err := decode[orgapi.ParentPageRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.ParentID.Require("ParentId", req.ParentID); err != nil {
		return err
	}
	page, err := pageOf(req.MaxResults, req.NextToken)
	if err != nil {
		return err
	}

	out, err := m.store.ListAccountsForParent(ctx, req.ParentID, page)
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, wireAccounts(out))
}

func (m *Module) closeAccount(ctx gas.Context) error {
	req, err := decode[orgapi.AccountIDRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.AccountID.Require("AccountId", req.AccountID); err != nil {
		return err
	}

	if err = m.store.CloseAccount(ctx, req.AccountID); err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.EmptyResponse{})
}

func (m *Module) removeAccountFromOrganization(ctx gas.Context) error {
	req, err := decode[orgapi.AccountIDRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.AccountID.Require("AccountId", req.AccountID); err != nil {
		return err
	}

	if err = m.store.RemoveAccountFromOrganization(ctx, req.AccountID); err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.EmptyResponse{})
}

func (m *Module) moveAccount(ctx gas.Context) error {
	req, err := decode[orgapi.MoveAccountRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.AccountID.Require("AccountId", req.AccountID); err != nil {
		return err
	}
	if err = orgapi.ParentID.Require("SourceParentId", req.SourceParentID); err != nil {
		return err
	}
	if err = orgapi.ParentID.Require("DestinationParentId", req.DestinationParentID); err != nil {
		return err
	}

	if err = m.store.MoveAccount(ctx, contracts.MoveAccountInput{
		AccountID:           req.AccountID,
		SourceParentID:      req.SourceParentID,
		DestinationParentID: req.DestinationParentID,
	}); err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.EmptyResponse{})
}

func wireAccount(a *contracts.Account) orgapi.Account {
	return orgapi.Account{
		Arn:             a.ARN,
		Email:           a.Email,
		ID:              a.ID,
		JoinedMethod:    a.JoinedMethod,
		JoinedTimestamp: orgapi.Stamp(a.JoinedTimestamp),
		Name:            a.Name,
		State:           a.State,
		Status:          accountStatus(a.State),
		Paths:           a.Paths,
	}
}

func wireAccounts(page *contracts.Page[contracts.Account]) orgapi.ListAccountsResponse {
	resp := orgapi.ListAccountsResponse{
		NextToken: page.NextToken,
		Accounts:  make([]orgapi.Account, 0, len(page.Items)),
	}
	for i := range page.Items {
		resp.Accounts = append(resp.Accounts, wireAccount(&page.Items[i]))
	}
	return resp
}

func wireStatus(st *contracts.CreateAccountStatus) orgapi.CreateAccountStatus {
	return orgapi.CreateAccountStatus{
		AccountID:          st.AccountID,
		AccountName:        st.AccountName,
		CompletedTimestamp: orgapi.Stamp(st.CompletedTimestamp),
		FailureReason:      st.FailureReason,
		ID:                 st.ID,
		RequestedTimestamp: orgapi.Stamp(st.RequestedTimestamp),
		State:              st.State,
	}
}
