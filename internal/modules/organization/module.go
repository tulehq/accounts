// Package organization serves the Organizations API: one route that
// dispatches on the operation named in the request's X-Amz-Target header, as
// the AWS JSON protocol does.
package organization

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/gasmod/gas"

	"tule.dev/accounts/internal/contracts"
	"tule.dev/accounts/internal/orgapi"
)

const moduleName = "tule/modules/organization"

// Module registers the API route and serves the operations behind it.
type Module struct {
	router   *gas.Router
	store    contracts.OrganizationProvider
	handlers map[string]handler
}

// handler serves one operation. Returning an error leaves the response to the
// dispatcher, which renders it as an Organizations error document.
type handler func(gas.Context) error

// NewModule returns a Module serving from store. It registers its route when
// the app initializes it.
func NewModule(router *gas.Router, store contracts.OrganizationProvider) *Module {
	m := &Module{router: router, store: store}
	m.handlers = map[string]handler{
		"CreateOrganization":               m.createOrganization,
		"DescribeOrganization":             m.describeOrganization,
		"DeleteOrganization":               m.deleteOrganization,
		"CreateAccount":                    m.createAccount,
		"DescribeCreateAccountStatus":      m.describeCreateAccountStatus,
		"ListCreateAccountStatus":          m.listCreateAccountStatus,
		"DescribeAccount":                  m.describeAccount,
		"ListAccounts":                     m.listAccounts,
		"ListAccountsForParent":            m.listAccountsForParent,
		"CloseAccount":                     m.closeAccount,
		"RemoveAccountFromOrganization":    m.removeAccountFromOrganization,
		"MoveAccount":                      m.moveAccount,
		"ListRoots":                        m.listRoots,
		"ListParents":                      m.listParents,
		"ListChildren":                     m.listChildren,
		"CreateOrganizationalUnit":         m.createOrganizationalUnit,
		"DescribeOrganizationalUnit":       m.describeOrganizationalUnit,
		"UpdateOrganizationalUnit":         m.updateOrganizationalUnit,
		"DeleteOrganizationalUnit":         m.deleteOrganizationalUnit,
		"ListOrganizationalUnitsForParent": m.listOrganizationalUnitsForParent,
		"TagResource":                      m.tagResource,
		"UntagResource":                    m.untagResource,
		"ListTagsForResource":              m.listTagsForResource,
	}
	return m
}

// Name identifies the module to gas.
func (m *Module) Name() string {
	return moduleName
}

// Init registers the module's route.
func (m *Module) Init(context.Context) error {
	// The AWS JSON protocol puts every operation on POST /, so there is one
	// route and the operation comes from a header.
	m.router.Handle(m, http.MethodPost, "/", m.dispatch)
	return nil
}

// Close releases nothing; the module holds no resources of its own.
func (m *Module) Close(context.Context) error {
	return nil
}

// dispatch serves the operation the request names. An operation this service
// does not serve, whether or not Organizations has it, is answered as an
// unknown operation, as AWS answers a target it does not know.
func (m *Module) dispatch(ctx gas.Context) error {
	op := orgapi.Operation(ctx.Header(orgapi.TargetHeader))

	h, ok := m.handlers[op]
	if !ok {
		return orgapi.WriteError(ctx, orgapi.ErrUnknownOperation(
			"The X-Amz-Target header names no Organizations operation this service serves."))
	}
	if err := h(ctx); err != nil {
		return orgapi.WriteError(ctx, err)
	}
	return nil
}

// decode reads a request body into T. An empty body decodes to the zero value,
// and unknown fields are ignored, as the AWS JSON protocol expects.
func decode[T any](ctx gas.Context) (T, error) {
	var body T
	err := json.NewDecoder(ctx.Request().Body).Decode(&body)
	if err != nil && !errors.Is(err, io.EOF) {
		return body, orgapi.ErrSerialization("The request body is not valid JSON, " +
			"or a field has the wrong type.")
	}
	return body, nil
}

// pageOf checks a list request's page parameters.
func pageOf(maxResults *int, nextToken string) (contracts.PageInput, error) {
	n, err := orgapi.MaxResults(maxResults)
	if err != nil {
		return contracts.PageInput{}, err
	}
	if err = orgapi.NextToken.Check("NextToken", nextToken); err != nil {
		return contracts.PageInput{}, err
	}
	return contracts.PageInput{NextToken: nextToken, MaxResults: n}, nil
}

// tagsOf checks request tags and converts them for the store.
func tagsOf(tags []orgapi.Tag) ([]contracts.Tag, error) {
	if err := orgapi.Tags(tags); err != nil {
		return nil, err
	}
	out := make([]contracts.Tag, 0, len(tags))
	for _, t := range tags {
		out = append(out, contracts.Tag{Key: t.Key, Value: *t.Value})
	}
	return out, nil
}

func wirePolicyTypes(types []contracts.PolicyTypeSummary) []orgapi.PolicyTypeSummary {
	out := make([]orgapi.PolicyTypeSummary, 0, len(types))
	for _, t := range types {
		out = append(out, orgapi.PolicyTypeSummary{Type: t.Type, Status: t.Status})
	}
	return out
}
