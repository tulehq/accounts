package organization

import (
	"github.com/gasmod/gas"

	"tule.dev/accounts/internal/contracts"
	"tule.dev/accounts/internal/orgapi"
)

func (m *Module) createOrganization(ctx gas.Context) error {
	req, err := decode[orgapi.CreateOrganizationRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.Enum("FeatureSet", req.FeatureSet,
		contracts.FeatureSetAll, contracts.FeatureSetConsolidatedBilling); err != nil {
		return err
	}

	out, err := m.store.CreateOrganization(ctx, req.FeatureSet)
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.OrganizationResponse{Organization: wireOrganization(out)})
}

func (m *Module) describeOrganization(ctx gas.Context) error {
	out, err := m.store.DescribeOrganization(ctx)
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.OrganizationResponse{Organization: wireOrganization(out)})
}

func (m *Module) deleteOrganization(ctx gas.Context) error {
	if err := m.store.DeleteOrganization(ctx); err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.EmptyResponse{})
}

func wireOrganization(o *contracts.Organization) orgapi.Organization {
	return orgapi.Organization{
		Arn:                  o.ARN,
		FeatureSet:           o.FeatureSet,
		ID:                   o.ID,
		MasterAccountArn:     o.ManagementAccountARN,
		MasterAccountEmail:   o.ManagementAccountEmail,
		MasterAccountID:      o.ManagementAccountID,
		AvailablePolicyTypes: wirePolicyTypes(o.AvailablePolicyTypes),
	}
}
