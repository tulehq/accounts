package organization

import (
	"github.com/gasmod/gas"

	"tule.dev/accounts/internal/contracts"
	"tule.dev/accounts/internal/orgapi"
)

func (m *Module) listRoots(ctx gas.Context) error {
	req, err := decode[orgapi.PageRequest](ctx)
	if err != nil {
		return err
	}
	page, err := pageOf(req.MaxResults, req.NextToken)
	if err != nil {
		return err
	}

	out, err := m.store.ListRoots(ctx, page)
	if err != nil {
		return err
	}
	resp := orgapi.ListRootsResponse{
		NextToken: out.NextToken,
		Roots:     make([]orgapi.Root, 0, len(out.Items)),
	}
	for _, r := range out.Items {
		resp.Roots = append(resp.Roots, orgapi.Root{
			Arn:         r.ARN,
			ID:          r.ID,
			Name:        r.Name,
			PolicyTypes: wirePolicyTypes(r.PolicyTypes),
		})
	}
	return orgapi.Write(ctx, resp)
}

func (m *Module) listParents(ctx gas.Context) error {
	req, err := decode[orgapi.ListParentsRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.ChildID.Require("ChildId", req.ChildID); err != nil {
		return err
	}
	page, err := pageOf(req.MaxResults, req.NextToken)
	if err != nil {
		return err
	}

	out, err := m.store.ListParents(ctx, req.ChildID, page)
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.ListParentsResponse{
		NextToken: out.NextToken,
		Parents:   wireNodes(out.Items),
	})
}

func (m *Module) listChildren(ctx gas.Context) error {
	req, err := decode[orgapi.ListChildrenRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.ParentID.Require("ParentId", req.ParentID); err != nil {
		return err
	}
	if err = orgapi.RequireEnum("ChildType", req.ChildType,
		contracts.NodeAccount, contracts.NodeOrganizationalUnit); err != nil {
		return err
	}
	page, err := pageOf(req.MaxResults, req.NextToken)
	if err != nil {
		return err
	}

	out, err := m.store.ListChildren(ctx, contracts.ListChildrenInput{
		ParentID:  req.ParentID,
		ChildType: req.ChildType,
		Page:      page,
	})
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.ListChildrenResponse{
		NextToken: out.NextToken,
		Children:  wireNodes(out.Items),
	})
}

func (m *Module) createOrganizationalUnit(ctx gas.Context) error {
	req, err := decode[orgapi.CreateOrganizationalUnitRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.ParentID.Require("ParentId", req.ParentID); err != nil {
		return err
	}
	if err = orgapi.OrganizationalUnitName.Require("Name", req.Name); err != nil {
		return err
	}
	tags, err := tagsOf(req.Tags)
	if err != nil {
		return err
	}

	out, err := m.store.CreateOrganizationalUnit(ctx, contracts.CreateOrganizationalUnitInput{
		ParentID: req.ParentID,
		Name:     req.Name,
		Tags:     tags,
	})
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, wireOU(out))
}

func (m *Module) describeOrganizationalUnit(ctx gas.Context) error {
	req, err := decode[orgapi.OrganizationalUnitIDRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.OrganizationalUnitID.Require("OrganizationalUnitId",
		req.OrganizationalUnitID); err != nil {
		return err
	}

	out, err := m.store.DescribeOrganizationalUnit(ctx, req.OrganizationalUnitID)
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, wireOU(out))
}

func (m *Module) updateOrganizationalUnit(ctx gas.Context) error {
	req, err := decode[orgapi.UpdateOrganizationalUnitRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.OrganizationalUnitID.Require("OrganizationalUnitId",
		req.OrganizationalUnitID); err != nil {
		return err
	}
	if req.Name != nil {
		if err = orgapi.OrganizationalUnitName.Check("Name", *req.Name); err != nil {
			return err
		}
	}

	out, err := m.store.UpdateOrganizationalUnit(ctx, contracts.UpdateOrganizationalUnitInput{
		ID:   req.OrganizationalUnitID,
		Name: req.Name,
	})
	if err != nil {
		return err
	}
	return orgapi.Write(ctx, wireOU(out))
}

func (m *Module) deleteOrganizationalUnit(ctx gas.Context) error {
	req, err := decode[orgapi.OrganizationalUnitIDRequest](ctx)
	if err != nil {
		return err
	}
	if err = orgapi.OrganizationalUnitID.Require("OrganizationalUnitId",
		req.OrganizationalUnitID); err != nil {
		return err
	}

	if err = m.store.DeleteOrganizationalUnit(ctx, req.OrganizationalUnitID); err != nil {
		return err
	}
	return orgapi.Write(ctx, orgapi.EmptyResponse{})
}

func (m *Module) listOrganizationalUnitsForParent(ctx gas.Context) error {
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

	out, err := m.store.ListOrganizationalUnitsForParent(ctx, req.ParentID, page)
	if err != nil {
		return err
	}
	resp := orgapi.ListOrganizationalUnitsResponse{
		NextToken:           out.NextToken,
		OrganizationalUnits: make([]orgapi.OrganizationalUnit, 0, len(out.Items)),
	}
	for i := range out.Items {
		resp.OrganizationalUnits = append(resp.OrganizationalUnits,
			wireOU(&out.Items[i]).OrganizationalUnit)
	}
	return orgapi.Write(ctx, resp)
}

func wireOU(ou *contracts.OrganizationalUnit) orgapi.OrganizationalUnitResponse {
	return orgapi.OrganizationalUnitResponse{OrganizationalUnit: orgapi.OrganizationalUnit{
		Arn:  ou.ARN,
		ID:   ou.ID,
		Name: ou.Name,
		Path: ou.Path,
	}}
}

func wireNodes(nodes []contracts.Node) []orgapi.Node {
	out := make([]orgapi.Node, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, orgapi.Node{ID: n.ID, Type: n.Type})
	}
	return out
}
