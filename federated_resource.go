package mycelium

import "github.com/google/uuid"

// FederatedResource is a grant the subject holds on a peer instance. On the
// wire it is a flat licensed resource object plus "issuer", the instance id of
// the peer that asserted it. It is carried apart from LicensedResources so the
// default filters never take a foreign grant for a local one.
type FederatedResource struct {
	Issuer uuid.UUID `json:"issuer"`
	LicensedResource
}

// WithFederated adds every federated grant (issuer dropped) to the local
// licensed resources.
func (p Profile) WithFederated() Profile {
	var grants []LicensedResource
	if p.LicensedResources != nil {
		grants = append(grants, p.LicensedResources.ToLicensesVector()...)
	}
	for _, r := range p.FederatedResources {
		grants = append(grants, r.LicensedResource)
	}
	np := p.updateState("withFederated", "true")
	np.LicensedResources = recordsOrNil(grants)
	return np
}

// FromIssuer keeps only the federated grants asserted by issuer, dropping the
// local licensed resources.
func (p Profile) FromIssuer(issuer uuid.UUID) Profile {
	var grants []LicensedResource
	for _, r := range p.FederatedResources {
		if r.Issuer == issuer {
			grants = append(grants, r.LicensedResource)
		}
	}
	np := p.updateState("issuer", issuer.String())
	np.LicensedResources = recordsOrNil(grants)
	return np
}

func recordsOrNil(grants []LicensedResource) *LicensedResources {
	if len(grants) == 0 {
		return nil
	}
	return &LicensedResources{Records: grants}
}
