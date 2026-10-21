package hankoadk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// DelegatedPosition exposes only the approved application's effective roles.
type DelegatedPosition struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	ParentID string   `json:"parent_id,omitempty"`
	Roles    []string `json:"roles"`
}

type OrganizationDelegationSpec struct {
	RootPositionID   string   `json:"root_position_id"`
	ApplicationID    string   `json:"application_id"`
	AllowedRoles     []string `json:"allowed_roles"`
	WriteEnabled     bool     `json:"write_enabled"`
	ExpiresInSeconds int64    `json:"expires_in_seconds"`
}

type OrganizationDelegationMetadata struct {
	ID           string   `json:"id"`
	Sub          string   `json:"sub"`
	Kind         string   `json:"kind"`
	RealmID      string   `json:"realm_id"`
	Scopes       []string `json:"scopes"`
	CreatedAt    string   `json:"created_at"`
	ExpiresAt    string   `json:"expires_at"`
	Organization struct {
		RootPositionID string   `json:"root_position_id"`
		RootGroupID    string   `json:"root_group_id"`
		ApplicationID  string   `json:"application_id"`
		AllowedRoles   []string `json:"allowed_roles"`
	} `json:"organization"`
}

type OrganizationDelegation struct {
	Token    string                         `json:"token"`
	Metadata OrganizationDelegationMetadata `json:"metadata"`
}

// DelegatedOrganizationClient uses a dedicated organization credential on a
// backend. It exposes membership operations only, bound at construction to one
// root and application. The API independently verifies live provider authority.
type DelegatedOrganizationClient struct {
	client *OrganizationClient
	path   string
}

func NewDelegatedOrganizationClient(apiURL, realm, applicationID, rootPositionID string, options OrganizationClientOptions) (*DelegatedOrganizationClient, error) {
	for _, id := range []string{realm, applicationID, rootPositionID} {
		if err := validateDelegatedIdentifier(id); err != nil {
			return nil, err
		}
	}
	client, err := NewOrganizationClient(apiURL, options)
	if err != nil {
		return nil, err
	}
	return &DelegatedOrganizationClient{client: client, path: "/api/v1/organization-admin/realms/" + url.PathEscape(realm) + "/applications/" + url.PathEscape(applicationID) + "/roots/" + url.PathEscape(rootPositionID) + "/positions"}, nil
}

func (c *DelegatedOrganizationClient) ListPositions(ctx context.Context) ([]DelegatedPosition, error) {
	var response struct {
		Positions []DelegatedPosition `json:"positions"`
	}
	if err := c.client.request(ctx, http.MethodGet, c.path, nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if response.Positions == nil {
		return nil, fmt.Errorf("invalid Hanko delegated positions response")
	}
	return response.Positions, nil
}

func (c *DelegatedOrganizationClient) ListMembers(ctx context.Context, positionID string) ([]PositionMember, error) {
	if err := validateDelegatedIdentifier(positionID); err != nil {
		return nil, err
	}
	var response struct {
		Members []PositionMember `json:"members"`
	}
	if err := c.client.request(ctx, http.MethodGet, c.path+"/"+url.PathEscape(positionID)+"/members", nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if response.Members == nil {
		return nil, fmt.Errorf("invalid Hanko members response")
	}
	return response.Members, nil
}

func (c *DelegatedOrganizationClient) AssignMember(ctx context.Context, positionID, userID string) error {
	for _, id := range []string{positionID, userID} {
		if err := validateDelegatedIdentifier(id); err != nil {
			return err
		}
	}
	return c.client.request(ctx, http.MethodPost, c.path+"/"+url.PathEscape(positionID)+"/members", map[string]string{"user_id": userID}, nil, http.StatusNoContent)
}

func (c *DelegatedOrganizationClient) RemoveMember(ctx context.Context, positionID, userID string) error {
	for _, id := range []string{positionID, userID} {
		if err := validateDelegatedIdentifier(id); err != nil {
			return err
		}
	}
	return c.client.request(ctx, http.MethodDelete, c.path+"/"+url.PathEscape(positionID)+"/members/"+url.PathEscape(userID), nil, nil, http.StatusNoContent)
}

func validateDelegatedIdentifier(value string) error {
	if len(value) > 255 || strings.ContainsAny(value, "%?#") || strings.ContainsFunc(value, unicode.IsSpace) {
		return fmt.Errorf("invalid Hanko API path identifier")
	}
	return validateAPIIdentifier(value)
}

// CreateOrganizationDelegation requires an administrator session. Store the
// returned credential only in the product backend's secret mechanism.
func (c *IAMClient) CreateOrganizationDelegation(ctx context.Context, realm string, spec OrganizationDelegationSpec) (OrganizationDelegation, error) {
	var response OrganizationDelegation
	err := c.request(ctx, http.MethodPost, realmPath(realm)+"/org/delegations", spec, &response, http.StatusCreated)
	return response, err
}

func (c *IAMClient) ListOrganizationDelegations(ctx context.Context, realm string) ([]OrganizationDelegationMetadata, error) {
	var response struct {
		Delegations []OrganizationDelegationMetadata `json:"delegations"`
	}
	if err := c.request(ctx, http.MethodGet, realmPath(realm)+"/org/delegations", nil, &response, http.StatusOK); err != nil {
		return nil, err
	}
	if response.Delegations == nil {
		return nil, fmt.Errorf("invalid Hanko delegations response")
	}
	return response.Delegations, nil
}

func (c *IAMClient) RevokeOrganizationDelegation(ctx context.Context, realm, id string) error {
	return c.request(ctx, http.MethodDelete, realmPath(realm)+"/org/delegations/"+url.PathEscape(id), nil, nil, http.StatusNoContent)
}
