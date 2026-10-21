package hankoadk

import (
	"context"
	"net/http"
	"net/url"
)

// IAMClient adds directory and realm-role management to the organization client.
// Authority is checked server-side. Never hand realm-admin credentials to a
// product as a substitute for organization-scoped delegation.
type IAMClient struct{ *OrganizationClient }

// User is the portable Hanko directory representation.
type User struct {
	ID         string   `json:"id"`
	Username   string   `json:"username"`
	Email      string   `json:"email"`
	FirstName  string   `json:"firstName"`
	LastName   string   `json:"lastName"`
	Enabled    bool     `json:"enabled"`
	RealmRoles []string `json:"realmRoles,omitempty"`
}

// Role is a Hanko realm role, not an application-local role.
type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Composite   bool   `json:"composite"`
}

// RoleSpec declares a realm role through Hanko's operator-backed API.
type RoleSpec struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Composite   bool                `json:"composite,omitempty"`
	Composites  []string            `json:"composites,omitempty"`
	Attributes  map[string][]string `json:"attributes,omitempty"`
}

// RolePatch changes selected role attributes. Pointers preserve explicit false/empty values.
type RolePatch struct {
	Description *string             `json:"description,omitempty"`
	Composite   *bool               `json:"composite,omitempty"`
	Composites  []string            `json:"composites,omitzero"`
	Attributes  map[string][]string `json:"attributes,omitzero"`
}

// NewIAMClient builds a server-side client using short-lived caller tokens.
func NewIAMClient(apiURL string, options OrganizationClientOptions) (*IAMClient, error) {
	client, err := NewOrganizationClient(apiURL, options)
	if err != nil {
		return nil, err
	}
	return &IAMClient{client}, nil
}

// ListUsers reads the users envelope returned by Hanko.
func (c *IAMClient) ListUsers(ctx context.Context, realm string) ([]User, error) {
	var response struct {
		Users []User `json:"users"`
	}
	err := c.request(ctx, http.MethodGet, realmPath(realm)+"/users", nil, &response, http.StatusOK)
	if response.Users == nil {
		response.Users = []User{}
	}
	return response.Users, err
}

// GetUser reads one directory user.
func (c *IAMClient) GetUser(ctx context.Context, realm, userID string) (User, error) {
	var user User
	err := c.request(ctx, http.MethodGet, userPath(realm, userID), nil, &user, http.StatusOK)
	return user, err
}

// ListRoles returns the realm role catalogue.
func (c *IAMClient) ListRoles(ctx context.Context, realm string) ([]Role, error) {
	var response struct {
		Roles []Role `json:"roles"`
	}
	err := c.request(ctx, http.MethodGet, realmPath(realm)+"/roles", nil, &response, http.StatusOK)
	if response.Roles == nil {
		response.Roles = []Role{}
	}
	return response.Roles, err
}

// CreateRole declares a realm role.
func (c *IAMClient) CreateRole(ctx context.Context, realm string, spec RoleSpec) (Role, error) {
	var role Role
	err := c.request(ctx, http.MethodPost, realmPath(realm)+"/roles", spec, &role, http.StatusCreated)
	return role, err
}

// UpdateRole changes selected realm role fields.
func (c *IAMClient) UpdateRole(ctx context.Context, realm, name string, patch RolePatch) error {
	return c.request(ctx, http.MethodPatch, realmPath(realm)+"/roles/"+url.PathEscape(name), patch, nil, http.StatusNoContent)
}

// DeleteRole removes a realm role declaration.
func (c *IAMClient) DeleteRole(ctx context.Context, realm, name string) error {
	return c.request(ctx, http.MethodDelete, realmPath(realm)+"/roles/"+url.PathEscape(name), nil, nil, http.StatusNoContent)
}

// ListUserRoles returns directly assigned realm roles, excluding inherited roles.
func (c *IAMClient) ListUserRoles(ctx context.Context, realm, userID string) ([]string, error) {
	var response struct {
		Roles []string `json:"roles"`
	}
	err := c.request(ctx, http.MethodGet, userPath(realm, userID)+"/roles", nil, &response, http.StatusOK)
	if response.Roles == nil {
		response.Roles = []string{}
	}
	return response.Roles, err
}

// AssignRole assigns a realm role; protected roles remain subject to API policy.
func (c *IAMClient) AssignRole(ctx context.Context, realm, userID, role string) error {
	if err := validateAPIIdentifier(role); err != nil {
		return err
	}
	return c.request(ctx, http.MethodPost, userPath(realm, userID)+"/roles", map[string]string{"role": role}, nil, http.StatusNoContent)
}

// UnassignRole removes a directly assigned realm role.
func (c *IAMClient) UnassignRole(ctx context.Context, realm, userID, role string) error {
	return c.request(ctx, http.MethodDelete, userPath(realm, userID)+"/roles/"+url.PathEscape(role), nil, nil, http.StatusNoContent)
}

func realmPath(realm string) string { return "/api/v1/realms/" + url.PathEscape(realm) }
func userPath(realm, userID string) string {
	return realmPath(realm) + "/users/" + url.PathEscape(userID)
}
