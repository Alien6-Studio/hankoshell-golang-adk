package hankoadk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// ApplicationMembership describes the current user's application membership.
type ApplicationMembership struct {
	Subject       string `json:"subject"`
	Organization  string `json:"organization"`
	Role          string `json:"role"`
	Administrator bool   `json:"administrator"`
}

type ApplicationMember struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Manageable bool   `json:"manageable,omitempty"`
}

// ApplicationMembers includes the roles allowed by the server's product policy.
type ApplicationMembers struct {
	Members       []ApplicationMember `json:"members"`
	Roles         []string            `json:"roles"`
	Administrator bool                `json:"administrator"`
}

type ApplicationInvitation struct {
	ID           string `json:"id"`
	Organization string `json:"organization"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	ExpiresAt    string `json:"expires_at"`
}

type ApplicationInvitationSpec struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// ApplicationOrganizationClient uses the current user's session. Hanko checks
// membership, organization administration and allowed roles on every request.
// Do not supply a platform administrator or delegated backend credential.
type ApplicationOrganizationClient struct {
	client *OrganizationClient
	path   string
}

var applicationIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,254}$`)
var invitationEmailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func validateApplicationIdentifiers(values ...string) error {
	for _, value := range values {
		if !applicationIdentifierPattern.MatchString(value) {
			return fmt.Errorf("invalid Hanko API path identifier")
		}
	}
	return nil
}

func NewApplicationOrganizationClient(apiURL, realm, applicationID string, options OrganizationClientOptions) (*ApplicationOrganizationClient, error) {
	if err := validateApplicationIdentifiers(realm, applicationID); err != nil {
		return nil, err
	}
	client, err := NewOrganizationClient(apiURL, options)
	if err != nil {
		return nil, err
	}
	return &ApplicationOrganizationClient{
		client: client,
		path:   "/api/v1/application-organizations/realms/" + url.PathEscape(realm) + "/applications/" + url.PathEscape(applicationID),
	}, nil
}

func (c *ApplicationOrganizationClient) Membership(ctx context.Context) (ApplicationMembership, error) {
	var response ApplicationMembership
	err := c.client.request(ctx, http.MethodGet, c.path+"/membership", nil, &response, http.StatusOK)
	return response, err
}

func (c *ApplicationOrganizationClient) Members(ctx context.Context, organization string) (ApplicationMembers, error) {
	if err := validateApplicationIdentifiers(organization); err != nil {
		return ApplicationMembers{}, err
	}
	var response ApplicationMembers
	err := c.client.request(ctx, http.MethodGet, c.organizationPath(organization)+"/members", nil, &response, http.StatusOK)
	return response, err
}

func (c *ApplicationOrganizationClient) ChangeRole(ctx context.Context, organization, user, role string) error {
	if err := validateApplicationIdentifiers(organization, user, role); err != nil {
		return err
	}
	return c.client.request(ctx, http.MethodPatch, c.organizationPath(organization)+"/members/"+url.PathEscape(user), map[string]string{"role": role}, nil, http.StatusNoContent)
}

func (c *ApplicationOrganizationClient) Invite(ctx context.Context, organization string, spec ApplicationInvitationSpec) (ApplicationInvitation, error) {
	if err := validateApplicationIdentifiers(organization, spec.Role); err != nil {
		return ApplicationInvitation{}, err
	}
	if len(spec.Email) > 320 || strings.ContainsFunc(spec.Email, unicode.IsSpace) || !invitationEmailPattern.MatchString(spec.Email) {
		return ApplicationInvitation{}, fmt.Errorf("invalid invitation email")
	}
	var response ApplicationInvitation
	err := c.client.request(ctx, http.MethodPost, c.organizationPath(organization)+"/invitations", spec, &response, http.StatusCreated)
	return response, err
}

func (c *ApplicationOrganizationClient) Invitation(ctx context.Context, organization, invitation string) (ApplicationInvitation, error) {
	if err := validateApplicationIdentifiers(organization, invitation); err != nil {
		return ApplicationInvitation{}, err
	}
	var response ApplicationInvitation
	err := c.client.request(ctx, http.MethodGet, c.invitationPath(organization, invitation), nil, &response, http.StatusOK)
	return response, err
}

// Accept uses the invitee's current session; Hanko verifies the invitation recipient.
func (c *ApplicationOrganizationClient) Accept(ctx context.Context, organization, invitation string) error {
	if err := validateApplicationIdentifiers(organization, invitation); err != nil {
		return err
	}
	return c.client.request(ctx, http.MethodPost, c.invitationPath(organization, invitation)+"/accept", struct{}{}, nil, http.StatusNoContent)
}

func (c *ApplicationOrganizationClient) Revoke(ctx context.Context, organization, invitation string) error {
	if err := validateApplicationIdentifiers(organization, invitation); err != nil {
		return err
	}
	return c.client.request(ctx, http.MethodDelete, c.invitationPath(organization, invitation), nil, nil, http.StatusNoContent)
}

func (c *ApplicationOrganizationClient) organizationPath(organization string) string {
	return c.path + "/" + url.PathEscape(organization)
}

func (c *ApplicationOrganizationClient) invitationPath(organization, invitation string) string {
	return c.organizationPath(organization) + "/invitations/" + url.PathEscape(invitation)
}
