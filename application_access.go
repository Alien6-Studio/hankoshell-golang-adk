package hankoadk

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// AccessDenial is an allowlisted authorization outcome; it contains no claims.
type AccessDenial string

const (
	AccessAudienceMismatch           AccessDenial = "audience_mismatch"
	AccessOrganizationMalformed      AccessDenial = "organization_malformed"
	AccessOrganizationAmbiguous      AccessDenial = "organization_ambiguous"
	AccessApplicationBindingMismatch AccessDenial = "application_binding_mismatch"
	AccessApplicationRolesMissing    AccessDenial = "application_roles_missing"
	AccessApplicationRolesMalformed  AccessDenial = "application_roles_malformed"
	AccessRequiredRoleMissing        AccessDenial = "required_role_missing"
)

// ApplicationAccessError is a safe 403 diagnostic, never an authentication error.
type ApplicationAccessError struct {
	Category AccessDenial `json:"category"`
}

func (e *ApplicationAccessError) Error() string {
	return fmt.Sprintf("Hanko application access denied (%s)", e.Category)
}

// ApplicationOrganization identifies one active context, never a union of tenants.
type ApplicationOrganization struct {
	Alias string
	ID    string
}

// ApplicationAccess contains only roles for the explicitly selected application.
type ApplicationAccess struct {
	Issuer       string
	Subject      string
	Roles        []string
	Organization *ApplicationOrganization
}

// RequireApplicationAccess runs after signature verification. Realm-wide roles
// never substitute for the target application's roles. requiredRoles uses any-of.
func RequireApplicationAccess(principal *Principal, applicationID string, requiredRoles ...string) (*ApplicationAccess, error) {
	return RequireApplicationAccessForClient(principal, applicationID, "", requiredRoles...)
}

// RequireApplicationAccessForClient explicitly binds a sign-in client to an API
// audience when consuming a platform-issued active-organization context.
func RequireApplicationAccessForClient(principal *Principal, applicationID, clientID string, requiredRoles ...string) (*ApplicationAccess, error) {
	deny := func(category AccessDenial) (*ApplicationAccess, error) {
		return nil, &ApplicationAccessError{Category: category}
	}
	if principal == nil || strings.TrimSpace(applicationID) == "" || !slices.Contains(principal.Audiences, applicationID) {
		return deny(AccessAudienceMismatch)
	}
	claims := principal.Claims
	var organization *ApplicationOrganization
	roleClient := applicationID
	var selected map[string]any
	if raw, present := claims["hanko_application_context"]; present {
		if clientID == "" || claims["azp"] != clientID {
			return deny(AccessApplicationBindingMismatch)
		}
		selected, _ = raw.(map[string]any)
		_, nativeContext := claims["organization"]
		org, _ := selected["organization"].(string)
		root, _ := selected["root"].(string)
		role, _ := selected["role"].(string)
		version, validVersion := selected["policy_version"].(float64)
		_, validAdmin := selected["administrator"].(bool)
		path, validPath := selected["node_path"].([]any)
		if selected == nil || nativeContext || selected["subject"] != principal.Subject || !applicationContextID(org) || !applicationContextID(root) || !applicationContextID(role) || !validAdmin || !validVersion || version < 1 || version > 9007199254740991 || version != float64(int64(version)) || !validPath || len(path) == 0 || len(path) > 128 || path[0] != root || path[len(path)-1] != org {
			return deny(AccessOrganizationMalformed)
		}
		for _, item := range path {
			id, ok := item.(string)
			if !ok || !applicationContextID(id) {
				return deny(AccessOrganizationMalformed)
			}
		}
		organization = &ApplicationOrganization{Alias: org, ID: org}
		roleClient = clientID
	} else if raw, present := claims["organization"]; present {
		contexts, ok := raw.(map[string]any)
		if !ok || len(contexts) == 0 {
			return deny(AccessOrganizationMalformed)
		}
		if len(contexts) != 1 {
			return deny(AccessOrganizationAmbiguous)
		}
		for alias, value := range contexts {
			context, ok := value.(map[string]any)
			if !ok || strings.TrimSpace(alias) == "" || utf8.RuneCountInString(alias) > 255 || strings.ContainsAny(alias, "/\\") || hasControl(alias) {
				return deny(AccessOrganizationMalformed)
			}
			claims = context
			organization = &ApplicationOrganization{Alias: alias}
			if id, ok := context["id"].(string); ok && utf8.RuneCountInString(id) <= 255 {
				organization.ID = id
			}
		}
	}
	resources, _ := claims["resource_access"].(map[string]any)
	client, _ := resources[roleClient].(map[string]any)
	raw, present := client["roles"]
	if !present {
		return deny(AccessApplicationRolesMissing)
	}
	var roles []string
	switch values := raw.(type) {
	case []any:
		for _, value := range values {
			role, ok := value.(string)
			if !ok {
				return deny(AccessApplicationRolesMalformed)
			}
			roles = append(roles, role)
		}
	case []string:
		roles = append(roles, values...)
	default:
		return deny(AccessApplicationRolesMalformed)
	}
	if len(roles) > 128 {
		return deny(AccessApplicationRolesMalformed)
	}
	if selected != nil {
		approved, ok := selected["roles"].([]any)
		if !ok || len(approved) != len(roles) {
			return deny(AccessApplicationRolesMalformed)
		}
		for _, value := range approved {
			role, ok := value.(string)
			if !ok || !slices.Contains(roles, role) {
				return deny(AccessApplicationRolesMalformed)
			}
		}
		for _, role := range roles {
			if !slices.Contains(approved, any(role)) {
				return deny(AccessApplicationRolesMalformed)
			}
		}
	}
	unique := make([]string, 0, len(roles))
	for _, role := range roles {
		if role == "" || utf8.RuneCountInString(role) > 1024 || hasControl(role) {
			return deny(AccessApplicationRolesMalformed)
		}
		if !slices.Contains(unique, role) {
			unique = append(unique, role)
		}
	}
	if len(unique) == 0 || (len(requiredRoles) > 0 && !slices.ContainsFunc(requiredRoles, func(role string) bool { return slices.Contains(unique, role) })) {
		return deny(AccessRequiredRoleMissing)
	}
	return &ApplicationAccess{Issuer: principal.Issuer, Subject: principal.Subject, Roles: unique, Organization: organization}, nil
}

func applicationContextID(value string) bool {
	if len(value) == 0 || len(value) > 255 {
		return false
	}
	for index, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if index > 0 && strings.ContainsRune("._:@-", r) {
			continue
		}
		return false
	}
	return true
}

func hasControl(value string) bool {
	return strings.ContainsFunc(value, func(r rune) bool { return r < 32 || r == 127 })
}
