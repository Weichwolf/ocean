package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

const (
	keycloakUserStorageType = "org.keycloak.storage.UserStorageProvider"
	keycloakLDAPMapperType  = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
	managedLDAPReader       = "ocean-sso-reader"
	managedLDAPObjectID     = "oceanDirectoryObjectId"
)

type keycloakComponent struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	ParentID     string              `json:"parentId"`
	ProviderType string              `json:"providerType"`
	ProviderID   string              `json:"providerId"`
	Config       map[string][]string `json:"config"`
}

type keycloakDirectoryFederation struct {
	ProviderID  string
	GroupMapper string
	GroupPath   string
}

// ensureDirectoryFederation uses the two trusted connector addresses for an
// established tenant directory. The bind account is outside the workforce OU.
func (k keycloakAdmin) ensureDirectoryFederation(ctx context.Context, tenant TenantReservation, directory ManagedDirectory,
	connectors [2]string, bindSecret string) (keycloakDirectoryFederation, error) {
	var federation keycloakDirectoryFederation
	if !directory.Valid(tenant) || directory.ProvisionedAt.IsZero() || connectors[0] == connectors[1] ||
		!validLDAPSConnector(connectors[0]) || !validLDAPSConnector(connectors[1]) || len(bindSecret) < 24 {
		return federation, errors.New("a provisioned tenant directory with two LDAPS connectors and a reader credential is required")
	}
	realmID, err := k.federationRealm(ctx, tenant)
	if err != nil {
		return federation, err
	}
	dns := directory.Spec.DNSName
	baseDN := "DC=" + strings.ReplaceAll(dns, ".", ",DC=")
	provider := keycloakComponent{ID: directory.ID, Name: "Ocean Samba AD " + directory.ID, ParentID: realmID,
		ProviderType: keycloakUserStorageType, ProviderID: "ldap", Config: componentConfig(map[string]string{
			"enabled": "true", "vendor": "ad", "editMode": "READ_ONLY", "importEnabled": "true",
			"syncRegistrations": "false", "cachePolicy": "NO_CACHE", "priority": "0",
			"fullSyncPeriod": "-1", "changedSyncPeriod": "-1",
			"connectionUrl": strings.Join(connectors[:], " "), "useTruststoreSpi": "always",
			"startTls": "false", "authType": "simple", "bindDn": managedLDAPReader + "@" + dns,
			"bindCredential": bindSecret, "connectionTimeout": "2000", "readTimeout": "4000",
			"connectionPooling": "false", "referral": "ignore", "pagination": "true",
			"usersDn": "OU=Ocean Workforce Users," + baseDN, "searchScope": "1",
			"usernameLDAPAttribute": "userPrincipalName", "rdnLDAPAttribute": "cn", "uuidLDAPAttribute": "objectGUID",
			"userObjectClasses":      "person, organizationalPerson, user",
			"customUserSearchFilter": "(&(objectCategory=person)(!(isCriticalSystemObject=TRUE))(!(adminCount=1))(userPrincipalName=*@" + dns + "))",
			"trustEmail":             "false", "allowKerberosAuthentication": "false", "useKerberosForPasswordAuthentication": "false",
		})}
	if err := k.ensureDirectoryComponent(ctx, tenant.TenantID, provider); err != nil {
		return federation, err
	}
	if err := k.checkDirectoryAccountMapper(ctx, tenant.TenantID, provider.ID); err != nil {
		return federation, err
	}
	guidMapper := keycloakComponent{ID: directoryMapperID(directory.ID, "objectGUID"), Name: "Ocean workforce object GUID",
		ParentID: provider.ID, ProviderType: keycloakLDAPMapperType, ProviderID: "user-attribute-ldap-mapper",
		Config: componentConfig(map[string]string{
			"user.model.attribute": managedLDAPObjectID, "ldap.attribute": "objectGUID", "read.only": "true",
			"always.read.value.from.ldap": "true", "is.mandatory.in.ldap": "true",
			"is.binary.attribute": "true", "binary.attribute.decoder": "uuid",
		})}
	if err := k.ensureDirectoryComponent(ctx, tenant.TenantID, guidMapper); err != nil {
		return federation, err
	}
	groupName := "ocean-samba-" + directory.ID
	if _, err := k.ensureDirectoryGroupRoot(ctx, tenant.TenantID, groupName); err != nil {
		return federation, err
	}
	groupMapper := keycloakComponent{ID: directoryMapperID(directory.ID, "groups"), Name: "Ocean workforce security groups",
		ParentID: provider.ID, ProviderType: keycloakLDAPMapperType, ProviderID: "group-ldap-mapper",
		Config: directoryGroupMapperConfig(baseDN, groupName, "")}
	if err := k.ensureDirectoryComponent(ctx, tenant.TenantID, groupMapper); err != nil {
		return federation, err
	}
	return keycloakDirectoryFederation{ProviderID: provider.ID, GroupMapper: groupMapper.ID, GroupPath: "/" + groupName}, nil
}

func directoryGroupMapperConfig(baseDN, groupName, additionalFilter string) map[string][]string {
	return componentConfig(map[string]string{
		"groups.dn": "OU=Ocean Workforce Groups," + baseDN, "groups.path": "/" + groupName,
		"group.name.ldap.attribute": "cn", "group.object.classes": "group",
		"groups.ldap.filter":        "(&(!(isCriticalSystemObject=TRUE))(!(adminCount=1))(groupType=-2147483646)" + additionalFilter + ")",
		"membership.ldap.attribute": "member", "membership.attribute.type": "DN", "mode": "LDAP_ONLY",
		"user.roles.retrieve.strategy": "LOAD_GROUPS_BY_MEMBER_ATTRIBUTE", "preserve.group.inheritance": "false",
		"ignore.missing.groups": "false", "mapped.group.attributes": "objectGUID", "decode.group.uuid.attribute": "true",
	})
}

func validLDAPSConnector(raw string) bool {
	if len(raw) > 255 || strings.ContainsAny(raw, "%,\\") || strings.ContainsFunc(raw, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || r > unicode.MaxASCII
	}) {
		return false
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "ldaps" || endpoint.Hostname() == "" || endpoint.User != nil || raw != "ldaps://"+endpoint.Host {
		return false
	}
	port, err := strconv.ParseUint(endpoint.Port(), 10, 16)
	return err == nil && port != 0
}

func componentConfig(values map[string]string) map[string][]string {
	config := make(map[string][]string, len(values))
	for key, value := range values {
		config[key] = []string{value}
	}
	return config
}

func directoryMapperID(directory, mapper string) string {
	digest := sha256.Sum256([]byte("ocean-directory-ldap\x00" + directory + "\x00" + mapper))
	digest[6] = (digest[6] & 0x0f) | 0x80
	digest[8] = (digest[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func (k keycloakAdmin) federationRealm(ctx context.Context, tenant TenantReservation) (string, error) {
	var realm struct {
		ID         string            `json:"id"`
		Realm      string            `json:"realm"`
		Attributes map[string]string `json:"attributes"`
	}
	status, err := k.directoryRequest(ctx, tenant.TenantID, http.MethodGet, "", nil, &realm)
	if err != nil || status != http.StatusOK || realm.Realm != tenant.TenantID || !tenantID.MatchString(realm.ID) ||
		realm.Attributes["oceanRegistration"] != tenant.SubscriptionID {
		return "", errors.New("unable to confirm the tenant realm for directory federation")
	}
	return realm.ID, nil
}

func (k keycloakAdmin) ensureDirectoryComponent(ctx context.Context, tenant string, wanted keycloakComponent) error {
	var actual keycloakComponent
	path := "/components/" + wanted.ID
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, path, nil, &actual)
	if err == nil && status == http.StatusNotFound {
		if wanted.ProviderType == keycloakUserStorageType && wanted.ProviderID == "ldap" {
			if err := k.verifyDirectoryBinds(ctx, tenant, wanted.Config); err != nil {
				return err
			}
		}
		// Component IDs are stable across API replicas. Confirm persisted state
		// after a create, including when its response is lost.
		_, _ = k.directoryRequest(ctx, tenant, http.MethodPost, "/components", wanted, nil)
		status, err = k.directoryRequest(ctx, tenant, http.MethodGet, path, nil, &actual)
	}
	if err != nil || status != http.StatusOK || actual.ID != wanted.ID || actual.Name != wanted.Name ||
		actual.ParentID != wanted.ParentID || actual.ProviderType != wanted.ProviderType || actual.ProviderID != wanted.ProviderID {
		return fmt.Errorf("unable to confirm Keycloak component %q", wanted.Name)
	}
	for key, value := range wanted.Config {
		if key == "bindCredential" {
			// Keycloak masks component credentials on reads.
			if len(actual.Config[key]) == 1 && actual.Config[key][0] != "" {
				continue
			}
		} else if slices.Equal(actual.Config[key], value) {
			continue
		}
		return fmt.Errorf("unexpected Keycloak directory setting %q on %q", key, wanted.Name)
	}
	return nil
}

func (k keycloakAdmin) verifyDirectoryBinds(ctx context.Context, tenant string, config map[string][]string) error {
	for index, target := range strings.Fields(config["connectionUrl"][0]) {
		input := map[string]any{"action": "testAuthentication", "authType": "simple", "connectionUrl": target,
			"startTls": false, "useTruststoreSpi": "always", "connectionTimeout": "2000",
			"bindDn": config["bindDn"][0], "bindCredential": config["bindCredential"][0]}
		status, err := k.directoryRequest(ctx, tenant, http.MethodPost, "/testLDAPConnection", input, nil)
		if err != nil || status != http.StatusNoContent {
			return fmt.Errorf("unable to verify the LDAPS reader bind to directory connector %d", index+1)
		}
	}
	return nil
}

func (k keycloakAdmin) checkDirectoryAccountMapper(ctx context.Context, tenant, provider string) error {
	query := url.Values{"parent": {provider}, "type": {keycloakLDAPMapperType}, "providerId": {"msad-user-account-control-mapper"}}
	var components []keycloakComponent
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, "/components?"+query.Encode(), nil, &components)
	if err != nil || status != http.StatusOK || len(components) != 1 || components[0].ParentID != provider ||
		!slices.Equal(components[0].Config["always.read.enabled.value.from.ldap"], []string{"true"}) {
		return errors.New("unable to confirm live AD account status mapping")
	}
	return nil
}

func (k keycloakAdmin) ensureDirectoryGroupRoot(ctx context.Context, tenant, name string) (string, error) {
	var group struct {
		ID         string              `json:"id"`
		Path       string              `json:"path"`
		Attributes map[string][]string `json:"attributes"`
	}
	path := "/group-by-path/" + name
	status, err := k.directoryRequest(ctx, tenant, http.MethodGet, path, nil, &group)
	if err == nil && status == http.StatusNotFound {
		_, _ = k.directoryRequest(ctx, tenant, http.MethodPost, "/groups", map[string]any{
			"name": name, "attributes": componentConfig(map[string]string{"oceanLDAPBinding": name}),
		}, nil)
		status, err = k.directoryRequest(ctx, tenant, http.MethodGet, path, nil, &group)
	}
	if err != nil || status != http.StatusOK || !tenantID.MatchString(group.ID) || group.Path != "/"+name ||
		!slices.Equal(group.Attributes["oceanLDAPBinding"], []string{name}) {
		return "", errors.New("unable to confirm the managed Keycloak group root")
	}
	return group.ID, nil
}
