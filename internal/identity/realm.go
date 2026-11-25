package identity

// MSAL refreshes cached tokens with less than five minutes remaining.
// Ten minutes leaves a short window for cached ARM access during IdP failover.
const tenantAccessTokenSeconds = 600

type keycloakMapper struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Kind     string            `json:"protocolMapper"`
	Config   map[string]string `json:"config"`
}

type keycloakScope struct {
	Name       string            `json:"name"`
	Protocol   string            `json:"protocol"`
	Attributes map[string]string `json:"attributes"`
	Mappers    []keycloakMapper  `json:"protocolMappers,omitempty"`
}

func realmScope(name string, visible string, mappers ...keycloakMapper) keycloakScope {
	return keycloakScope{name, "openid-connect", map[string]string{"include.in.token.scope": visible}, mappers}
}

func mapper(name, kind string, config map[string]string) keycloakMapper {
	return keycloakMapper{name, "openid-connect", "oidc-" + kind + "-mapper", config}
}

func tenantRealm(r TenantReservation, input onboardingRequest, cloud CloudEndpoints, exchange string) map[string]any {
	audience := func(name, key, value string) keycloakMapper {
		return mapper(name, "audience", map[string]string{key: value, "access.token.claim": "true", "id.token.claim": "false"})
	}
	profile := realmScope("profile", "true", mapper("preferred-username", "usermodel-property", map[string]string{
		"user.attribute": "username", "claim.name": "preferred_username", "id.token.claim": "true",
		"access.token.claim": "true", "jsonType.label": "String",
	}), mapper("ocean-tenant", "hardcoded-claim", map[string]string{
		"claim.name": "tid", "claim.value": r.TenantID, "id.token.claim": "true", "access.token.claim": "true",
		"jsonType.label": "String",
	}))
	armScope := cloud.ResourceManager + "/.default"
	graphScope := cloud.MicrosoftGraph + "/.default"
	scopes := []keycloakScope{
		realmScope("basic", "false", mapper("subject", "sub", map[string]string{"access.token.claim": "true"})),
		profile,
		realmScope("offline_access", "true"),
		realmScope("ocean-grant", "false", audience("token-exchange", "included.client.audience", exchangeClient)),
		realmScope(armScope, "true", audience("arm", "included.custom.audience", cloud.ResourceManager)),
		realmScope(graphScope, "true", audience("graph", "included.custom.audience", cloud.MicrosoftGraph)),
	}
	return map[string]any{
		"realm": r.TenantID, "displayName": input.DisplayName, "enabled": true, "sslRequired": "all",
		"attributes":          map[string]string{"oceanRegistration": r.SubscriptionID},
		"accessTokenLifespan": tenantAccessTokenSeconds, "offlineSessionMaxLifespanEnabled": true,
		"offlineSessionMaxLifespan": 28800, "offlineSessionIdleTimeout": 3600,
		"roles":         map[string]any{"realm": []map[string]string{{"name": "offline_access"}}},
		"scopeMappings": []map[string]any{{"clientScope": "offline_access", "roles": []string{"offline_access"}}},
		"clientScopes":  scopes,
		"clients": []map[string]any{
			{
				"clientId": cliClientID, "enabled": true, "publicClient": true, "protocol": "openid-connect",
				"fullScopeAllowed": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
				"attributes":          map[string]string{"oauth2.device.authorization.grant.enabled": "true"},
				"defaultClientScopes": []string{"profile", "basic", "ocean-grant"}, "optionalClientScopes": []string{"offline_access"},
			},
			{
				"clientId": exchangeClient, "enabled": true, "publicClient": false, "protocol": "openid-connect",
				"fullScopeAllowed": false, "standardFlowEnabled": false, "directAccessGrantsEnabled": false,
				"clientAuthenticatorType": "client-secret", "serviceAccountsEnabled": false, "secret": exchange,
				"attributes":          map[string]string{"standard.token.exchange.enabled": "true"},
				"defaultClientScopes": []string{"profile", "basic"}, "optionalClientScopes": []string{armScope, graphScope},
			},
		},
		"users": []map[string]any{{
			"id": r.Administrator, "enabled": true, "username": input.AdministratorUPN,
			"firstName": "Tenant", "lastName": "Administrator", "email": input.AdministratorUPN,
			"emailVerified": false, "realmRoles": []string{"offline_access"},
			"credentials": []map[string]any{{"type": "password", "value": input.AdministratorPassword, "temporary": false}},
		}},
	}
}
