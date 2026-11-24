package identity

import "context"

// RolePrincipalExists checks the assignee in the authenticated tenant directory.
func (c *Compatibility) RolePrincipalExists(ctx context.Context, tenant, subject, kind string) (bool, error) {
	if c.onboarding == nil || !tenantID.MatchString(tenant) || !tenantID.MatchString(subject) {
		return false, nil
	}
	app, _, err := c.onboarding.store.FindApplication(ctx, tenant, "principalId", subject)
	if err != nil || kind == "ServicePrincipal" {
		return app != nil && err == nil, err
	}
	if kind != "User" || app != nil {
		return false, nil
	}
	user, err := c.onboarding.admin.directoryUser(ctx, tenant, subject)
	return user != nil && user.ID == subject && user.Enabled, err
}
