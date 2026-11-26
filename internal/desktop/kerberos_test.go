package desktop

import (
	"strings"
	"testing"
	"time"
)

func TestCIFSCacheContainsOneCurrentPersonalService(t *testing.T) {
	const client = "smbwriter@AD.OCEAN.TEST"
	const service = "cifs/files04.ad.ocean.test@AD.OCEAN.TEST"
	const principal = "Default principal: " + client + "\n"
	const period = "11/26/26 00:01:00  11/26/26 00:06:00  "
	const good = "Ticket cache: FILE:/test\n" + principal + "\nValid starting     Expires            Service principal\n" + period + service + "\n"
	now := time.Date(2026, 11, 26, 0, 2, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, content string
		ok            bool
	}{
		{"personal CIFS", good, true},
		{"another user", strings.Replace(good, principal, "Default principal: another@AD.OCEAN.TEST\n", 1), false},
		{"a TGT", good + period + "krbtgt/AD.OCEAN.TEST@AD.OCEAN.TEST\n", false},
		{"another service", strings.Replace(good, service, "ldap/files04.ad.ocean.test@AD.OCEAN.TEST", 1), false},
		{"second ticket", good + period + service + "\n", false},
		{"expired", strings.Replace(good, "00:06:00", "00:01:59", 1), false},
		{"long lifetime", strings.Replace(good, "00:06:00", "00:06:01", 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCIFSList([]byte(tc.content), client, service, now)
			if (err == nil) != tc.ok {
				t.Fatalf("Kerberos cache validation returned %v, expected acceptance %v", err, tc.ok)
			}
		})
	}
}
