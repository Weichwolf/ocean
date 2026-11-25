package smb

import (
	"net/netip"
	"strings"
	"testing"
)

func TestMemberScopeAndAccessConfiguration(t *testing.T) {
	const domain = "S-1-5-21-157-201-942"
	member := Member{DNSDomain: "ad.ocean.test", NetBIOSDomain: "OCEANLAB", DomainSID: domain, ServerName: "FILES01",
		Address: netip.MustParseAddr("10.232.1.14"), Shares: []Share{{Name: "company-files", VolumeID: "vol-2a660fd1-3fbf-4b9a-97c0-cb93eb96ee33",
			ReaderSIDs: []string{domain + "-1401"}, WriterSIDs: []string{domain + "-1402"}}}}
	if err := member.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"interfaces = 10.232.1.14", "bind interfaces only = yes", "gensec:ntlmssp = no",
		"server smb encrypt = required", "idmap config OCEANLAB : backend = rid", "valid users = " + domain + "-1401 " + domain + "-1402",
		"read only = yes", "write list = " + domain + "-1402"} {
		if !strings.Contains(string(configuration(member)), expected) {
			t.Errorf("configuration omitted %q", expected)
		}
	}
	if id, ok := groupID(domain, domain+"-1402"); !ok || id != 1001402 {
		t.Fatalf("unexpected stable RID mapping %d, %v", id, ok)
	}
	tests := map[string]func(*Member){
		"public bind":             func(m *Member) { m.Address = netip.MustParseAddr("192.0.2.8") },
		"configuration injection": func(m *Member) { m.DNSDomain = "ad.ocean.test\ninclude = /tmp/other" },
		"foreign group":           func(m *Member) { m.Shares[0].WriterSIDs = []string{"S-1-5-21-99-201-942-1402"} },
		"reserved section":        func(m *Member) { m.Shares[0].Name = "global" },
		"volume escape":           func(m *Member) { m.Shares[0].VolumeID = "vol-../etc" },
		"duplicate grant":         func(m *Member) { m.Shares[0].WriterSIDs = m.Shares[0].ReaderSIDs },
		"duplicate volume":        func(m *Member) { m.Shares = append(m.Shares, m.Shares[0]); m.Shares[1].Name = "other-files" },
		"empty policy":            func(m *Member) { m.Shares[0].ReaderSIDs, m.Shares[0].WriterSIDs = nil, nil },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			changed := member
			changed.Shares = append([]Share(nil), member.Shares...)
			change(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("accepted an unsafe member configuration")
			}
		})
	}
}
