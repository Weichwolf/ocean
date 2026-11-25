package smb

import (
	"slices"
	"strings"
	"testing"
)

func TestEffectiveDirectoryAccessUsesCurrentUserSIDs(t *testing.T) {
	const domain = "S-1-5-21-10-20-30"
	const writer, reader = domain + "-1100", domain + "-1101"
	const nested = domain + "-1102"
	directory := []directoryEntry{
		{sid: writer, dn: "cn=writers"},
		{sid: reader, dn: "cn=readers"},
		{sid: nested, dn: "cn=nested", parents: []string{"cn=writers"}},
		{sid: domain + "-1200", dn: "cn=employee", primaryGroup: "513", parents: []string{"cn=nested"}},
		{sid: domain + "-1201", dn: "cn=reader", primaryGroup: "1101"},
		{sid: domain + "-1202", dn: "cn=unrelated", primaryGroup: "513", parents: []string{"cn=distribution"}},
		{sid: "S-1-5-21-40-50-60-1200", dn: "cn=foreign", primaryGroup: "513", parents: []string{"cn=writers"}},
	}
	member := Member{DomainSID: domain, Shares: []Share{{Name: "work", ReaderSIDs: []string{reader}, WriterSIDs: []string{writer}}}}
	access := effectiveDirectoryAccess(member, directory)["work"]
	if !slices.Equal(access.writers, []string{domain + "-1200"}) || !slices.Equal(access.readers, []string{domain + "-1201"}) {
		t.Fatalf("unexpected effective reader or writer: %+v", access)
	}

	// The user's old PAC might still contain the nested writer SID.
	directory[3].parents = nil
	member.access = effectiveDirectoryAccess(member, directory)
	rendered := string(configuration(member))
	if strings.Contains(rendered, domain+"-1200") || strings.Contains(rendered, "    write list = ") ||
		!strings.Contains(rendered, "    valid users = "+domain+"-1201\n") {
		t.Fatalf("the old writer SID remained in the share authorization")
	}
	member.access = effectiveDirectoryAccess(member, nil)
	if !strings.Contains(string(configuration(member)), "    valid users = "+domain+"-4294967295\n") {
		t.Fatal("a share with no approved users must keep a restrictive admission list")
	}
}

func TestDirectoryEntryParserRejectsIncompleteResults(t *testing.T) {
	for _, input := range []string{
		"Got 2 replies\n\nobjectSid: S-1-5-21-10-20-30-1100\ndistinguishedName: CN=writers\n",
		"Got 1 replies\n\nobjectSid: S-1-5-21-10-20-30-1100\ndistinguishedName: CN=writers\nmemberOf;range=0-1499: CN=groups\n",
		"Got 1 replies\n\nobjectSid: S-1-5-21-10-20-30-1100\nobjectSid: S-1-5-21-10-20-30-1101\ndistinguishedName: CN=writers\n",
	} {
		if _, err := parseDirectoryEntries([]byte(input)); err == nil {
			t.Fatalf("accepted an incomplete directory row: %q", input)
		}
	}
}
