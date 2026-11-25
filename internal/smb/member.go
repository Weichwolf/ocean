package smb

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Weichwolf/ocean/internal/storage"
)

const (
	MountRoot  = "/srv/ocean-smb/volumes"
	stateRoot  = "/var/lib/ocean-smb"
	domainBase = 1000000
	domainEnd  = 999999999
)

var (
	dnsLabel    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	netbiosName = regexp.MustCompile(`^[A-Z]([A-Z0-9-]{0,13}[A-Z0-9])?$`)
	domainSID   = regexp.MustCompile(`^S-1-5-21(-[0-9]{1,10}){3}$`)
)

// Member binds a dedicated Samba instance to one AD domain and tenant address.
type Member struct {
	DNSDomain     string     `json:"dnsDomain"`
	NetBIOSDomain string     `json:"netbiosDomain"`
	DomainSID     string     `json:"domainSid"`
	ServerName    string     `json:"serverName"`
	Address       netip.Addr `json:"address"`
	Shares        []Share    `json:"shares"`
}

// Share grants admission and write access to native AD security group SIDs.
// Each share occupies its own encrypted filesystem. QuotaMiB adds a project
// quota when the storage allocation reserves room for filesystem overhead.
type Share struct {
	Name       string   `json:"name"`
	VolumeID   string   `json:"volumeId"`
	QuotaMiB   int      `json:"quotaMiB,omitempty"`
	ReaderSIDs []string `json:"readerSids,omitempty"`
	WriterSIDs []string `json:"writerSids,omitempty"`
}

func (m Member) Validate() error {
	labels := strings.Split(m.DNSDomain, ".")
	if len(labels) < 2 || len(m.DNSDomain) > 253 || !netbiosName.MatchString(m.NetBIOSDomain) ||
		!netbiosName.MatchString(m.ServerName) || m.ServerName == m.NetBIOSDomain || !validDomainSID(m.DomainSID) ||
		!m.Address.Is4() || !m.Address.IsPrivate() {
		return errors.New("invalid Samba member domain, identity or private IPv4 address")
	}
	for _, label := range labels {
		if !dnsLabel.MatchString(label) {
			return errors.New("invalid member DNS domain")
		}
	}
	names, volumes := make(map[string]bool), make(map[string]bool)
	for _, share := range m.Shares {
		if !ValidName(share.Name) ||
			!storage.ValidID(share.VolumeID) || !strings.HasPrefix(share.VolumeID, "vol-") || names[share.Name] || volumes[share.VolumeID] {
			return errors.New("invalid or duplicate Samba share name or volume")
		}
		if share.QuotaMiB < 0 || share.QuotaMiB > 16*1024 {
			return errors.New("the Samba share quota must be between zero and 16 GiB")
		}
		names[share.Name], volumes[share.VolumeID] = true, true
		if len(share.ReaderSIDs)+len(share.WriterSIDs) == 0 {
			return errors.New("a Samba share requires at least one explicit group grant")
		}
		seen := make(map[string]bool)
		for _, sid := range slices.Concat(share.ReaderSIDs, share.WriterSIDs) {
			if _, ok := groupID(m.DomainSID, sid); !ok || seen[sid] {
				return errors.New("invalid, foreign or duplicate Samba group SID")
			}
			seen[sid] = true
		}
	}
	return nil
}

// ValidName accepts only ordinary SMB share names in the Ocean file service.
func ValidName(name string) bool {
	return storage.ValidShare(name) && name != "global" && name != "homes" && name != "printers"
}

func validDomainSID(sid string) bool {
	if !domainSID.MatchString(sid) {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(sid, "S-1-5-21-"), "-") {
		value, err := strconv.ParseUint(component, 10, 32)
		if err != nil || strconv.FormatUint(value, 10) != component {
			return false
		}
	}
	return true
}

func groupID(domain, sid string) (int, bool) {
	suffix, ok := strings.CutPrefix(sid, domain+"-")
	rid, err := strconv.ParseUint(suffix, 10, 32)
	return domainBase + int(rid), ok && err == nil && rid > 0 && rid <= domainEnd-domainBase && strconv.FormatUint(rid, 10) == suffix
}

func configuration(m Member) []byte {
	var output bytes.Buffer
	fmt.Fprintf(&output, `[global]
    server role = member server
    security = ADS
    workgroup = %s
    realm = %s
    netbios name = %s
    interfaces = %s
    bind interfaces only = yes
    smb ports = 445
    disable netbios = yes
    server multi channel support = no
    server min protocol = SMB3_00
    server smb encrypt = required
    server signing = mandatory
    allow trusted domains = no
    kerberos encryption types = strong
    client use kerberos = required
    ntlm auth = disabled
    gensec:ntlmssp = no
    map to guest = never
    restrict anonymous = 2
    private dir = %s/private
    state directory = %s/state
    cache directory = /var/cache/ocean-smb
    idmap config * : backend = tdb
    idmap config * : range = 100000-199999
    idmap config %s : backend = rid
    idmap config %s : range = %d-%d
    winbind offline logon = no
    load printers = no
    disable spoolss = yes
    logging = systemd
    log level = 1 auth_audit:3
`, m.NetBIOSDomain, strings.ToUpper(m.DNSDomain), m.ServerName, m.Address,
		stateRoot, stateRoot, m.NetBIOSDomain, m.NetBIOSDomain, domainBase, domainEnd)

	for _, share := range m.Shares {
		fmt.Fprintf(&output, `
[%s]
    path = %s
    browseable = no
    guest ok = no
    read only = yes
    valid users = %s
    follow symlinks = no
    wide links = no
    inherit acls = yes
    vfs objects = acl_xattr full_audit
    full_audit:prefix = %%D|%%U|%%I|%%S
    full_audit:success = connect disconnect create_file pwrite pwrite_recv fsync_recv renameat unlinkat fset_nt_acl
    full_audit:failure = connect create_file pwrite pwrite_recv
    full_audit:facility = LOCAL5
    full_audit:priority = NOTICE
`, share.Name, filepath.Join(MountRoot, share.VolumeID, "data"), strings.Join(slices.Concat(share.ReaderSIDs, share.WriterSIDs), " "))
		if len(share.WriterSIDs) != 0 {
			fmt.Fprintf(&output, "    write list = %s\n", strings.Join(share.WriterSIDs, " "))
		}
	}
	return output.Bytes()
}
