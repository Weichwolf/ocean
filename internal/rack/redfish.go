package rack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Weichwolf/ocean/internal/config"
)

type Redfish struct {
	client     *http.Client
	credential bmcCredential
}

type bmcCredential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type redfishLink struct {
	Path string `json:"@odata.id"`
}

// OpenRedfish uses the site's BMC CA and a private credential file.
func OpenRedfish(caFile, credentialFile string) (*Redfish, error) {
	client, err := managementClient(caFile)
	if err != nil {
		return nil, fmt.Errorf("configure BMC TLS: %w", err)
	}
	raw, err := readBounded(credentialFile, 4096, true)
	if err != nil {
		return nil, fmt.Errorf("read BMC credentials: %w", err)
	}
	credential, err := config.Decode(bytes.NewReader(raw), bmcCredential{})
	if err != nil || credential.Username == "" || strings.Contains(credential.Username, ":") || credential.Password == "" {
		return nil, errors.New("invalid BMC credential file")
	}
	return &Redfish{client: client, credential: credential}, nil
}

// Verify checks the approved ComputerSystem and its boot NIC without changing BMC state.
func (r *Redfish) Verify(ctx context.Context, asset Asset) error {
	if !asset.valid() {
		return errors.New("invalid rack asset")
	}
	var system struct {
		SerialNumber       string      `json:"SerialNumber"`
		UUID               string      `json:"UUID"`
		EthernetInterfaces redfishLink `json:"EthernetInterfaces"`
	}
	if err := r.get(ctx, asset.BMC, asset.System, &system); err != nil {
		return err
	}
	if system.SerialNumber != asset.Serial || !strings.EqualFold(system.UUID, asset.UUID) {
		return errors.New("BMC system serial or UUID does not match approved asset")
	}
	collection := system.EthernetInterfaces.Path
	if !validRedfishPath(collection) || collection != asset.System+"/EthernetInterfaces" {
		return errors.New("BMC does not expose the approved system's Ethernet interfaces")
	}
	next := collection
	seen := make(map[string]bool)
	for page := 0; next != "" && page < 8; page++ {
		if seen[next] {
			return errors.New("BMC Ethernet interface pagination loop")
		}
		seen[next] = true
		var links struct {
			Members []redfishLink `json:"Members"`
			Next    string        `json:"Members@odata.nextLink"`
		}
		if err := r.get(ctx, asset.BMC, next, &links); err != nil {
			return err
		}
		if len(links.Members) > 64 {
			return errors.New("BMC returned too many Ethernet interfaces on a page")
		}
		for _, member := range links.Members {
			if !validRedfishPath(member.Path) || !strings.HasPrefix(member.Path, collection+"/") || strings.Contains(strings.TrimPrefix(member.Path, collection+"/"), "/") {
				return errors.New("BMC returned an Ethernet interface outside the approved system")
			}
			var iface struct {
				MAC          string `json:"MACAddress"`
				PermanentMAC string `json:"PermanentMACAddress"`
			}
			if err := r.get(ctx, asset.BMC, member.Path, &iface); err != nil {
				return err
			}
			mac, err := net.ParseMAC(iface.MAC)
			if err == nil && mac.String() == asset.BootMAC {
				if iface.PermanentMAC == "" || strings.EqualFold(iface.PermanentMAC, asset.BootMAC) {
					return nil
				}
				return errors.New("BMC Ethernet interface permanent MAC differs from the approved boot MAC")
			}
		}
		next = links.Next
		if next != "" && !validNextLink(collection, next) {
			return errors.New("BMC returned an invalid Ethernet interface page link")
		}
	}
	if next != "" {
		return errors.New("BMC Ethernet interface pagination limit exceeded")
	}
	return errors.New("BMC Ethernet interfaces do not include the approved boot MAC")
}

func validNextLink(collection, value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil && u.RawPath == "" && u.Path == collection &&
		u.RawQuery != "" && u.Fragment == "" && strings.HasPrefix(value, collection+"?")
}

func (r *Redfish) get(ctx context.Context, origin, resource string, result any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+resource, nil)
	if err != nil {
		return errors.New("invalid BMC request")
	}
	req.SetBasicAuth(r.credential.Username, r.credential.Password)
	return readManagementJSON(r.client, req, "BMC", result)
}
