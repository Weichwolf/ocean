package rack

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

type DNSConfig struct {
	Server  netip.AddrPort `json:"server"`
	KeyFile string         `json:"keyFile"`
}

type DNS struct {
	config DNSConfig
	binary string
}

// OpenDNS uses the site's RFC 2136 primary with a private BIND TSIG key file.
func OpenDNS(cfg DNSConfig) (*DNS, error) {
	if !cfg.Server.IsValid() || cfg.Server.Port() == 0 || cfg.Server.Addr().Zone() != "" || cfg.Server.Addr().IsUnspecified() {
		return nil, errors.New("rack DNS requires a primary address and port")
	}
	if key, err := readBounded(cfg.KeyFile, 16<<10, true); err != nil || len(key) == 0 {
		return nil, errors.New("rack DNS requires a private TSIG key file")
	}
	binary, err := exec.LookPath("nsupdate")
	if err != nil {
		return nil, fmt.Errorf("find nsupdate: %w", err)
	}
	return &DNS{config: cfg, binary: binary}, nil
}

// ValidDNSZone checks a canonical management zone without a trailing dot.
func ValidDNSZone(zone string) bool {
	if len(zone) > 253 || !strings.Contains(zone, ".") {
		return false
	}
	for label := range strings.SplitSeq(zone, ".") {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

// Publish adds the A record only while its name is unused. An authenticated
// prerequisite also confirms a previously committed update after a lost reply.
func (d *DNS) Publish(ctx context.Context, zone, host string, address netip.Addr) error {
	if !ValidDNSZone(zone) || !labelPattern.MatchString(host) || len(host)+1+len(zone) > 253 || !address.Is4() || !address.IsGlobalUnicast() {
		return errors.New("invalid rack DNS publication")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	name := host + "." + zone + "."
	prefix := fmt.Sprintf("server %s %d\nzone %s.\n", d.config.Server.Addr(), d.config.Server.Port(), zone)
	add := fmt.Sprintf("prereq nxdomain %s\nupdate add %s 60 IN A %s\nsend\n", name, name, address)
	if err := d.update(ctx, prefix+add); err != nil {
		verify := fmt.Sprintf("prereq yxrrset %s IN A %s\nsend\n", name, address)
		if verifyErr := d.update(ctx, prefix+verify); verifyErr != nil {
			return fmt.Errorf("publish management DNS for %s: %w", name, err)
		}
	}
	return nil
}

func (d *DNS) update(ctx context.Context, update string) error {
	cmd := exec.CommandContext(ctx, d.binary, "-v", "-t", "3", "-k", d.config.KeyFile)
	cmd.Stdin = strings.NewReader(update)
	return cmd.Run()
}
