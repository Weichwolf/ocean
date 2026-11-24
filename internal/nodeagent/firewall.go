package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/enrollment"
	"github.com/Weichwolf/ocean/internal/network"
)

const (
	policyInterval = 2 * time.Second
	policyTimeout  = 4 * time.Second
	policyLease    = 8 * time.Second
)

type firewallLink struct {
	Namespace string `json:"namespace"`
	Interface string `json:"interface"`
}

type placementIdentity struct {
	TenantID       string `json:"tenantId"`
	SubscriptionID string `json:"subscriptionId"`
	ID             string `json:"id"`
	Generation     string `json:"generation"`
}

type firewallEndpoint struct {
	firewallLink
	placementIdentity
}

type endpointRegistry struct {
	ProtectedPrefixes []netip.Prefix     `json:"protectedPrefixes"`
	InternetPrefixes  []netip.Prefix     `json:"internetPrefixes"`
	Endpoints         []firewallEndpoint `json:"endpoints"`
}

type appliedFirewall struct {
	identity placementIdentity
	policy   network.WorkloadFirewall
}

// RunNetworkPolicies synchronizes root-owned routing links with mTLS-authenticated
// assignments. Kernel timeouts expire forwarding if reconciliation stops.
func RunNetworkPolicies(ctx context.Context, agentPath, registryPath string, logger *slog.Logger) error {
	cfg, err := config.Load(agentPath, settings{})
	if err != nil {
		return err
	}
	if cfg.Enrollment == nil {
		return errors.New("network policy requires host enrollment")
	}
	client, err := newJoinClient(*cfg.Enrollment)
	if err != nil {
		return err
	}
	key, err := readIdentityKey(filepath.Join(cfg.Enrollment.StateDirectory, "identity.key"))
	if err != nil {
		return err
	}
	cert, err := privateData(filepath.Join(cfg.Enrollment.StateDirectory, "identity.crt"))
	if err != nil {
		return err
	}
	if err := client.useIdentity(cert, key); err != nil {
		return err
	}
	defer client.client.CloseIdleConnections()
	installed := make(map[firewallLink]appliedFirewall)
	ticker := time.NewTicker(policyInterval)
	defer ticker.Stop()
	for ctx.Err() == nil {
		round, cancel := context.WithTimeout(ctx, policyTimeout)
		err := reconcileFirewalls(round, registryPath, client, installed)
		cancel()
		if err != nil && ctx.Err() == nil {
			logger.Warn("network policy reconciliation failed", "error", err)
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), policyTimeout)
	defer cancel()
	return reconcileFirewallRules(shutdown, nil, nil, installed)
}

func reconcileFirewalls(ctx context.Context, registryPath string, client *joinClient, installed map[firewallLink]appliedFirewall) error {
	registry, err := loadEndpointRegistry(registryPath)
	if err != nil {
		return errors.Join(err, reconcileFirewallRules(ctx, nil, nil, installed))
	}
	var assignments map[placementIdentity]enrollment.Assignment
	if len(registry.Endpoints) != 0 {
		assignments, err = client.networkAssignments(ctx)
	}
	if err != nil {
		// A slow or unavailable API cannot prevent local revocation.
		local, cancel := context.WithTimeout(context.WithoutCancel(ctx), policyTimeout)
		defer cancel()
		return errors.Join(err, reconcileFirewallRules(local, &registry, nil, installed))
	}
	return reconcileFirewallRules(ctx, &registry, assignments, installed)
}

func reconcileFirewallRules(ctx context.Context, registry *endpointRegistry, assignments map[placementIdentity]enrollment.Assignment, installed map[firewallLink]appliedFirewall) error {
	desired := make(map[firewallLink]firewallEndpoint)
	if registry != nil {
		for _, endpoint := range registry.Endpoints {
			desired[endpoint.firewallLink] = endpoint
		}
	}
	var failures []error
	block := func(link firewallLink) bool {
		if err := network.BlockWorkload(ctx, link.Namespace, link.Interface); err != nil {
			failures = append(failures, err)
			return false
		}
		installed[link] = appliedFirewall{}
		return true
	}
	for link := range installed {
		if _, exists := desired[link]; !exists && block(link) {
			delete(installed, link)
		}
	}
	for link, endpoint := range desired {
		current, known := installed[link]
		if !known || (current.identity != (placementIdentity{}) && current.identity != endpoint.placementIdentity) {
			if !block(link) {
				continue
			}
			current = installed[link]
		}
		policy, err := registry.workloadFirewall(endpoint, assignments[endpoint.placementIdentity])
		if !policy.Address.IsValid() && err == nil {
			if current.identity != (placementIdentity{}) {
				block(link)
			}
			continue
		}
		if err == nil && reflect.DeepEqual(current.policy, policy) && policy.Refresh(ctx, link.Namespace) == nil {
			continue
		}
		if err == nil {
			err = policy.Apply(ctx, link.Namespace)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("link %s/%s: %w", link.Namespace, link.Interface, err))
			if current.identity != (placementIdentity{}) {
				block(link)
			}
			continue
		}
		installed[link] = appliedFirewall{endpoint.placementIdentity, policy}
	}
	return errors.Join(failures...)
}

func (r endpointRegistry) workloadFirewall(endpoint firewallEndpoint, a enrollment.Assignment) (network.WorkloadFirewall, error) {
	p := a.Network
	if a.NetworkUnavailable || p == nil {
		return network.WorkloadFirewall{}, nil
	}
	if !p.ValidFor(a.PrivateIPv4) {
		return network.WorkloadFirewall{}, errors.New("invalid network assignment")
	}
	firewall := network.WorkloadFirewall{
		Interface:         endpoint.Interface,
		Address:           a.PrivateIPv4,
		ProtectedPrefixes: r.ProtectedPrefixes,
		Rules:             p.SecurityRules,
		Lease:             policyLease,
	}
	for _, value := range p.Prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return network.WorkloadFirewall{}, err
		}
		firewall.VNetPrefixes = append(firewall.VNetPrefixes, prefix)
	}
	if p.PublicIPv4.IsValid() {
		firewall.InternetPrefixes = r.InternetPrefixes
	}
	return firewall, nil
}

func loadEndpointRegistry(path string) (endpointRegistry, error) {
	const maximumSize = 128 << 10
	var registry endpointRegistry
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return registry, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return registry, err
	}
	if !info.Mode().IsRegular() || info.Sys().(*syscall.Stat_t).Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Size() > maximumSize {
		return registry, errors.New("endpoint registry must be a small root-owned file with no group or other write access")
	}
	content := &io.LimitedReader{R: file, N: maximumSize + 1}
	decoder := json.NewDecoder(content)
	decoder.DisallowUnknownFields()
	var value *endpointRegistry
	if err := decoder.Decode(&value); err != nil {
		return registry, err
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF || content.N == 0 || value == nil {
		return registry, errors.New("endpoint registry must contain one JSON object within the size limit")
	}
	if len(value.Endpoints) != 0 && len(value.ProtectedPrefixes) == 0 {
		return registry, errors.New("protected prefixes are required for workload endpoints")
	}
	links := make(map[firewallLink]bool)
	placements := make(map[placementIdentity]bool)
	for _, endpoint := range value.Endpoints {
		if !network.ValidRoutingLink(endpoint.Namespace) || !network.ValidRoutingLink(endpoint.Interface) ||
			endpoint.TenantID == "" || endpoint.SubscriptionID == "" || endpoint.ID == "" || endpoint.Generation == "" ||
			links[endpoint.firewallLink] || placements[endpoint.placementIdentity] {
			return registry, errors.New("endpoint links and placement identities must be valid and unique")
		}
		links[endpoint.firewallLink] = true
		placements[endpoint.placementIdentity] = true
	}
	return *value, nil
}

func (j *joinClient) networkAssignments(ctx context.Context) (map[placementIdentity]enrollment.Assignment, error) {
	const maxPages = 32
	assignments := make(map[placementIdentity]enrollment.Assignment)
	seen := make(map[string]bool)
	cursor := ""
	for range maxPages {
		page, err := j.networkAssignmentPage(ctx, cursor)
		if err != nil {
			return nil, err
		}
		for _, assignment := range page.Assignments {
			id := placementIdentity{assignment.TenantID, assignment.SubscriptionID, assignment.ID, assignment.Generation}
			if _, duplicate := assignments[id]; duplicate {
				return nil, errors.New("duplicate network assignment")
			}
			assignments[id] = assignment
		}
		cursor = page.Next
		if cursor == "" {
			return assignments, nil
		}
		if seen[cursor] {
			return nil, errors.New("repeated placement continuation")
		}
		seen[cursor] = true
	}
	return nil, errors.New("network assignments exceed the page limit")
}

func (j *joinClient) networkAssignmentPage(ctx context.Context, cursor string) (enrollment.AssignmentPage, error) {
	var page enrollment.AssignmentPage
	path := j.url() + "/placements"
	if cursor != "" {
		path += "?" + url.Values{"continuation": {cursor}}.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return page, err
	}
	response, err := j.client.Do(request)
	if err != nil {
		return page, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return page, fmt.Errorf("network assignments returned HTTP %d", response.StatusCode)
	}
	const maxPageBytes = 8 << 20
	content := &io.LimitedReader{R: response.Body, N: maxPageBytes + 1}
	decoder := json.NewDecoder(content)
	if err := decoder.Decode(&page); err != nil {
		return page, err
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF || content.N == 0 || len(page.Assignments) > 32 {
		return page, errors.New("invalid network assignment page")
	}
	return page, nil
}
