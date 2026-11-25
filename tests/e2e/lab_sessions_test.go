//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Weichwolf/ocean/tests/e2e/internal/harness"
)

type labSession struct {
	state   string
	profile string
	initial []string
}

type labSessions struct {
	root    string
	current string
	labs    []labSession
}

func orderLabSteps(steps []harness.Step) []harness.Step {
	rank := map[string]int{"": 0, "storage-ha": 1, "single-farm-3": 2, "scale-16": 3}
	slices.SortStableFunc(steps, func(a, b harness.Step) int { return rank[a.LabProfile] - rank[b.LabProfile] })
	return steps
}

func prepareLabSessions(ctx context.Context, root string, steps []harness.Step, selected map[string]bool) (*labSessions, error) {
	sessions := &labSessions{root: root}
	byDirectory := make(map[string]string)
	for _, step := range steps {
		if step.LabState == "" || step.BlockedReason != "" || !slices.ContainsFunc(step.Cases, func(id string) bool { return selected[id] }) {
			continue
		}
		canonical, err := filepath.EvalSymlinks(step.LabState)
		if err != nil {
			return nil, err
		}
		if profile, exists := byDirectory[canonical]; exists {
			if profile != step.LabProfile {
				return nil, errors.New("the regional, small, and scale profiles require separate lab state directories")
			}
			continue
		}
		byDirectory[canonical] = step.LabProfile
		names, err := sessions.running(ctx, step.LabState)
		if err != nil {
			return nil, err
		}
		sessions.labs = append(sessions.labs, labSession{state: step.LabState, profile: step.LabProfile, initial: names})
	}
	return sessions, nil
}

func (sessions *labSessions) command(ctx context.Context, operation, state string, extra ...string) ([]byte, error) {
	args := append([]string{operation, "-state", state}, extra...)
	command := exec.CommandContext(ctx, filepath.Join(sessions.root, "bin", "ocean-lab"), args...)
	command.Dir = sessions.root
	out, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("lab %s in %s: %w (%s)", operation, state, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (sessions *labSessions) running(ctx context.Context, state string) ([]string, error) {
	result, err := sessions.command(ctx, "status", state)
	if err != nil {
		return nil, err
	}
	var cloud []struct {
		Running bool `json:"running"`
		Guest   struct {
			Name string `json:"name"`
		} `json:"guest"`
	}
	if err := json.Unmarshal(result, &cloud); err != nil {
		return nil, err
	}
	var names []string
	for _, guest := range cloud {
		if guest.Running {
			names = append(names, guest.Guest.Name)
		}
	}
	return names, nil
}

func (sessions *labSessions) up(ctx context.Context, lab labSession, names []string) error {
	args := []string{"-profile", filepath.Join("lab", "profiles", lab.profile+".yaml")}
	for _, name := range names {
		args = append(args, "-only", name)
	}
	_, err := sessions.command(ctx, "up", lab.state, args...)
	return err
}

func (sessions *labSessions) use(ctx context.Context, state string) error {
	if sessions.current == state {
		return nil
	}
	for _, lab := range sessions.labs {
		if lab.state == state {
			continue
		}
		names, err := sessions.running(ctx, lab.state)
		if err != nil {
			return err
		}
		if len(names) > 0 {
			if _, err := sessions.command(ctx, "down", lab.state); err != nil {
				return err
			}
		}
	}
	index := slices.IndexFunc(sessions.labs, func(lab labSession) bool { return lab.state == state })
	if index < 0 {
		return errors.New("the selected stage has no prepared lab session")
	}
	lab := sessions.labs[index]
	var names []string
	if lab.profile == "scale-16" {
		names = []string{"farm-1-node-01", "farm-1-node-02", "farm-1-node-03", "farm-1-operator", "farm-1-customer"}
	}
	if err := sessions.up(ctx, lab, names); err != nil {
		return err
	}
	lastErr := errors.New("the management endpoint did not become ready")
	for attempt := 0; attempt < 60; attempt++ {
		probe, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := sessions.command(probe, "ssh", lab.state, "farm-1-operator", "--",
			"curl --fail --silent --max-time 3 --cacert /opt/ocean-region/pki/ingress-ca.pem https://arm.farm-1.ocean.test/readyz")
		cancel()
		if err == nil {
			sessions.current = state
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(time.Second):
		}
	}
	return lastErr
}

func (sessions *labSessions) restore() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var failure error
	for _, lab := range sessions.labs {
		actual, err := sessions.running(ctx, lab.state)
		if err != nil {
			failure = errors.Join(failure, err)
			continue
		}
		if slices.Equal(actual, lab.initial) {
			continue
		}
		if len(actual) > 0 {
			if _, err := sessions.command(ctx, "down", lab.state); err != nil {
				failure = errors.Join(failure, err)
				continue
			}
		}
	}
	for _, lab := range sessions.labs {
		if len(lab.initial) > 0 {
			failure = errors.Join(failure, sessions.up(ctx, lab, lab.initial))
		}
	}
	return failure
}
