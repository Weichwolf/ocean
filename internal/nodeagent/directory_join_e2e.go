//go:build e2e

package nodeagent

import (
	"context"
	"net/http"

	"github.com/Weichwolf/ocean/internal/enrollment"
)

// RunDirectoryJoinFixture executes the production join worker for one
// prestarted, isolated controller without reconciling other local containers.
func RunDirectoryJoinFixture(ctx context.Context, origin, host string, client *http.Client, name string, assignment enrollment.Assignment) error {
	j := joinClient{config: joinConfig{Origin: origin, HostID: host}, client: client}
	return j.runDirectoryJoinTask(ctx, name, assignment)
}
