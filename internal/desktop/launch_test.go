package desktop

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLaunchRejectsInvalidCredentialsWithoutConsumingValidOne(t *testing.T) {
	const machine = "9feab7c2-1302-4622-a932-729678cd61ee"
	const user = "desktop-user@ad.ocean.test"
	now := time.Unix(1_795_600_000, 0)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IssueLaunch(private, machine, user, now, now.Add(LaunchLifetime+time.Second)); !errors.Is(err, ErrLaunchDenied) {
		t.Fatalf("long-lived credential was not rejected: %v", err)
	}
	deadline := now.Add(LaunchLifetime)
	password, err := IssueLaunch(private, machine, user, now, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != MaxLaunchBytes {
		t.Fatalf("credential length = %d, want %d", len(password), MaxLaunchBytes)
	}
	tampered := []byte(password)
	tampered[len(launchPrefix)+31] ^= 1
	state := filepath.Join(t.TempDir(), "replay")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		name, machine, user string
		key                 ed25519.PublicKey
		password            []byte
		now                 time.Time
	}{
		{"wrong machine", "9feab7c2-1302-4622-a932-729678cd61ef", user, public, []byte(password), now},
		{"wrong user", machine, "other-user@ad.ocean.test", public, []byte(password), now},
		{"wrong signing key", machine, user, otherKey, []byte(password), now},
		{"tampered token", machine, user, public, tampered, now},
		{"past expiry", machine, user, public, []byte(password), deadline},
		{"clock outside validity window", machine, user, public, []byte(password), now.Add(-time.Second)},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			err := RedeemLaunch(invalid.key, invalid.machine, invalid.user, invalid.password, invalid.now, state)
			if !errors.Is(err, ErrLaunchDenied) {
				t.Fatalf("invalid credential was not rejected: %v", err)
			}
		})
	}
	if entries, err := os.ReadDir(state); err != nil || len(entries) != 0 {
		t.Fatalf("invalid requests modified replay state: entries=%d, err=%v", len(entries), err)
	}

	const attempts = 12
	result := make(chan error, attempts)
	for range attempts {
		go func() {
			result <- RedeemLaunch(public, machine, user, []byte(password), now, state)
		}()
	}
	accepted := 0
	for range attempts {
		err := <-result
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrLaunchDenied) {
			t.Logf("concurrent redemption failed closed: %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("concurrent redemption accepted %d attempts, want 1", accepted)
	}
	if err := RedeemLaunch(public, machine, user, []byte(password), now, state); !errors.Is(err, ErrLaunchDenied) {
		t.Fatalf("reopened replay state accepted a used credential: %v", err)
	}
}
