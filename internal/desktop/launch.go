// Package desktop implements credentials shared by the regional issuer and
// personal desktop guests.
package desktop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	LaunchLifetime = 15 * time.Second
	launchPrefix   = "ocean1."
	payloadBytes   = 4 + 16
	MaxLaunchBytes = len(launchPrefix) + ((payloadBytes+ed25519.SignatureSize)*8+5)/6
	replayLimit    = 4096
	replayGrace    = 60
)

var (
	ErrLaunchDenied = errors.New("desktop launch credential was denied")
	machineID       = regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`)
	workforceUPN    = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,19}@[a-z0-9][a-z0-9.-]{0,252}$`)
)

func IsLaunchPassword(password []byte) bool {
	return len(password) == MaxLaunchBytes && bytes.HasPrefix(password, []byte(launchPrefix))
}

// IssueLaunch uses the admission deadline as the credential expiry. The
// recipient supplies the machine ID and canonical AD UPN when verifying it.
func IssueLaunch(key ed25519.PrivateKey, machine, upn string, now, expires time.Time) (string, error) {
	if len(key) != ed25519.PrivateKeySize || !validRecipient(machine, upn) || !expires.After(now) ||
		expires.Sub(now) > LaunchLifetime || expires.Unix() <= now.Unix() || expires.Unix() > math.MaxUint32 || expires.Unix() <= 0 {
		return "", ErrLaunchDenied
	}
	var data [payloadBytes + ed25519.SignatureSize]byte
	binary.BigEndian.PutUint32(data[:4], uint32(expires.Unix()))
	_, _ = rand.Read(data[4:payloadBytes])
	copy(data[payloadBytes:], ed25519.Sign(key, signedLaunch(machine, upn, data[:payloadBytes])))
	return launchPrefix + base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func validRecipient(machine, upn string) bool {
	return machineID.MatchString(machine) && machine != "00000000-0000-0000-0000-000000000000" && workforceUPN.MatchString(upn)
}

func signedLaunch(machine, upn string, data []byte) []byte {
	return append([]byte("ocean-desktop-launch-v1\x00"+machine+"\x00"+upn+"\x00"), data...)
}

// RedeemLaunch checks the recipient, signature and deadline before committing
// the nonce to the guest's persistent replay state.
func RedeemLaunch(key ed25519.PublicKey, machine, upn string, password []byte, now time.Time, stateDir string) error {
	if len(key) != ed25519.PublicKeySize || !validRecipient(machine, upn) || !IsLaunchPassword(password) {
		return ErrLaunchDenied
	}
	var data [payloadBytes + ed25519.SignatureSize]byte
	n, err := base64.RawURLEncoding.Strict().Decode(data[:], password[len(launchPrefix):])
	if err != nil || n != len(data) || !ed25519.Verify(key, signedLaunch(machine, upn, data[:payloadBytes]), data[payloadBytes:]) {
		return ErrLaunchDenied
	}
	expires := int64(binary.BigEndian.Uint32(data[:4]))
	deadline := time.Unix(expires, 0)
	if !now.Before(deadline) || deadline.Sub(now) > LaunchLifetime {
		return ErrLaunchDenied
	}
	return consumeNonce(stateDir, strconv.FormatInt(expires, 10)+"-"+hex.EncodeToString(data[4:payloadBytes]), now.Unix())
}

func consumeNonce(path, receipt string, now int64) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	info, err := dir.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || int(stat.Uid) != os.Geteuid() || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("desktop replay state requires a private directory")
	}
	lock, err := root.OpenFile("lock", os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	names, err := dir.Readdirnames(replayLimit + 2)
	if (err != nil && !errors.Is(err, io.EOF)) || len(names) > replayLimit+1 {
		return errors.New("desktop replay state could not be enumerated within its limit")
	}
	used := 0
	for _, name := range names {
		if name == "lock" {
			continue
		}
		prefix, nonce, ok := strings.Cut(name, "-")
		expires, err := strconv.ParseInt(prefix, 10, 64)
		_, nonceErr := hex.DecodeString(nonce)
		if !ok || err != nil || len(nonce) != 32 || nonceErr != nil {
			return errors.New("unexpected entry in desktop replay state")
		}
		if expires <= now-replayGrace {
			if err := root.Remove(name); err != nil {
				return err
			}
		} else {
			used++
		}
	}
	if used >= replayLimit {
		return errors.New("desktop replay state is full")
	}
	marker, err := root.OpenFile(receipt, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if errors.Is(err, os.ErrExist) {
		return ErrLaunchDenied
	}
	if err != nil {
		return err
	}
	if err := errors.Join(marker.Sync(), marker.Close(), dir.Sync()); err != nil {
		return fmt.Errorf("commit desktop replay receipt: %w", err)
	}
	return nil
}
