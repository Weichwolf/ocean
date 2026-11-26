package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/desktop"
	"golang.org/x/sys/unix"
)

type guestConfig struct {
	MachineID string         `json:"machineId"`
	PublicKey string         `json:"publicKey"`
	Kerberos  *guestKerberos `json:"kerberos,omitempty"`
}

func main() {
	mode := flag.String("mode", "", "classify or redeem an XRDP launch credential")
	path := flag.String("config", "/etc/ocean-desktop/guest.json", "root-owned guest configuration")
	flag.Parse()
	if !run(*mode, *path) {
		os.Exit(1)
	}
}

func run(mode, path string) bool {
	if os.Geteuid() != 0 || os.Getenv("PAM_SERVICE") != "xrdp-sesman" || os.Getenv("PAM_TYPE") != "auth" {
		return false
	}
	password, err := io.ReadAll(io.LimitReader(os.Stdin, int64(desktop.MaxLaunchBytes)+1))
	defer clear(password)
	if err != nil || !desktop.IsLaunchPassword(password) {
		return false
	}
	if mode == "classify" {
		return true
	}
	if mode != "redeem" {
		return false
	}
	settings, err := loadGuestConfig(path)
	if err != nil {
		return false
	}
	public, err := base64.StdEncoding.Strict().DecodeString(settings.PublicKey)
	if err != nil {
		return false
	}
	account := os.Getenv("PAM_USER")
	if err := desktop.RedeemLaunch(ed25519.PublicKey(public), settings.MachineID, account, password,
		time.Now(), "/var/lib/ocean-desktop/replay"); err != nil {
		return false
	}
	return settings.Kerberos == nil || installCIFSCache(*settings.Kerberos, account, password) == nil
}

func loadGuestConfig(path string) (guestConfig, error) {
	const limit = 4096
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return guestConfig{}, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return guestConfig{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 ||
		info.Size() < 1 || info.Size() > limit {
		return guestConfig{}, errors.New("invalid desktop guest configuration file")
	}
	return config.Decode(io.LimitReader(file, limit+1), guestConfig{})
}
